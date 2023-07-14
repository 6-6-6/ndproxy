use crate::conf::{NDConfig, Proxy, ADDRESS_NETMAP, ADDRESS_NPT, MPSC_CAPACITY};
use crate::datalink::{PacketSender, PacketSenderOpts};
use crate::interfaces::{get_ifaces_defined_by_config, NDInterface};
use crate::types::*;
use crate::{error::Error, packets};
use ipnet::Ipv6Net;
use log::{info, trace, warn};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::sync::mpsc;

/// proxy for Neighbor Discovery requests
/// it will: 0. receive Neighbor Solicitation provided by NSMonitor
///          1. perform Neighbor Solicitation on the downstream interfaces (skip in 'static' mode)
///          2. check whether the related neighbor exists (skip in 'static' mode)
///          3. send Neighbor Advertisement to upstream interface that sent the NS packet
#[derive(getset::Getters, getset::MutGetters)]
pub struct NDProxy {
    proxy_type: Proxy,
    #[get = "pub with_prefix"]
    proxied_prefix: Ipv6Net,
    /// for reducing computations
    proxied_prefix_csum: u16,
    address_mangling: u8,
    rewrite_prefix: Ipv6Net,
    /// for reducing computations
    rewrite_prefix_csum: u16,
    mpsc_receiver: SharedNSPacketReceiver,
    #[get_mut = "pub with_prefix"]
    mpsc_sender: Option<SharedNSPacketSender>,
    pkt_sender: PacketSender,
    na_flag: u8,
    /// manage ndp myself
    neighbors_cache: NeighborsCache,
    upstream_ifs: HashMap<u32, NDInterface>,
    downstream_ifs: HashMap<u32, NDInterface>,
}

impl NDProxy {
    pub fn new(config: NDConfig, neighbors_cache: NeighborsCache) -> Result<Self, Error> {
        // get values from config
        let proxied_prefix = *config.get_proxied_pfx();
        let proxy_type = *config.get_proxy_type();
        let address_mangling = *config.get_address_mangling();
        let rewrite_prefix = *config.get_dst_pfx();
        let (upstream_ifs, downstream_ifs) = get_ifaces_defined_by_config(&config);
        // generate local resources
        let (mpsc_sender, mpsc_receiver) = mpsc::channel(MPSC_CAPACITY);
        // packet sender
        let pkt_sender = PacketSender::new()?;
        pkt_sender.set_multicast_hops_v6(255)?;
        pkt_sender.set_unicast_hops_v6(255)?;
        // if everything goes as expected
        Ok(Self {
            proxy_type,
            proxied_prefix,
            proxied_prefix_csum: address_translation::pfx_csum(&proxied_prefix),
            address_mangling,
            rewrite_prefix,
            rewrite_prefix_csum: address_translation::pfx_csum(&rewrite_prefix),
            mpsc_receiver,
            mpsc_sender: Some(mpsc_sender),
            pkt_sender,
            na_flag: 0,
            neighbors_cache,
            upstream_ifs,
            downstream_ifs,
        })
    }

    pub async fn run(mut self) -> Result<(), Error> {
        drop(self.mpsc_sender.take());
        warn!("NDProxy for {}: Start to work.", self.proxied_prefix);
        match self.proxy_type {
            Proxy::Static => self.run_static().await,
            Proxy::Forward => self.run_forward().await,
        }
    }

    async fn run_static(mut self) -> Result<(), Error> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr(),
                None => continue,
            };
            let src_addr = unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) };
            // TODO: randomly send to multicast addr
            self.send_na_to_upstream(src_addr, *tgt_addr, macaddr, scope_id)
                .await?
        }
        Err(Error::MpscRecvNone())
    }

    async fn run_forward(mut self) -> Result<(), Error> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            // I will not process the pkt,
            // if the scope id does not show up in upstream_ifs
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr().to_owned(),
                None => continue,
            };

            // rewrite the target address if needed
            let rewrited_addr = match self.address_mangling {
                ADDRESS_NETMAP => address_translation::netmapv6(*tgt_addr, &self.rewrite_prefix),
                ADDRESS_NPT => address_translation::nptv6(
                    self.proxied_prefix_csum,
                    self.rewrite_prefix_csum,
                    *tgt_addr,
                    &self.rewrite_prefix,
                ),
                _ => *tgt_addr,
            };

            // send unicast NS anyways
            self.forward_ns_to_downstream(rewrited_addr, rewrited_addr, scope_id)
                .await?;

            // get the cache
            match self
                .downstream_ifs
                .keys()
                .map(|nei_scope_id| self.neighbors_cache.get(&(*nei_scope_id, rewrited_addr)))
                .any(|res| res.is_some())
            {
                true => {
                    // if the neighbors exist in cache, send back the proxied NA
                    self.send_na_to_upstream(
                        unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) },
                        *tgt_addr,
                        &macaddr,
                        scope_id,
                    )
                    .await?
                }
                false => {
                    // send multicast NS if the neighbor does not exist, and increase the possibility to find it
                    self.forward_ns_to_downstream(
                        address_translation::gen_solicited_node_multicast_address(&rewrited_addr),
                        rewrited_addr,
                        scope_id,
                    )
                    .await?
                }
            }
        }
        Err(Error::MpscRecvNone())
    }

    /// construct a NA packet, and send it to upstream
    async fn send_na_to_upstream(
        &self,
        ns_origin: Ipv6Addr,
        proxied_addr: Ipv6Addr,
        src_hwaddr: &MacAddr,
        scope_id: u32,
    ) -> Result<(), Error> {
        info!(
            "NDProxy for {}: Send NA for {} to {} on interface {:?}",
            self.proxied_prefix,
            proxied_addr,
            ns_origin,
            self.upstream_ifs.get(&scope_id)
        );
        // construct the NA packet
        let na_pkt = packets::generate_NA_forwarded(
            &Ipv6Addr::UNSPECIFIED,
            &ns_origin,
            &proxied_addr,
            src_hwaddr,
            self.na_flag,
        )?;
        // send the packet via send_to()
        self.pkt_sender
            .send_pkt_to(
                na_pkt.packet(),
                &SocketAddrV6::new(ns_origin, 0, 0, scope_id).into(),
            )
            .await?;
        Ok(())
    }

    /// discover neighbors on proxied (downstream) interfaces
    async fn forward_ns_to_downstream(
        &mut self,
        dst_addr: Ipv6Addr,
        ns_tgt_addr: Ipv6Addr,
        origin_scope_id: u32,
    ) -> Result<(), Error> {
        // logging
        trace!(
            "NDProxy for {}: Send Neighbour Solicition packet for {} to {}.",
            self.proxied_prefix,
            ns_tgt_addr,
            dst_addr
        );
        // send to every interested interface
        for (id, iface) in self.downstream_ifs.iter() {
            if *id == origin_scope_id {
                continue;
            };

            // send unicast NS packet anyways
            self.pkt_sender
                .send_pkt_to(
                    packets::generate_NS_packet(
                        iface.get_link_addr(),
                        &dst_addr,
                        &ns_tgt_addr,
                        Some(iface.get_hwaddr()),
                    )?
                    .packet(),
                    &SocketAddrV6::new(dst_addr, 0, 0, *id).into(),
                )
                .await?;
        }
        Ok(())
    }
}
