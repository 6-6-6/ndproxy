use crate::conf::{NDConfig, ADDRESS_NETMAP, ADDRESS_NPT, PROXY_STATIC};
use crate::interfaces::{get_ifaces_defined_by_config, NDInterface};
use crate::types::*;
use crate::{error, packets};
use ipnet::Ipv6Net;
use log::{error, info, trace, warn};
use pnet::packet::{icmpv6::ndp, Packet};
use pnet::util::MacAddr;
use socket2::{Domain, Protocol, Socket, Type};
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
    proxy_type: u8,
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
    pkt_sender: Socket,
    na_flag: u8,
    /// manage ndp myself
    neighbors_cache: NeighborsCache,
    upstream_ifs: HashMap<u32, NDInterface>,
    downstream_ifs: HashMap<u32, NDInterface>,
}

impl NDProxy {
    pub fn new(config: NDConfig, neighbors_cache: NeighborsCache) -> Option<Self> {
        let proxied_prefix = *config.get_proxied_pfx();
        let proxy_type = *config.get_proxy_type();
        let address_mangling = *config.get_address_mangling();
        let rewrite_prefix = *config.get_dst_pfx();
        let (mpsc_sender, mpsc_receiver) = mpsc::unbounded_channel();
        let (upstream_ifs, downstream_ifs) = get_ifaces_defined_by_config(&config);
        let pkt_sender = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(v) => v,
            Err(_) => return None,
        };
        if let Err(e) = pkt_sender.set_multicast_hops_v6(255) {
            error!(
                "NDProxy for {}: [{:?}] Failed to set multicast hops to 255",
                proxied_prefix, e
            );
            return None;
        };
        if let Err(e) = pkt_sender.set_unicast_hops_v6(255) {
            error!(
                "NDProxy for {}: [{:?}] Failed to set uniicast hops to 255",
                proxied_prefix, e
            );
            return None;
        };
        Some(Self {
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

    pub async fn run(mut self) -> Result<(), error::Error> {
        drop(self.mpsc_sender.take());
        warn!("NDProxy for {}: Start to work.", self.proxied_prefix);
        match self.proxy_type {
            PROXY_STATIC => self.run_static().await,
            _ => self.run_forward().await,
        }
    }

    async fn run_static(mut self) -> Result<(), error::Error> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr(),
                None => continue,
            };
            let src_addr = unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) };
            // TODO: randomly send to multicast addr
            self.send_na_to_upstream(src_addr, *tgt_addr, macaddr, scope_id)?
        }
        Ok(())
    }

    async fn run_forward(mut self) -> Result<(), error::Error> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            // TODO: unwrap or continue?
            let ns_packet = ndp::NeighborSolicitPacket::new(&packet[40..]).unwrap();
            // I will not process the pkt,
            // if the scope id does not show up in upstream_ifs
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr().to_owned(),
                None => continue,
            };
            // send NS to downstreams anyway
            // TODO: is the Error returned by the function critical?
            self.forward_ns_to_downstream(*tgt_addr, scope_id, ns_packet)
                .await?;
            // if the neighbors exist in cache, send back the proxied NA
            if let Some(true) = self.neighbors_cache.lock().await.get(&tgt_addr) {
                let src_addr =
                    unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) };
                // TODO: randomly send to multicast addr
                self.send_na_to_upstream(src_addr, *tgt_addr, &macaddr, scope_id)?
            }
        }
        Ok(())
    }

    /// construct a NA packet, and send it to upstream
    fn send_na_to_upstream(
        &self,
        ns_origin: Ipv6Addr,
        proxied_addr: Ipv6Addr,
        src_hwaddr: &MacAddr,
        scope_id: u32,
    ) -> Result<(), error::Error> {
        info!(
            "NDProxy for {}: Send NA for {} to {} on interface {}",
            self.proxied_prefix,
            proxied_addr,
            ns_origin,
            self.upstream_ifs.get(&scope_id).unwrap().get_name()
        );
        // construct the NA packet
        let na_pkt = match packets::generate_NA_forwarded(
            &Ipv6Addr::UNSPECIFIED,
            &ns_origin,
            &proxied_addr,
            src_hwaddr,
            self.na_flag,
        ) {
            Some(v) => v,
            None => {
                error!(
                    "NDProxy for {}: Failed to generate Neighbor Advertisement packet.",
                    self.proxied_prefix,
                );
                return Err(error::Error::PacketGeneration(NDTypes::NeighborAdv));
            }
        };
        // send the packet via send_to()
        match self.pkt_sender.send_to(
            na_pkt.packet(),
            &SocketAddrV6::new(ns_origin, 0, 0, scope_id).into(),
        ) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!(
                    "NDProxy for {}: [{:?}] failed to send Neighbor Advertisement packet to interface {}.",
                    self.proxied_prefix,
                    e,
                    self.upstream_ifs.get(&scope_id).unwrap().get_name()
                );
                Err(error::Error::Io(()))
            }
        }
    }

    /// discover neighbors on proxied (downstream) interfaces
    async fn forward_ns_to_downstream(
        &mut self,
        proxied_addr: Ipv6Addr,
        origin_scope_id: u32,
        original_packet: ndp::NeighborSolicitPacket<'_>,
    ) -> Result<(), error::Error> {
        // rewrite the target address if needed
        let rewrited_addr = match self.address_mangling {
            ADDRESS_NETMAP => address_translation::netmapv6(proxied_addr, &self.rewrite_prefix),
            ADDRESS_NPT => address_translation::nptv6(
                self.proxied_prefix_csum,
                self.rewrite_prefix_csum,
                proxied_addr,
                &self.rewrite_prefix,
            ),
            _ => proxied_addr,
        };
        // construct a packet whose target is the target address
        let ns_trick = match packets::generate_NS_trick(
            &original_packet,
            &Ipv6Addr::UNSPECIFIED,
            &rewrited_addr,
        ) {
            Some(v) => v,
            None => {
                error!(
                    "NDProxy for {}: Failed to generate ICMPv6 packet.",
                    self.proxied_prefix,
                );
                return Err(error::Error::PacketGeneration(NDTypes::NeighborSol));
            }
        };
        // logging
        trace!(
            "NDProxy for {}: Send packet to {}.",
            self.proxied_prefix,
            rewrited_addr,
        );
        // send to every interested interface
        for id in self.downstream_ifs.keys() {
            if *id == origin_scope_id {
                continue;
            };
            if let Err(e) = self.pkt_sender.send_to(
                ns_trick.packet(),
                &SocketAddrV6::new(rewrited_addr, 0, 0, *id).into(),
            ) {
                error!(
                    "NDProxy for {}: [{:?}] failed to send packet to interface {}.",
                    self.proxied_prefix,
                    e,
                    self.downstream_ifs.get(id).unwrap().get_name(),
                );
                return Err(error::Error::Io(()));
            };
        }
        Ok(())
    }
}
