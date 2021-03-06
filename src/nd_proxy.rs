use crate::conf::{NDConfig, ADDRESS_NETMAP, ADDRESS_NPT, PROXY_STATIC};
use crate::interfaces::{get_ifaces_defined_by_config, NDInterface};
use crate::neighbors::Neighbors;
use crate::packets;
use crate::routing::{SharedNSPacketReceiver, SharedNSPacketSender};
use ipnet::Ipv6Net;
use log::{error, info, trace, warn};
use pnet::packet::{icmpv6::ndp, Packet};
use pnet::util::MacAddr;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use ttl_cache::TtlCache;

/// proxy for Neighbor Discovery requests
/// it will: 0. receive Neighbor Solicitation provided by NSMonitor
///          1. perform Neighbor Solicitation on the downstream interfaces (skip in 'static' mode)
///          2. check whether the related neighbor exists (skip in 'static' mode)
///          3. send Neighbor Advertisement to upstream interface that sent the NS packet
#[derive(getset::Getters, getset::MutGetters)]
pub struct NDProxy {
    /// cache the existence of a neighbor to reduce the number of packets sent to downstream interfaces
    cache: TtlCache<Ipv6Addr, (u8, bool)>,
    proxy_type: u8,
    #[get = "pub with_prefix"]
    proxied_prefix: Ipv6Net,
    proxied_prefix_csum: u16,
    address_mangling: u8,
    rewrite_prefix: Ipv6Net,
    rewrite_prefix_csum: u16,
    mpsc_receiver: SharedNSPacketReceiver,
    #[get_mut = "pub with_prefix"]
    mpsc_sender: Option<SharedNSPacketSender>,
    pkt_sender: Socket,
    na_flag: u8,
    neighbors: Arc<Mutex<Neighbors>>,
    upstream_ifs: HashMap<u32, NDInterface>,
    downstream_ifs: HashMap<u32, NDInterface>,
}

impl NDProxy {
    pub fn new(config: NDConfig, neighbors: Arc<Mutex<Neighbors>>) -> Option<Self> {
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
            // TODO: another magic number: cache size?
            cache: TtlCache::new(256),
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
            neighbors,
            upstream_ifs,
            downstream_ifs,
        })
    }

    pub async fn run(mut self) -> Result<(), ()> {
        drop(self.mpsc_sender.take());
        warn!("NDProxy for {}: Start to work.", self.proxied_prefix);
        match self.proxy_type {
            PROXY_STATIC => self.run_static().await,
            _ => self.run_forward().await,
        }
    }

    async fn run_static(mut self) -> Result<(), ()> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr(),
                None => continue,
            };
            let src_addr = unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) };
            // TODO: randomly send to multicast addr
            if self
                .send_na_to_upstream(src_addr, *tgt_addr, macaddr, scope_id)
                .is_err()
            {
                return Err(());
            }
        }
        Ok(())
    }

    async fn run_forward(mut self) -> Result<(), ()> {
        while let Some((scope_id, tgt_addr, packet)) = self.mpsc_receiver.recv().await {
            // TODO: unwrap or continue?
            let ns_packet = ndp::NeighborSolicitPacket::new(&packet[40..]).unwrap();
            // I will not process the pkt,
            // if the scope id does not show up in upstream_ifs
            let macaddr = match self.upstream_ifs.get(&scope_id) {
                Some(iface) => iface.get_hwaddr(),
                None => continue,
            };
            match self.cache.get(&tgt_addr) {
                Some((_, true)) => {
                    let src_addr =
                        unsafe { address_translation::construct_v6addr_unchecked(&packet[8..]) };
                    // TODO: randomly send to multicast addr
                    if self
                        .send_na_to_upstream(src_addr, *tgt_addr, macaddr, scope_id)
                        .is_err()
                    {
                        return Err(());
                    }
                }
                // TODO: magic number here
                Some((cnt, false)) if *cnt > 5 => continue,
                _ => {
                    // TODO: is the Error returned by the function critical?
                    if self
                        .forward_ns_to_downstream(*tgt_addr, scope_id, ns_packet)
                        .await
                        .is_err()
                    {
                        return Err(());
                    };
                }
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
    ) -> Result<(), ()> {
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
                // TODO: return err or ok
                return Err(());
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
                Err(())
            }
        }
    }

    /// discover neighbors on proxied (downstream) interfaces
    async fn forward_ns_to_downstream(
        &mut self,
        proxied_addr: Ipv6Addr,
        origin_scope_id: u32,
        original_packet: ndp::NeighborSolicitPacket<'_>,
    ) -> Result<(), ()> {
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
                // TODO: return err or ok
                return Err(());
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
                return Err(());
            };
        }
        // update local cache
        match self
            .neighbors
            .lock()
            .await
            .check_whehter_entry_exists(&rewrited_addr)
            .await
        {
            Some(_) => {
                self.cache
                    .insert(proxied_addr, (0, true), Duration::from_secs(120));
            }
            None => match self.cache.get_mut(&proxied_addr) {
                Some((cnt, false)) => *cnt += 1,
                _ => {
                    self.cache
                        .insert(proxied_addr, (0, false), Duration::from_secs(10));
                }
            },
        };
        Ok(())
    }
}
