use crate::conf::{NDConfig, ADDRESS_NETMAP, ADDRESS_NPT};
use crate::packets;
use crate::routing::{SharedNSPacketReceiver, SharedNSPacketSender};
use crate::neighbors::Neighbors;
use crate::interfaces::{NDInterface, get_ifaces_defined_by_config};
use ipnet::Ipv6Net;
use log::{error, trace, warn};
use pnet::packet::{Packet, icmpv6::ndp};
use pnet::util::MacAddr;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::mpsc;
use ttl_cache::TtlCache;
use std::collections::HashMap;
use std::time::Duration;

#[derive(getset::Getters)]
pub struct NDProxier {
    cache: TtlCache<Ipv6Addr, (u8, bool)>,
    #[get = "pub with_prefix"]
    proxied_prefix: Ipv6Net,
    proxied_prefix_csum: u16,
    address_mangling: u8,
    rewrite_prefix: Ipv6Net,
    rewrite_prefix_csum: u16,
    mpsc_receiver: SharedNSPacketReceiver,
    #[get = "pub with_prefix"]
    mpsc_sender: SharedNSPacketSender,
    pkt_sender: Socket,
    na_flag: u8,
    neighbors: Neighbors,
    upstream_ifs: HashMap<u32, NDInterface>,
    downstream_ifs: HashMap<u32, NDInterface>,
}

use futures::executor::block_on;
impl NDProxier {
    pub fn new(config: NDConfig) -> Option<Self> {
        let proxied_prefix = config.get_proxied_pfx().clone();
        let address_mangling = config.get_address_mangling().clone();
        let rewrite_prefix = config.get_dst_pfx().clone();
        let (mpsc_sender, mpsc_receiver) = mpsc::channel();
        let (upstream_ifs, downstream_ifs) = get_ifaces_defined_by_config(&config);
        // TODO: maybe a Lock<Arc<Socket>> would be better?
        let pkt_sender = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(v) => v,
            Err(_) => return None,
        };
        if let Err(_) = pkt_sender.set_multicast_hops_v6(255) {
            error!(
                "NDProxier for {}: Failed to set multicast hops to 255",
                proxied_prefix
            );
            return None;
        };
        if let Err(_) = pkt_sender.set_unicast_hops_v6(255) {
            error!(
                "NDProxier for {}: Failed to set uniicast hops to 255",
                proxied_prefix
            );
            return None;
        };
        Some(Self {
            // cache size?
            cache: TtlCache::new(256),
            proxied_prefix,
            proxied_prefix_csum: address_translation::pfx_csum(&proxied_prefix),
            address_mangling,
            rewrite_prefix,
            rewrite_prefix_csum: address_translation::pfx_csum(&rewrite_prefix),
            mpsc_receiver,
            mpsc_sender,
            pkt_sender,
            na_flag: 0,
            neighbors: Neighbors::new(),
            upstream_ifs,
            downstream_ifs,
        })
    }

    pub fn run(mut self) {// -> Result<(), ()> {
        println!("********* runnning");
        while let Ok((scope_id, macaddr, packet)) = self.mpsc_receiver.recv() {
            println!("*********************** {:?}", scope_id);
            let src_addr = unsafe { address_translation::construct_v6addr(&packet[8..]) };
            let dst_addr = unsafe { address_translation::construct_v6addr(&packet[24..]) };
            // TODO: unwrap or continue?
            let ns_packet = ndp::NeighborSolicitPacket::new(&packet[40..]).unwrap();
            let tgt_addr = ns_packet.get_target_addr();
            for i in self.cache.iter() {
                trace!("{:?}", i);
            };
            match self.cache.get(&tgt_addr) {
                Some((_, true)) => {
                    if let Err(_) = self.send_na_to_upstream(src_addr, tgt_addr, &macaddr, scope_id) {
                        break;
                    }
                }
                // TODO: magic number
                Some((cnt, false)) if *cnt > 5 => continue,
                _ => {
                    let _res = self.forward_ns_to_downstream(tgt_addr, scope_id, ns_packet);
                }
            }
        }
        //Ok(())
    }

    fn send_na_to_upstream(
        &self,
        ns_origin: Ipv6Addr,
        proxied_addr: Ipv6Addr,
        src_hwaddr: &MacAddr,
        scope_id: u32,
    ) -> Result<(), ()> {
        warn!("NDProxier for {}: Send NA to {} on interface {}",
            self.proxied_prefix,
            proxied_addr,
            scope_id
        );
        // randomly send to multicast
        let na_pkt = match block_on(packets::generate_NA_forwarded(
            &Ipv6Addr::UNSPECIFIED,
            &ns_origin,
            &proxied_addr,
            src_hwaddr,
            self.na_flag,
        ))
        {
            Some(v) => v,
            None => return Err(()),
        };
        match self.pkt_sender.send_to(na_pkt.packet(), &SocketAddrV6::new(ns_origin, 0, 0, scope_id).into()) {
            Ok(_) => return Ok(()),
            Err(_) => return Err(())
        }
    }

    fn forward_ns_to_downstream<'a>(&mut self, proxied_addr: Ipv6Addr, origin_scope_id: u32, original_packet: ndp::NeighborSolicitPacket<'a>) -> Result<(), ()> {
        let rewrited_addr = match self.address_mangling {
            ADDRESS_NETMAP => address_translation::netmapv6(proxied_addr, &self.rewrite_prefix),
            ADDRESS_NPT => address_translation::nptv6(self.proxied_prefix_csum, self.rewrite_prefix_csum, proxied_addr, &self.rewrite_prefix),
            _ => proxied_addr,
        };
        match self.neighbors.check_whehter_entry_exists_sync(&rewrited_addr) {
            Some(_) => { self.cache.insert(proxied_addr, (0, true), Duration::from_secs(30)); },
            // TODO: update cache
            None => { match self.cache.get_mut(&proxied_addr) {
                Some((cnt, false)) => *cnt += 1,
                _ => { self.cache.insert(proxied_addr, (0, false), Duration::from_secs(5)); },
            }},
        };
        let ns_trick = match block_on(packets::generate_NS_trick(&original_packet, &Ipv6Addr::UNSPECIFIED, &rewrited_addr)) {
            Some(v) => v,
            None => return Err(())
        };
        // TODO: logging
        for (id, _iface) in self.downstream_ifs.iter() {
            match self.pkt_sender.send_to(ns_trick.packet(), &SocketAddrV6::new(rewrited_addr, 0, 0, *id).into()) {
                Ok(_) => return Ok(()),
                Err(_) => return Err(())
            }
        }
        Ok(())
    }
}
