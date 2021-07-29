use crate::conf::NDConfig;
use crate::conf;
use crate::interfaces::{get_ifaces_defined_by_config, NDInterface};
use crate::ns_monitor::NSMonitor;
use crate::routing::NDPRoute;
use crate::packets;
use crate::neighbors;

use socket2::{Domain, Protocol, Socket, Type};
use futures::stream::FuturesOrdered;
use mio::event::Source;
use mio::{Events, Interest, Poll, Registry, Token};
use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::net::{Ipv6Addr, SocketAddrV6};
use treebitmap::IpLookupTable;

pub async fn proxy_main_loop(configs: Vec<NDConfig>) {
    let neighbors_cache = neighbors::Neighbors::new();
    let mut monitor_ifaces = HashMap::new();
    let mut route_table = IpLookupTable::with_capacity(configs.len());
    route_table.insert(Ipv6Addr::from([0; 8]), 0, NDPRoute::default());
    // extract information from config vector
    for config in configs.iter() {
        let (monitor_seg, forwarder_seg) = get_ifaces_defined_by_config(config);
        monitor_ifaces.extend(monitor_seg);
        route_table.insert(
            config.get_proxied_pfx().addr(),
            config.get_proxied_pfx().prefix_len() as u32,
            NDPRoute::new(
                *config.get_proxied_pfx(),
                Vec::from_iter(forwarder_seg.values().cloned()),
                *config.get_address_mangling(),
                *config.get_dst_pfx()
            ),
        );
    }

    // prepare senders
    let sender = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).expect("Failed to create sender");
    let _res = sender.set_multicast_hops_v6(255).unwrap();
    let _res = sender.set_unicast_hops_v6(255).unwrap();
    //sender.bind(&SocketAddrV6::new("2a0c:b641:730:bee::cc1:119".parse().unwrap(), 0, 0, 6).into()).expect("Failed to bind sender to unspecified address.");
    //sender.set_nonblocking(true).expect("The sender cannot be set to non-blocking mode.");

    // prepare monitors
    let mut monitors = HashMap::new();
    //let mut src_and_tgt = Vec::with_capacity(32);
    for (id, iface) in monitor_ifaces.drain() {
        monitors.insert(
            Token(id as usize),
            NSMonitor::new(iface).expect("Failed to create NSMonitor for iface {}."),
        );
    }

    let mut poll = Poll::new().expect("Failed to create a Poll instance.");
    let mut events = Events::with_capacity(monitors.len());
    //let futures = FuturesOrdered::new();
    register_monitors(&mut monitors, poll.registry()).expect("Failed to register Monitors");

    loop {
        let _ret = poll.poll(&mut events, None);

        for event in &events {
            let src_addr;
            let dst_addr;
            let target_addr;
            let rewrited_target_addr;
            let current_pkt;
            match monitors.get_mut(&event.token()).unwrap().next() {
                Some(payload) => {
                    src_addr = unsafe { address_translation::construct_v6addr(&payload[8..]) };
                    dst_addr = unsafe { address_translation::construct_v6addr(&payload[24..]) };
                    current_pkt = NeighborSolicitPacket::owned(payload[40..].into()).unwrap();
                    target_addr = current_pkt.get_target_addr();
                }
                None => continue,
            }
            //
            let (_addr, _pfx, route_object) = route_table.longest_match(target_addr).unwrap();
            if _pfx == 0 { continue };
            match *route_object.get_rewrite_method() {
                conf::ADDRESS_NETMAP => {
                    rewrited_target_addr = address_translation::netmapv6(target_addr, route_object.get_target_pfx())
                },
                conf::ADDRESS_NPT => {
                    rewrited_target_addr = address_translation::nptv6(*route_object.get_pfx_csum(), *route_object.get_target_pfx_csum(), target_addr, route_object.get_target_pfx());
                },
                _ => rewrited_target_addr = target_addr,
            }
            //src_and_tgt.push((src_addr, target_addr, rewrited_target_addr));
            //
            for iface in route_object.get_target_iface() {
                let ns = packets::generate_NS_trick(&current_pkt, &Ipv6Addr::UNSPECIFIED, &rewrited_target_addr).await.unwrap();
                let _ret = sender.send_to(ns.packet(), &SocketAddrV6::new(rewrited_target_addr, 0, 0, *iface.get_scope_id()).into());
                //println!("Sending packet to {} on interface {} and the process returned {:?}", rewrited_target_addr, iface.get_name(), _ret);
            }

            if let None = neighbors_cache.check_whehter_entry_exists_sync(&rewrited_target_addr) {
                continue
            }

            let na = packets::generate_NA_forwarded(&Ipv6Addr::UNSPECIFIED, &src_addr, &target_addr, monitors.get(&event.token()).unwrap().get_iface().get_hwaddr(), 0).await.unwrap();
            let _ret = sender.send_to(na.packet(), &SocketAddrV6::new(src_addr, 0, 0, *monitors.get(&event.token()).unwrap().get_iface().get_scope_id()).into());
            //println!("Sending NA packet for {} to {} on interface {} and the process returned {:?}", rewrited_target_addr, src_addr, *monitors.get(&event.token()).unwrap().get_iface().get_name(), _ret);
        }

    }
}

fn register_monitors(
    monitors: &mut HashMap<Token, NSMonitor>,
    registry: &Registry,
) -> std::io::Result<()> {
    for (id, monitor) in monitors.iter_mut() {
        if let Err(e) = monitor.register(registry, *id, Interest::READABLE) {
            return Err(e);
        }
    }
    Ok(())
}
