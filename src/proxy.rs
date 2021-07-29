use crate::interfaces::{NDInterface, get_ifaces_defined_by_config};
use crate::ns_monitor::NSMonitor;
use crate::conf::NDConfig;
use mio::event::Source;
use mio::{Events, Registry, Interest, Token, Poll};
use std::collections::HashMap;

use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;

pub fn proxy_main_loop(configs: Vec<NDConfig>) {
    let mut monitor_ifaces = HashMap::new();
    let mut _forwarder_ifaces = HashMap::new();
    for config in configs.iter() {
        let (monitor_seg, forwarder_seg) = get_ifaces_defined_by_config(config);
        monitor_ifaces.extend(monitor_seg);
        _forwarder_ifaces.extend(forwarder_seg);
    }

    let mut monitors = HashMap::new();
    for (id,iface) in monitor_ifaces.drain() {
        monitors.insert(Token(id as usize), NSMonitor::new(iface).expect("Failed to create NSMonitor for iface {}."));
    }

    let mut poll = Poll::new().expect("Failed to create a Poll instance.");
    let mut events = Events::with_capacity(monitors.len());
    //let futures = ;
    register_monitors(&mut monitors, poll.registry()).expect("Failed to register Monitors");

    loop {
        let _ret = poll.poll(&mut events, None);
        println!("{:?}", _ret);

        for event in &events {
            let src_addr;
            let dst_addr;
            let current_pkt;
            match monitors.get_mut(&event.token()).unwrap().next() {
                Some(payload) => {
                    src_addr = unsafe { address_translation::construct_v6addr(&payload[8..]) };
                    dst_addr = unsafe { address_translation::construct_v6addr(&payload[24..]) };
                    current_pkt = NeighborSolicitPacket::owned(payload[40..].into()).unwrap()
                },
                None => continue,
            }
            println!("####################################");
            println!("Got a NS packet");
            println!("src addr: {:?}", src_addr);
            println!("dst addr: {:?}", dst_addr);
            println!("target_addr: {:?}", current_pkt.get_target_addr());
            //for iface in find_next_hops().into_iter()
            //let current_pkt = NeighborSolicitPacket::new();
        }
    }
}

fn register_monitors(monitors: &mut HashMap<Token, NSMonitor>, registry: &Registry) -> std::io::Result<()> {
    for (id,monitor) in monitors.iter_mut() {
        if let Err(e) = monitor.register(
            registry,
            *id,
            Interest::READABLE) {
                return Err(e)
            }
    }
    Ok(())
}