use std::sync::mpsc::channel;
use std::thread;
use crate::interfaces;
use crate::conf::NDConfig;
use std::net::{SocketAddrV6};
use socket2::{Socket,Type,Domain,Protocol};
use std::mem::MaybeUninit;
use crate::address;

pub struct NeighborDiscoveryProxyItem {
    config: NDConfig,
    proxied_ifaces: Vec<interfaces::NDInterface>,
    forwarded_ifaces: Vec<interfaces::NDInterface>,
}

impl NeighborDiscoveryProxyItem {
    pub fn new(config: NDConfig) -> Self {
        let (proxied_ifaces, forwarded_ifaces) = interfaces::get_ifaces_defined_by_config(&config);
        NeighborDiscoveryProxyItem {
            config,
            proxied_ifaces,
            forwarded_ifaces,
        }
    }

    pub fn run(&self) -> Result<(),()> {
        //let (sender, receiver) = channel();
        Ok(())
    }

    pub fn monitor_NS(&self, proxied_index: usize) {
        let monitor = Socket::new(Domain::IPV6,
            Type::RAW,
            Some(Protocol::ICMPV6)).unwrap();
        //TODO: log
        println!("[Monitor_NS]: Monitoring ICMPv6 packets on {}.", self.proxied_ifaces[proxied_index].get_name());
        //
        let addr = SocketAddrV6::new(*self.proxied_ifaces[proxied_index].get_link_addr(), 0, 0, *self.proxied_ifaces[proxied_index].get_scope_id());
        // panic if it fails to bind
        // bind to its lladdr to receive unicast msgs
        let _res = monitor.bind(&addr.into()).unwrap();
        // join multicast group to receive multicast msgs
        let _res = monitor.join_multicast_v6(&"ff02::1".parse().unwrap(), *self.proxied_ifaces[proxied_index].get_scope_id());
        // the receiving buffer
        let mut buf: Vec<MaybeUninit::<u8>> = vec![MaybeUninit::<u8>::zeroed();1500];
        //let mut buf = vec![0u8; 1500];
        loop {
            let ret = monitor.recv_from(&mut buf);
            match ret {
                Ok((packet_size, _addr)) => {
                    let the_packet: Vec<u8> = unsafe{ buf[0..packet_size].iter().map(|x| x.assume_init()).collect() };
                    println!("[len] {}", packet_size);
                    println!("[Type] {:#x}", &the_packet[0]);
                    println!("[Code] {:#x}", &the_packet[1]);
                    println!("[Code] {:?}", &the_packet[2..4]);
                },
                Err(_) => continue
            }
        }
    }
}