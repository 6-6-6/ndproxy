use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use std::io::{Error, ErrorKind};
use pnet::datalink;
use pnet::packet::icmpv6::ndp;
use pnet::packet::Packet;
use std::net::{Ipv6Addr, SocketAddrV6};
use socket2::{Socket,Type,Domain,Protocol};
use std::mem::MaybeUninit;
use crate::address;
use crate::interfaces;
use crate::packets;
use crate::neighors;
use crate::conf::NDConfig;

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
            //neighbors
            //proxied_if_senders
            //forwarded_if_senders
            //router flag mask
        }
    }

    pub fn run(&self) -> Result<(),()> {
        let (mpsc_tx, mpsc_rx) = channel();
        let mut id = 0;
        let mut senders = Vec::new();
        for iface in self.proxied_ifaces.iter() {
            //
            let tx = mpsc_tx.clone();
            let iface = iface.clone();
            let pfx = self.config.get_proxied_pfx().clone();
            //
            let _handle = thread::Builder::new().name(format!("NS Listener: {}", iface.get_name())).spawn(move|| { monitor_NS(iface, id, pfx, tx) });
            id += 1;
        }
        for iface in self.forwarded_ifaces.iter() {
            //
            let iface_sender = Socket::new(Domain::IPV6,
                Type::RAW,
                Some(Protocol::ICMPV6)).unwrap();
            let addr = SocketAddrV6::new(iface.get_link_addr().clone(), 0, 0, iface.get_scope_id().clone());
            let _res = iface_sender.bind(&addr.into()).unwrap();
            // useful?
            let _res = iface_sender.set_multicast_hops_v6(255).unwrap();
            senders.push(iface_sender);
        }
        self.process_NS(mpsc_rx, senders);
        Ok(())
    }

 
    pub fn process_NS(&self, mpsc_rx: Receiver<(ndp::NeighborSolicitPacket, usize)>, senders: Vec<Socket>) {
        let nei = neighors::Neighbors::new();
        loop {
            let (the_ndp, ndp_receiver_id) = match mpsc_rx.recv() {
                Ok(v) => v,
                Err(_) => continue,
            };
            //TODO: determine static or not
            //TODO: determine rewrite
            let tgt_addr;
            if *self.config.get_rewrite() {
                let target_prefix = self.config.get_dst_pfx();
                let net_u128 = u128::from_be_bytes(the_ndp.get_target_addr().octets()) & u128::from_be_bytes(target_prefix.hostmask().octets());
                let prefix_u128 = u128::from_be_bytes(target_prefix.addr().octets()) & u128::from_be_bytes(target_prefix.netmask().octets());
                tgt_addr = Ipv6Addr::from((prefix_u128+net_u128).to_be_bytes());
            } else {
                tgt_addr = the_ndp.get_target_addr();
            }
            // play some trick, ask our OS to discover its neighbour
            for (iface, sender) in self.forwarded_ifaces.iter().zip(senders.iter()) {
                let addr = SocketAddrV6::new(tgt_addr, 0, 0, iface.get_scope_id().clone());
                let send_pkt = packets::generate_NS_trick(&the_ndp, iface.get_link_addr(), &addr.ip()).unwrap();
                let _ret = sender.send_to(send_pkt.packet(), &addr.into());
            }
            //TODO: wait for a random time to make the discovery complete
            //TODO: decide whether to unicast
            // TODO use self-owned objects
            match nei.check_whehter_entry_exists_sync(&tgt_addr) {
                Some((mac, scope_id)) => if &scope_id != self.proxied_ifaces[ndp_receiver_id].get_scope_id() {
                    self.forward_NA(ndp_receiver_id, the_ndp.get_target_addr(), "ff02::1".parse().unwrap())
                },
                None => continue,
            }
        }
    }

    pub fn forward_NA(&self, proxied_if_index: usize, proxied_addr: Ipv6Addr, dst_addr: Ipv6Addr) {
        let iface_sender = Socket::new(Domain::IPV6,
            Type::RAW,
            Some(Protocol::ICMPV6)).unwrap();
        // 
        let src_addr = *self.proxied_ifaces[proxied_if_index].get_link_addr();
        let src_hwaddr = *self.proxied_ifaces[0].get_hwaddr();
        let my_scope_id = *self.proxied_ifaces[proxied_if_index].get_scope_id();
        let tgt = SocketAddrV6::new(dst_addr, 0, 0, my_scope_id);
        let pkt: ndp::NeighborAdvertPacket;
        // TODO: add router flag or not
        if dst_addr.is_multicast() {
             pkt = packets::generate_NA_forwarded(&src_addr, &dst_addr,
                &proxied_addr, &src_hwaddr, 0b00000000).unwrap();
        } else {
            pkt = packets::generate_NA_forwarded(&src_addr, &dst_addr,
                &proxied_addr, &src_hwaddr, 0b01000000).unwrap();
        }
        // TODO: use self-owned senders
        let txaddr = SocketAddrV6::new(src_addr, 0, 0, my_scope_id);
        let _res = iface_sender.bind(&txaddr.into()).unwrap();
        let _res = iface_sender.set_multicast_hops_v6(255).unwrap();
        let _res = iface_sender.set_unicast_hops_v6(255).unwrap();

        // TODO: logging
        println!("How I sent my NA: {:?}",iface_sender.send_to(pkt.packet(), &tgt.into()));
    }
    /*
    // make it private after testing
    pub fn forward_NS(&self, original_packet: &ndp::NeighborSolicitPacket, forward_iface: &interfaces::NDInterface, dst_addr: SocketAddrV6) -> Result<usize, Error>{
        if let Some(forwarded_ns) = packets::generate_NS_proxied(original_packet, forward_iface.get_link_addr(), dst_addr.ip()) {
            return forward_iface.get_sender().send_to(&forwarded_ns.packet(), &dst_addr.into())
        }
        Err(Error::new(ErrorKind::InvalidInput, format!("Could not Create a new packet while processing NS for {}", forward_iface.get_name())))
    }
    */
}

// make it private after testing
pub fn monitor_NS(proxied_iface: interfaces::NDInterface, proxied_id: usize, proxied_pfx: ipnet::Ipv6Net, mpsc_tx: Sender<(ndp::NeighborSolicitPacket, usize)>) {
    let mut monitor_config: datalink::Config = Default::default();
    monitor_config.channel_type = datalink::ChannelType::Layer3(0x86DD);
    let (_tx, mut monitor) = match datalink::channel(proxied_iface.get_from_pnet(), monitor_config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    drop(_tx);
    loop {
        let packet = match monitor.next() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // magic number: change to variables
        if packet[40] == 135 {
            let the_ndp = match ndp::NeighborSolicitPacket::owned(packet[40..].to_vec()) {
                Some(v) => v,
                None => continue,
            };
            if proxied_pfx.contains(&the_ndp.get_target_addr()) {
                let _res = mpsc_tx.send((the_ndp,proxied_id));
            };
        }
    }
}

