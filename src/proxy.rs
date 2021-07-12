use crate::address;
use crate::conf;
use crate::interfaces;
use crate::neighors;
use crate::packets;
use pnet::datalink;
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::Packet;
use socket2::Socket;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

pub struct NeighborDiscoveryProxyItem {
    config: conf::NDConfig,
    proxied_ifaces: Vec<interfaces::NDInterface>,
    proxied_if_senders: Vec<Socket>,
    forwarded_ifaces: Vec<interfaces::NDInterface>,
    forwarded_if_senders: Vec<Socket>,
    neighbor_handle: neighors::Neighbors,
    // TODO: whether I should set Router flag
}

impl NeighborDiscoveryProxyItem {
    pub fn new(config: conf::NDConfig) -> Self {
        let (proxied_ifaces, forwarded_ifaces) = interfaces::get_ifaces_defined_by_config(&config);
        let neighbor_handle = neighors::Neighbors::new();
        let proxied_if_senders = interfaces::prepare_sockets_for_ifaces(&proxied_ifaces);
        let forwarded_if_senders = interfaces::prepare_sockets_for_ifaces(&forwarded_ifaces);

        // TODO: logging INFO
        println!("[#] Initializing NeighborDiscoveryProxyItem...");
        println!("\tconfig: {:?}", config);
        println!(
            "\tProxying _Neighbor Solicitation_ for: {:?}",
            proxied_ifaces
        );
        println!(
            "\tForwarding _Neighbor Advertisement_ for: {:?}",
            forwarded_ifaces
        );
        // End of Logging

        NeighborDiscoveryProxyItem {
            config,
            proxied_ifaces,
            proxied_if_senders,
            forwarded_ifaces,
            forwarded_if_senders,
            neighbor_handle, //router flag
        }
    }

    pub fn run(&self) -> Result<(), ()> {
        let (mpsc_tx, mpsc_rx) = channel();
        // spawn all of my monitors
        for (id, iface) in self.proxied_ifaces.iter().enumerate() {
            //
            let tx = mpsc_tx.clone();
            let iface = iface.clone();
            let pfx = *self.config.get_proxied_pfx();
            //
            let _handle = thread::Builder::new()
                .name(format!(
                    "[{}] NS Listener: {}",
                    self.config.get_name(),
                    iface.get_name()
                ))
                .spawn(move || monitor_NS(iface, id, pfx, tx));
        }
        if *self.config.get_proxy_type() == conf::PROXY_STATIC {
            self.process_NS_static(mpsc_rx)
        } else if *self.config.get_proxy_type() == conf::PROXY_FORWARD {
            self.process_NS_forward(mpsc_rx)
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    fn process_NS_static(&self, mpsc_rx: Receiver<(ndp::NeighborSolicitPacket, usize, Ipv6Addr)>) {
        loop {
            // receive msg from mpsc transmitter
            let (the_ndp, ndp_receiver_id, node_addr) = match mpsc_rx.recv() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let tgt_addr = the_ndp.get_target_addr();
            self.forward_NA_wrapper(node_addr, tgt_addr, the_ndp, ndp_receiver_id)
        }
    }

    #[allow(non_snake_case)]
    fn process_NS_forward(&self, mpsc_rx: Receiver<(ndp::NeighborSolicitPacket, usize, Ipv6Addr)>) {
        loop {
            // receive msg from mpsc transmitter
            let (the_ndp, ndp_receiver_id, node_addr) = match mpsc_rx.recv() {
                Ok(v) => v,
                Err(_) => continue,
            };
            // determine the target address: whether we need to rewrite it
            let tgt_addr;
            if *self.config.get_rewrite() {
                let target_prefix = self.config.get_dst_pfx();
                let net_u128 = u128::from_be_bytes(the_ndp.get_target_addr().octets())
                    & u128::from_be_bytes(target_prefix.hostmask().octets());
                let prefix_u128 = u128::from_be_bytes(target_prefix.addr().octets())
                    & u128::from_be_bytes(target_prefix.netmask().octets());
                tgt_addr = Ipv6Addr::from((prefix_u128 + net_u128).to_be_bytes());
            } else {
                tgt_addr = the_ndp.get_target_addr();
            }
            // play some trick, ask our OS to discover its neighbor
            for (iface, sender) in self
                .forwarded_ifaces
                .iter()
                .zip(self.forwarded_if_senders.iter())
            {
                let addr = SocketAddrV6::new(tgt_addr, 0, 0, *iface.get_scope_id());
                // never expecting it could go wrong
                let send_pkt =
                    packets::generate_NS_trick(&the_ndp, iface.get_link_addr(), &addr.ip()).expect(
                        "Failed while generating Echo Request Message for detecting neighbors.",
                    );
                let _ret = sender.send_to(send_pkt.packet(), &addr.into());
                // TODO: logging DEBUG
                println!(
                    "[#] Discovering Neighbor {:?} on interface {:?}",
                    tgt_addr,
                    iface.get_name()
                );
                // End of Logging
            }
            self.forward_NA_wrapper(node_addr, tgt_addr, the_ndp, ndp_receiver_id)
        }
    }

    #[allow(non_snake_case)]
    fn forward_NA_wrapper(
        &self,
        node_addr: Ipv6Addr,
        tgt_addr: Ipv6Addr,
        the_ndp: ndp::NeighborSolicitPacket,
        ndp_receiver_id: usize,
    ) {
        //TODO: wait for a random time to make the discovery complete
        if let Some((_mac, scope_id)) = self
            .neighbor_handle
            .check_whehter_entry_exists_sync(&tgt_addr)
        {
            /*
             * make sure the neighbor cache does not come from the same iface
             *   which we are going to send NA to
             */
            if &scope_id != self.proxied_ifaces[ndp_receiver_id].get_scope_id() {
                self.forward_NA(ndp_receiver_id, the_ndp.get_target_addr(), node_addr);
                // TODO: roll a dice and randomly send multicast NA messages
                // self.forward_NA(ndp_receiver_id, the_ndp.get_target_addr(), "ff02::1".parse().unwrap())
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn forward_NA(&self, proxied_if_index: usize, proxied_addr: Ipv6Addr, dst_addr: Ipv6Addr) {
        // get items
        let iface = self.proxied_ifaces.get(proxied_if_index).unwrap();
        let iface_sender = self.proxied_if_senders.get(proxied_if_index).unwrap();
        let src_addr = *iface.get_link_addr();
        let src_hwaddr = *iface.get_hwaddr();

        let tgt = SocketAddrV6::new(dst_addr, 0, 0, *iface.get_scope_id());
        let pkt: ndp::NeighborAdvertPacket;

        // TODO: add router flag or not
        if dst_addr.is_multicast() {
            pkt = packets::generate_NA_forwarded(
                &src_addr,
                &dst_addr,
                &proxied_addr,
                &src_hwaddr,
                0b00000000,
            )
            .unwrap();
        } else {
            pkt = packets::generate_NA_forwarded(
                &src_addr,
                &dst_addr,
                &proxied_addr,
                &src_hwaddr,
                0b01000000,
            )
            .unwrap();
        }

        // TODO: logging INFO
        println!(
            "[#] sent my NA for {:?} to {:?} on {:?} and the process returns {:?}",
            proxied_addr,
            tgt.ip(),
            iface.get_name(),
            iface_sender.send_to(pkt.packet(), &tgt.into())
        );
        // End of logging
    }
}

// monitor all the NS packets of a interface
#[allow(non_snake_case)]
fn monitor_NS(
    proxied_iface: interfaces::NDInterface,
    proxied_id: usize,
    proxied_pfx: ipnet::Ipv6Net,
    mpsc_tx: Sender<(ndp::NeighborSolicitPacket, usize, Ipv6Addr)>,
) {
    // assume it is ethernet
    // TODO: try to determine what link type it is.
    let mut monitor_config: datalink::Config = Default::default();
    monitor_config.channel_type = datalink::ChannelType::Layer3(0x86DD);
    // initialize the monitor
    let (_tx, mut monitor) = match datalink::channel(proxied_iface.get_from_pnet(), monitor_config)
    {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    drop(_tx);
    // TODO: logging
    println!(
        "[#] Initialized _Neighbor Solicitation_ monitor on interface {:?}.",
        proxied_iface.get_name()
    );
    // End of Logging
    //
    loop {
        let packet = match monitor.next() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // check the header of Icmpv6
        if packet[40] == Icmpv6Types::NeighborSolicit.0 {
            let the_ndp = match ndp::NeighborSolicitPacket::owned(packet[40..].to_vec()) {
                Some(v) => v,
                None => continue,
            };
            let ns_target_addr = the_ndp.get_target_addr();
            // TODO: logging: DEBUG
            let node_addr = address::construct_v6addr_from_vecu8(&packet[8..24]);
            println!(
                "[#] Got a neighbor solicitation from {:?} for {:?} on interface {:?}.",
                node_addr,
                ns_target_addr,
                proxied_iface.get_name()
            );
            // End of Logging
            if proxied_pfx.contains(&ns_target_addr) {
                let node_addr = address::construct_v6addr_from_vecu8(&packet[8..24]);
                let _res = mpsc_tx.send((the_ndp, proxied_id, node_addr));
            };
        }
    }
}
