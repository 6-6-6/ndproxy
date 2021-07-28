use crate::address;
use crate::conf;
use crate::datalink;
use crate::datalink::PacketReceiverOpts;
use crate::interfaces;
use crate::neighbors;
use crate::packets;
use log::{debug, info, trace, warn};
use pnet::packet::icmpv6::ndp;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::Packet;
use socket2::Socket;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

type ProxyNSPack<'a> = (ndp::NeighborSolicitPacket<'a>, u32, Ipv6Addr);

/*
 * an object the reveives NS packets from the monitor,
 *    forward the NS to downstreams,
 *    and send the corresponding NA to upstreams
 */
#[derive(getset::Getters)]
pub struct NeighborDiscoveryProxyItem {
    #[get = "pub with_prefix"]
    config: conf::NDConfig,
    #[get = "pub with_prefix"]
    proxied_ifaces: HashMap<u32, interfaces::NDInterface>,
    proxied_if_senders: HashMap<u32, Socket>,
    forwarded_ifaces: HashMap<u32, interfaces::NDInterface>,
    forwarded_if_senders: HashMap<u32, Socket>,
    neighbor_handle: neighbors::Neighbors,
    // TODO: whether I should set Router flag
}

impl NeighborDiscoveryProxyItem {
    pub fn new(config: conf::NDConfig) -> Self {
        let (proxied_ifaces, forwarded_ifaces) = interfaces::get_ifaces_defined_by_config(&config);
        let neighbor_handle = neighbors::Neighbors::new();
        // to send NS to upstream
        let proxied_if_senders = interfaces::prepare_sockets_for_ifaces(&proxied_ifaces);
        // to trigger Neighbor Discovery locally
        let forwarded_if_senders;
        match *config.get_proxy_type() {
            conf::PROXY_STATIC => forwarded_if_senders = HashMap::new(),
            _ => forwarded_if_senders = interfaces::prepare_sockets_for_ifaces(&forwarded_ifaces),
        };
        // logging warn
        warn!(
            "Initializing NeighborDiscoveryProxyItem...\n\
            \tconfig: {:?}\n\
            \tProxying _Neighbor Solicitation_ for: {:?}\n\
            \tForwarding _Neighbor Advertisement_ for: {:?}",
            config,
            proxied_ifaces.keys().map(|k| proxied_ifaces[k].get_name()),
            forwarded_ifaces
                .keys()
                .map(|k| forwarded_ifaces[k].get_name())
        );
        // End of logging

        NeighborDiscoveryProxyItem {
            config,
            proxied_ifaces,
            proxied_if_senders,
            forwarded_ifaces,
            forwarded_if_senders,
            neighbor_handle, //router flag
        }
    }

    /*
     * accept a mpsc_receiver, and
     *   pass the rx to self.process_NS_* to process upstream NSes
     */
    pub fn run(&self, mpsc_rx: Receiver<ProxyNSPack>) {
        if *self.config.get_proxy_type() == conf::PROXY_STATIC {
            self.process_NS_static(mpsc_rx)
        } else if *self.config.get_proxy_type() == conf::PROXY_FORWARD {
            self.process_NS_forward(mpsc_rx)
        }
    }

    #[allow(non_snake_case)]
    fn process_NS_static(&self, mpsc_rx: Receiver<ProxyNSPack>) {
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
    fn process_NS_forward(&self, mpsc_rx: Receiver<ProxyNSPack>) {
        // for NPTv6
        let upstream_pfx_csum = address_translation::pfx_csum(self.config.get_proxied_pfx());
        let downstream_pfx_csum = address_translation::pfx_csum(self.config.get_dst_pfx());
        let pfx_len = self.config.get_dst_pfx().prefix_len();
        // for RFC 4291#section-2.6.1
        let no_response_addresses =
            address::get_no_forwarding_addresses(self.config.get_proxied_pfx());
        loop {
            // receive msg from mpsc transmitter
            let (the_ndp, ndp_receiver_id, node_addr) = match mpsc_rx.recv() {
                Ok(v) => v,
                // TODO: logging
                Err(_) => continue,
            };
            let original_requested_address = the_ndp.get_target_addr();
            if no_response_addresses.contains(&original_requested_address) {
                continue;
            };
            // determine the target address: whether we need to rewrite it and how to rewrite it
            let tgt_addr = match *self.config.get_address_mangling() {
                conf::ADDRESS_NETMAP => address_translation::netmapv6(
                    original_requested_address,
                    self.config.get_dst_pfx(),
                ),
                conf::ADDRESS_NPT => address_translation::nptv6(
                    upstream_pfx_csum,
                    downstream_pfx_csum,
                    ipnet::Ipv6Net::new(original_requested_address, pfx_len).unwrap(),
                    *self.config.get_dst_pfx(),
                ),
                _ => original_requested_address,
            };
            // play some trick, ask our OS to discover its neighbor
            for (scope_id, iface) in self.forwarded_ifaces.iter() {
                let sender = self.forwarded_if_senders.get(scope_id).unwrap();
                let addr = SocketAddrV6::new(tgt_addr, 0, 0, *iface.get_scope_id());
                // never expecting it could go wrong
                let send_pkt =
                    packets::generate_NS_trick(&the_ndp, iface.get_link_addr(), &addr.ip()).expect(
                        "Failed while generating Echo Request Message for detecting neighbors.",
                    );
                let send_ret = sender.send_to(send_pkt.packet(), &addr.into());
                // logging debug
                debug!(
                    "Discovering Neighbor {:?} on interface {:?}, the result of sending this packet (icmpv6 type {:?}) is {:?}",
                    tgt_addr,
                    iface.get_name(),
                    send_pkt.get_icmpv6_type(),
                    send_ret
                );
                // End of logging
            }
            self.forward_NA_wrapper(node_addr, tgt_addr, the_ndp, ndp_receiver_id)
        }
    }

    /*
     * just a wrapper
     *
     * TODO: rewrite it the async way, and make it wait for a random time to make the discovery complete
     */
    #[allow(non_snake_case)]
    fn forward_NA_wrapper(
        &self,
        node_addr: Ipv6Addr,
        tgt_addr: Ipv6Addr,
        the_ndp: ndp::NeighborSolicitPacket,
        ndp_receiver_id: u32,
    ) {
        /*
        println!("{:?}", self
        .neighbor_handle
        .check_whehter_entry_exists_sync(&tgt_addr));
        */
        if let Some((_mac, scope_id)) = self
            .neighbor_handle
            .check_whehter_entry_exists_sync(&tgt_addr)
        {
            /*
             * make sure the neighbor cache does not come from the same iface
             *   which we are going to send NA to
             */
            if &scope_id != self.proxied_ifaces[&ndp_receiver_id].get_scope_id() {
                self.forward_NA(ndp_receiver_id, the_ndp.get_target_addr(), node_addr);
                // just a magic number
                if rand::random::<u8>() > 200 {
                    self.forward_NA(
                        ndp_receiver_id,
                        the_ndp.get_target_addr(),
                        "ff02::1".parse().unwrap(),
                    )
                }
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn forward_NA(&self, proxied_if_index: u32, proxied_addr: Ipv6Addr, dst_addr: Ipv6Addr) {
        // get items
        let iface = self.proxied_ifaces.get(&proxied_if_index).unwrap();
        let iface_sender = self.proxied_if_senders.get(&proxied_if_index).unwrap();
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

        let ret = iface_sender.send_to(pkt.packet(), &tgt.into());
        // logging info
        info!(
            "Sent NA for {:?} to {:?} on {:?} and the process returns {:?}",
            proxied_addr,
            tgt.ip(),
            iface.get_name(),
            ret
        );
        // End of logging
    }
}

// monitor all the NS packets of a interface
#[allow(non_snake_case)]
fn monitor_NS(
    proxied_iface: interfaces::NDInterface,
    proxied_id: u32,
    mpsc_txes: HashMap<ipnet::Ipv6Net, Sender<ProxyNSPack>>,
) {
    /*
     * The truth that mpsc_txes is empty indicates that
     *   there is no ipv6 NSes for us to proxy,
     *   so I will just stop here and stop monitoring the interface
     */
    if mpsc_txes.is_empty() {
        return;
    }
    // create the monitor, and set it up
    let mut monitor = datalink::PacketReceiver::new();
    let _ret = monitor.bind_to_interface(&proxied_iface);
    _ret.unwrap_or_else(|_| {
        panic!(
            "Failed to bind to interface {}, the process returned {:?}",
            proxied_iface.get_name(),
            _ret
        )
    });
    let _ret = monitor.set_filter_pass_ipv6_ns();
    _ret.unwrap_or_else(|_| {
        panic!(
            "Failed to set the packet filter on interface {}, the process returned {:?}",
            proxied_iface.get_name(),
            _ret
        )
    });
    let _ret = monitor.set_allmulti(&proxied_iface);
    _ret.unwrap_or_else(|_| {
        panic!(
            "Failed to enable promiscuous mode on interface {}, the process returned {:?}",
            proxied_iface.get_name(),
            _ret
        )
    });
    //*/
    // logging warn
    warn!(
        "Initialized _Neighbor Solicitation_ monitor on interface {:?}.\n\
         \tMonitoring Neighbor Solicitaions for {:?}",
        proxied_iface.get_name(),
        mpsc_txes.keys()
    );
    // End of Logging
    //
    loop {
        let packet = match monitor.next() {
            Some(v) => v,
            None => continue,
        };
        // check the header of Icmpv6 (there platforms that do not support BPF)
        if packet[40] == Icmpv6Types::NeighborSolicit.0 {
            let the_ndp = match ndp::NeighborSolicitPacket::new(&packet[40..]) {
                Some(v) => v,
                None => continue,
            };
            let ns_target_addr = the_ndp.get_target_addr();
            // logging trace
            unsafe {
                trace!(
                    "Got a neighbor solicitation from {:?} to {:?} for {:?} on interface {:?}.",
                    address_translation::construct_v6addr(&packet[8..24]),
                    address_translation::construct_v6addr(&packet[24..40]),
                    ns_target_addr,
                    proxied_iface.get_name()
                )
            };
            // End of Logging
            // send clone of the NS packet to _every_ receiver that matches this prefix (maybe too expensive)
            for (pfx, mpsc_tx) in mpsc_txes.iter() {
                if pfx.contains(&ns_target_addr) {
                    let node_addr =
                        unsafe { address_translation::construct_v6addr(&packet[8..24]) };
                    let _res = mpsc_tx.send((
                        ndp::NeighborSolicitPacket::owned(packet[40..].to_vec()).unwrap(),
                        proxied_id,
                        node_addr,
                    ));
                }
            }
        }
    }
}

// to simplify the types beloww
type MonitorPack<'a> = (NeighborDiscoveryProxyItem, Receiver<ProxyNSPack<'a>>);
type ForwarderPack<'a> = (
    interfaces::NDInterface,
    HashMap<ipnet::Ipv6Net, Sender<ProxyNSPack<'a>>>,
);

fn prepare_monitors_and_forwarders<'a>(
    mut conf_items: Vec<conf::NDConfig>,
) -> (Vec<MonitorPack<'a>>, HashMap<u32, ForwarderPack<'a>>) {
    let mut proxy_forwarders = Vec::new();
    let mut tx_vec = Vec::new();

    // prepare NeighborDiscoveryProxyItems and mpsc_rx for calling `run()`
    while let Some(conf_item) = conf_items.pop() {
        let (mpsc_tx, mpsc_rx) = channel();
        let proxy_item = NeighborDiscoveryProxyItem::new(conf_item);
        proxy_forwarders.push((proxy_item, mpsc_rx));
        tx_vec.push(mpsc_tx);
    }

    // prepare materials for calling `monitor_NS()`
    let mut proxy_monitors = HashMap::new();
    // get all the interfaces
    for (scope_id, iface) in interfaces::get_ifaces_with_name(&["*".to_string()]) {
        let mut mpsc_txes = HashMap::new();
        /*
         * iter through the proxy items
         *   if the proxy item is proxying NS from this interface
         *   I will record the related (IPv6 prefix, mpsc sender)
         */
        for ((proxy_item, _rx), tx) in proxy_forwarders.iter().zip(tx_vec.iter()) {
            if let Some(_iface) = proxy_item.get_proxied_ifaces().get(&scope_id) {
                if let Some(_tx) =
                    mpsc_txes.insert(*proxy_item.get_config().get_proxied_pfx(), tx.clone())
                {
                    panic!(
                        "I did not expect that there are multiple same prefixes\
                         in the configuration file."
                    );
                };
            }
        }
        // record the scope id of the interface and its related IPv6 prefixes
        if let Some(_txes) = proxy_monitors.insert(scope_id, (iface, mpsc_txes)) {
            panic!("scope_id exists twice")
        };
    }

    drop(tx_vec);
    (proxy_forwarders, proxy_monitors)
}

pub fn spawn_monitors_and_forwarders(conf_items: Vec<conf::NDConfig>) {
    let (mut forwarders, mut monitors) = prepare_monitors_and_forwarders(conf_items);
    let mut handles = Vec::new();
    // spawn all the monitors
    for (id, (monitored_iface, mpsc_txes)) in monitors.drain() {
        let handle = thread::Builder::new()
            .name(format!("[{}] NS Monitor", monitored_iface.get_name()))
            .spawn(move || monitor_NS(monitored_iface, id, mpsc_txes))
            .expect("Failed to spawn NS Monitor thread.");
        handles.push(handle);
    }

    // spawn all the forwarders
    while let Some((proxy_item, mpsc_rx)) = forwarders.pop() {
        let handle = thread::Builder::new()
            .name(format!(
                "[{}] NA Forwarder",
                proxy_item.get_config().get_name()
            ))
            .spawn(move || proxy_item.run(mpsc_rx))
            .expect("Failed to spawn NA Forwarder thread.");
        handles.push(handle);
    }

    while let Some(handle) = handles.pop() {
        // hold on
        let _ret = handle.join();
    }
}
