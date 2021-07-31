use crate::datalink::{PacketReceiver, PacketReceiverOpts};
use crate::interfaces::NDInterface;
use crate::routing::SharedNSPacketSender;
use log::{error, warn, trace};
use std::net::Ipv6Addr;
use std::sync::Arc;
use treebitmap::IpLookupTable;

/// monitors for Neighbor Solicitation
#[derive(getset::Getters, getset::Setters, getset::MutGetters)]
pub struct NSMonitor {
    #[get_mut = "pub with_prefix"]
    inner: PacketReceiver,
    #[get = "pub with_prefix"]
    #[set = "pub with_prefix"]
    routing_table: IpLookupTable<Ipv6Addr, SharedNSPacketSender>,
    #[get = "pub with_prefix"]
    iface: NDInterface,
}

impl NSMonitor {
    pub fn new(
        routing_table: IpLookupTable<Ipv6Addr, SharedNSPacketSender>,
        iface: NDInterface,
    ) -> Option<Self> {
        let inner = PacketReceiver::new();
        if let Err(_) = inner.bind_to_interface(&iface) {
            error!("Failed to bind to interface {}", iface.get_name());
            return None;
        };
        if let Err(_) = inner.set_allmulti(&iface) {
            error!("Failed to set ALLMULTI on interface {}", iface.get_name());
            return None;
        };
        if let Err(_) = inner.set_filter_pass_ipv6_ns() {
            error!(
                "Failed to attach BPF filter to interface {}",
                iface.get_name()
            );
            return None;
        };
        Some(Self {
            inner,
            routing_table,
            iface,
        })
    }

    /// main loop: receive NS packet and forward it to related consumer
    pub async fn run(mut self) {// -> Result<(), ()> {
        let macaddr = self.iface.get_hwaddr().clone();
        warn!("NSMonitor for {}: Start to work", self.iface.get_name());
        while let Some(packet) = self.inner.next() {
            if packet.len() < 64 {
                continue;
            };
            let shared_packet = packet;
            // call construct_v6addr() instead of construct the whole pkt into NeighborSolicitionPacket
            let tgt_addr = unsafe { address_translation::construct_v6addr(&shared_packet[48..64]) };
            // logging
            unsafe {
                trace!("NSMonitor for {}: Get a NS from {} to {} looking for 🔍{}🔍.",
                    self.iface.get_name(),
                    // src_addr
                    address_translation::construct_v6addr(&shared_packet[8..24]),
                    // dst_addr
                    address_translation::construct_v6addr(&shared_packet[24..40]),
                    tgt_addr,
                );
            }
            println!("################ {:?}", self.routing_table.longest_match(tgt_addr));
            if let Some((_pfx, _pfx_len, sender)) = self.routing_table.longest_match(tgt_addr) {
                if let Err(e) = sender.send((*self.iface.get_scope_id(), macaddr.clone() ,shared_packet)) {
                    error!("NSMonitor for {}: _{:?}_ Failed to send the packet searching for {} to its corresponding proxier.", self.iface.get_name(), e, tgt_addr);
                    break;
                };
            }
        }
        //Ok(())
    }
}
