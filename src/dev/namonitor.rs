use crate::datalink::{PacketReceiver, PacketReceiverOpts};
use crate::error;
use crate::interfaces::{self, NDInterface};
use log::{error, warn};

/// monitors for Neighbor Solicitation
/// the received packet will be sent to the corresponding NDProxy via mpsc
/// the corresponding NDProxy is determined by looking up the route entry for the target address in routing table
#[derive(getset::Getters, getset::Setters, getset::MutGetters)]
pub struct NAMonitor {
    #[get_mut = "pub with_prefix"]
    inner: PacketReceiver,
    #[get = "pub with_prefix"]
    iface: NDInterface,
}

impl NAMonitor {
    pub fn new(iface_names: &[String]) -> Option<Self> {
        //
        let tmp: Vec<NDInterface> = interfaces::get_ifaces_with_name(iface_names)
            .into_values()
            .collect();
        let iface: NDInterface = tmp[0].clone();
        //
        let inner = PacketReceiver::new();
        if let Err(e) = inner.bind_to_interface(&iface) {
            error!("[{:?}] Failed to bind to interface {}", e, iface.get_name());
            return None;
        };
        if let Err(e) = inner.set_allmulti(&iface) {
            error!(
                "[{:?}] Failed to set ALLMULTI on interface {}",
                e,
                iface.get_name()
            );
            return None;
        };
        if let Err(e) = inner.set_filter_pass_ipv6_na() {
            error!(
                "[{:?}] Failed to attach BPF filter to interface {}",
                e,
                iface.get_name()
            );
            return None;
        };
        Some(Self { inner, iface })
    }

    /// main loop: receive NS packet and forward it to related consumer
    pub fn run(mut self) -> Result<(), error::Error> {
        warn!("NAMonitor for {}: Start to work", self.iface.get_name());
        for packet in self.inner.by_ref() {
            if packet.len() < 64 {
                continue;
            };
            let shared_packet = Box::new(packet);
            // call construct_v6addr_unchecked() instead of construct the whole pkt into NeighborSolicitionPacket
            // check NA packet structure
            let tgt_addr = unsafe {
                Box::new(address_translation::construct_v6addr_unchecked(
                    &shared_packet[48..64],
                ))
            };
            // logging
            unsafe {
                println!(
                    "NAMonitor for {}: Get a NA from {} to {} advertising 📢{}📢.",
                    self.iface.get_name(),
                    // src_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[8..24]),
                    // dst_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[24..40]),
                    tgt_addr,
                );
            }
        }
        Ok(())
    }
}
