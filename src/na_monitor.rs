use crate::datalink::{PacketReceiver, PacketReceiverOpts};
use crate::error::Error;
use crate::interfaces::NDInterface;
use crate::types::*;
use log::{debug, warn};

/// monitors for Neighbor Solicitation
/// the received packet will be sent to the corresponding NDProxy via mpsc
/// the corresponding NDProxy is determined by looking up the route entry for the target address in routing table
#[derive(getset::Getters, getset::Setters, getset::MutGetters)]
pub struct NAMonitor {
    #[get_mut = "pub with_prefix"]
    inner: PacketReceiver,
    #[get = "pub with_prefix"]
    iface: NDInterface,
    /// manage ndp myself
    neighbors_cache: NeighborsCache,
}

impl NAMonitor {
    pub fn new(iface: NDInterface, neighbors_cache: NeighborsCache) -> Result<Self, Error> {
        let inner = PacketReceiver::new()?;
        inner.bind_to_interface(&iface)?;
        inner.set_allmulti(&iface)?;
        inner.set_filter_pass_ipv6_na()?;

        Ok(Self {
            inner,
            iface,
            neighbors_cache,
        })
    }

    /// main loop: receive NS packet and forward it to related consumer
    pub async fn run(mut self) -> Result<(), Error> {
        warn!("NAMonitor for {}: Start to work", self.iface.get_name());
        loop {
            let packet = self.inner.recv_pkt().await?;
            if packet.len() < 64 {
                continue;
            };
            let shared_packet = Box::new(packet);
            // call construct_v6addr_unchecked() instead of construct the whole pkt into NeighborSolicitionPacket
            let tgt_addr = unsafe {
                Box::new(address_translation::construct_v6addr_unchecked(
                    &shared_packet[48..64],
                ))
            };
            // logging
            unsafe {
                debug!(
                    "NAMonitor for {}: Get a NA from {} to {} advertising 📢{}📢.",
                    self.iface.get_name(),
                    // src_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[8..24]),
                    // dst_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[24..40]),
                    tgt_addr,
                );
            }
            // update ttl cache
            self.neighbors_cache
                .set((*self.iface.get_scope_id(), *tgt_addr), (), None);
        }
    }
}
