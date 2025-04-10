use crate::datalink::{PacketReceiver, PacketReceiverOpts};
use crate::error::Error;
use crate::interfaces::NDInterface;
use crate::types::SharedNSPacketSender;
use ip_network_table_deps_treebitmap::IpLookupTable;
use log::{debug, error, trace, warn};
use std::net::Ipv6Addr;

/// monitors for Neighbor Solicitation
/// the received packet will be sent to the corresponding NDProxy via mpsc
/// the corresponding NDProxy is determined by looking up the route entry for the target address in routing table
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
    ) -> Result<Self, Error> {
        let inner = PacketReceiver::new()?;
        inner.bind_to_interface(&iface)?;
        inner.set_allmulti(&iface)?;
        inner.set_filter_pass_ipv6_ns()?;

        Ok(Self {
            inner,
            routing_table,
            iface,
        })
    }

    /// main loop: receive NS packet and forward it to related consumer
    pub async fn run(mut self) -> Result<(), Error> {
        warn!("NSMonitor for {}: Start to work", self.iface.get_name());
        loop {
            let packet = self.inner.recv_pkt().await?;
            trace!("{:?}", packet);
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
                trace!(
                    "NSMonitor for {}: Get a NS from {} to {} looking for 🔍{}🔍.",
                    self.iface.get_name(),
                    // src_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[8..24]),
                    // dst_addr
                    address_translation::construct_v6addr_unchecked(&shared_packet[24..40]),
                    tgt_addr,
                );
            }
            // logging again
            debug!(
                "NSMonitor for {}: Get route for 🔍{}🔍 - {:?}",
                self.iface.get_name(),
                tgt_addr,
                self.routing_table.longest_match(*tgt_addr)
            );
            if let Some((pfx, _pfx_len, sender)) = self.routing_table.longest_match(*tgt_addr) {
                // NOT forwarding NS for some special addresses
                //     1. https://datatracker.ietf.org/doc/html/rfc4291#section-2.6.1
                if pfx == *tgt_addr {
                    continue;
                };
                //
                if let Err(e) = sender
                    .send((*self.iface.get_scope_id(), tgt_addr, shared_packet))
                    .await
                {
                    error!(
                        "NSMonitor for {}: _{:?}_ Failed to send the packet to its corresponding proxy.",
                        self.iface.get_name(),
                        e
                    );
                    return Err(Error::Mpsc(e));
                };
            }
        }
    }
}
