use futures::executor::block_on;
use futures::stream::TryStreamExt;
use netlink_packet_route::rtnl::neighbour::nlas::Nla;
use pnet::util::MacAddr;
use rtnetlink::{new_connection, IpVersion};
use std::net::Ipv6Addr;

struct NeighborStates;
#[allow(dead_code)]
impl NeighborStates {
    pub const NUD_INCOMPLETE: u16 = 0x01;
    pub const NUD_REACHABLE: u16 = 0x02;
    pub const NUD_STALE: u16 = 0x04;
    pub const NUD_DELAY: u16 = 0x08;
    pub const NUD_PROBE: u16 = 0x10;
    pub const NUD_FAILED: u16 = 0x20;
    pub const NUD_NOARP: u16 = 0x40;
    pub const NUD_PERMANENT: u16 = 0x80;
    pub const NUD_NONE: u16 = 0x00;
}

pub struct Neighbors {
    // communicate with netlink
    handle: rtnetlink::NeighbourHandle,
}

impl Neighbors {
    pub fn new() -> Self {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        Neighbors { handle: handle.neighbours() }
    }

    // check whether we have the related neighbor entry
    pub async fn check_whehter_entry_exists(&self, my_entry: &Ipv6Addr) -> Option<(MacAddr, u32)> {
        let mut neighbors = self
            .handle
            .get()
            .set_family(IpVersion::V6)
            .execute();
        while let Ok(Some(entry)) = neighbors.try_next().await {
            let mut iter_through_nlas = entry.nlas.iter();
            while let Some(Nla::Destination(destip)) = iter_through_nlas.next() {
                // break if this entry does not match our requested address.
                if &unsafe { address_translation::construct_v6addr(destip) } != my_entry {
                    break;
                };
                match entry.header.state {
                    // some states which indicate that the neighor MAY exist.
                    NeighborStates::NUD_PERMANENT
                    | NeighborStates::NUD_NOARP
                    | NeighborStates::NUD_REACHABLE
                    | NeighborStates::NUD_PROBE
                    | NeighborStates::NUD_STALE
                    | NeighborStates::NUD_DELAY => {
                        // get it a Mac address and return
                        let mut macaddr = MacAddr::zero();
                        let mut iter_through_nlas = entry.nlas.iter();
                        while let Some(Nla::LinkLocalAddress(v)) = iter_through_nlas.next() {
                            macaddr.0 = v[0];
                            macaddr.1 = v[1];
                            macaddr.2 = v[2];
                            macaddr.3 = v[3];
                            macaddr.4 = v[4];
                            macaddr.5 = v[5];
                        }
                        return Some((macaddr, entry.header.ifindex));
                    }
                    _ => (),
                }
            }
        }
        None
    }

    // sync version
    pub fn check_whehter_entry_exists_sync(&self, my_entry: &Ipv6Addr) -> Option<(MacAddr, u32)> {
        block_on(self.check_whehter_entry_exists(my_entry))
    }
}
