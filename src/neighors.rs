use std::net::Ipv6Addr;
use futures::executor::block_on;
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle, IpVersion};
use netlink_packet_route::rtnl::neighbour::nlas::Nla;
use crate::address;

struct NeighborStates;
impl NeighborStates {
    pub const NUD_INCOMPLETE:u16 = 0x01;
    pub const NUD_REACHABLE:u16 = 0x02;
    pub const NUD_STALE:u16 = 0x04;
    pub const NUD_DELAY:u16 = 0x08;
    pub const NUD_PROBE:u16 = 0x10;
    pub const NUD_FAILED:u16 = 0x20;
    pub const NUD_NOARP:u16 = 0x40;
    pub const NUD_PERMANENT:u16 = 0x80;
    pub const NUD_NONE:u16 = 0x00;
}


pub struct Neighbors {
    // communicate with netlink
    handle: rtnetlink::Handle,
}

impl Neighbors {
    pub fn new() -> Self {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        Neighbors {
            handle
        }
    }

    // check whether we have the related neighbor entry
    pub async fn check_whehter_entry_exists(&self, my_entry: &Ipv6Addr) -> Option<u32> {
        let mut neighbors = self.handle
            .neighbours()
            .get()
            .set_family(IpVersion::V6)
            .execute();
        loop {
            match neighbors.try_next().await {
                Ok(is_ok) => match is_ok {
                    Some(entry) => {
                        for nla in entry.nlas.iter() {
                            match nla {
                                Nla::Destination(destip) => {
                                    if &address::construct_v6addr_from_vecu8(destip) != my_entry {break};
                                    match entry.header.state {
                                        NeighborStates::NUD_PERMANENT|NeighborStates::NUD_NOARP|NeighborStates::NUD_REACHABLE => return Some(entry.header.ifindex),
                                        _ => (),
                                    }
                                },
                                _ => (),
                            }
                        }
                    }
                    None => break,
                },
                Err(_) => break,
            }
        }
        None
    }

    // sync version
    pub fn check_whehter_entry_exists_sync(&self, my_entry: &Ipv6Addr) -> Option<u32> {
        block_on(self.check_whehter_entry_exists(my_entry))
    }
}
