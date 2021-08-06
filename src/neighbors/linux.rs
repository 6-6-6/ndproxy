use futures::stream::TryStreamExt;
use netlink_packet_route::rtnl::neighbour::nlas::Nla;
use pnet::util::MacAddr;
use rtnetlink::{new_connection, IpVersion};
use std::net::Ipv6Addr;
use std::time::Duration;
use ttl_cache::TtlCache;

/// the status of a neighbour entry
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

/// wrapper for rtnetlink::NeighbourGetRequest
pub struct Neighbors {
    /// communicate with netlink
    handle: rtnetlink::NeighbourHandle,
    /// cache results of `ip -6 neigh`
    /// to reduce the frequency of communication with kernel
    cache: TtlCache<Ipv6Addr, (Vec<u8>, u32)>,
}

impl Neighbors {
    // TODO: magic number here
    pub const CACHE_LIFETIME: Duration = Duration::from_millis(150);

    pub fn new() -> Self {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        Self {
            handle: handle.neighbours(),
            cache: TtlCache::new(256),
        }
    }

    /// `ip -6 neigh`
    async fn update_cache(&mut self) {
        // return if cache is not expired
        if self.cache.get(&Ipv6Addr::UNSPECIFIED).is_some() {
            return;
        };
        //
        self.cache
            .insert(Ipv6Addr::UNSPECIFIED, (vec![], 0), Self::CACHE_LIFETIME);
        //
        let mut neighbors = self.handle.get().set_family(IpVersion::V6).execute();
        while let Ok(Some(entry)) = neighbors.try_next().await {
            // update cache only if the neighbor presents
            match entry.header.state {
                // some states which indicate that the neighor MAY exist.
                NeighborStates::NUD_PERMANENT
                | NeighborStates::NUD_NOARP
                | NeighborStates::NUD_REACHABLE
                | NeighborStates::NUD_PROBE
                | NeighborStates::NUD_STALE
                | NeighborStates::NUD_DELAY => (),
                _ => continue,
            };
            //
            let ifidx = entry.header.ifindex;
            let mut v6addr = Ipv6Addr::UNSPECIFIED;
            let mut hwaddr = vec![];
            for item in entry.nlas.into_iter() {
                match item {
                    Nla::Destination(destip) => {
                        v6addr = unsafe { address_translation::construct_v6addr_unchecked(&destip) }
                    }
                    Nla::LinkLocalAddress(v) => hwaddr = v,
                    _ => (),
                }
            }
            self.cache
                .insert(v6addr, (hwaddr, ifidx), Self::CACHE_LIFETIME);
        }
    }

    /// check whether the input address is a valid neighbor
    pub async fn check_whehter_entry_exists(
        &mut self,
        my_entry: &Ipv6Addr,
    ) -> Option<(MacAddr, u32)> {
        //
        self.update_cache().await;
        //
        self.cache.get(my_entry).map(|(hwaddr_vec, ifidx)| {
            (
                MacAddr(
                    hwaddr_vec[0],
                    hwaddr_vec[1],
                    hwaddr_vec[2],
                    hwaddr_vec[3],
                    hwaddr_vec[4],
                    hwaddr_vec[5],
                ),
                *ifidx,
            )
        })
    }
}
