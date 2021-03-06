use ipnet::Ipv6Net;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use tokio::sync::mpsc;
use treebitmap::IpLookupTable;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::UnboundedSender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::UnboundedReceiver<SharedNSPacket>;

/// create a routing table from a HashMap that stores route entries
pub fn construst_routing_table(
    prelude: HashMap<Ipv6Net, SharedNSPacketSender>,
) -> IpLookupTable<Ipv6Addr, SharedNSPacketSender> {
    let mut ret = IpLookupTable::new();
    prelude.into_iter().for_each(|(key, value)| {
        ret.insert(key.network(), key.prefix_len() as u32, value);
    });
    ret
}
