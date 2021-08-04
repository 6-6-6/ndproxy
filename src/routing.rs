use ipnet::Ipv6Net;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use treebitmap::IpLookupTable;

pub type SharedNSPacket = (u32, Arc<Ipv6Addr>, Arc<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::UnboundedSender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::UnboundedReceiver<SharedNSPacket>;

pub fn construst_route_table(
    mut prelude: HashMap<Ipv6Net, SharedNSPacketSender>,
) -> IpLookupTable<Ipv6Addr, SharedNSPacketSender> {
    let mut ret = IpLookupTable::new();
    for (key, value) in prelude.drain() {
        ret.insert(key.network(), key.prefix_len() as u32, value);
    }
    ret
}
