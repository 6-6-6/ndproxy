use std::sync::mpsc;
use std::sync::Arc;
use treebitmap::IpLookupTable;
use std::net::Ipv6Addr;
use ipnet::Ipv6Net;
use std::collections::HashMap;

pub type SharedNSPacket = Arc<Vec<u8>>;
pub type SharedNSPacketSender = mpsc::Sender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::Receiver<SharedNSPacket>;


fn construst_route_table(mut prelude: HashMap<Ipv6Net, SharedNSPacketSender>) -> IpLookupTable<Ipv6Addr, SharedNSPacketSender> {
    let mut ret = IpLookupTable::new();
    for (key, value) in prelude.drain() {
        ret.insert(key.network(), key.prefix_len() as u32, value);
    }
    ret
}