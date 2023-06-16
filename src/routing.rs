use crate::types::*;
use ip_network_table_deps_treebitmap::IpLookupTable;
use ipnet::Ipv6Net;
use std::collections::HashMap;
use std::net::Ipv6Addr;

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
