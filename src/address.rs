use ipnet::Ipv6Net;
use std::collections::HashSet;
use std::net::Ipv6Addr;

/// NOT forwarding NS for some special addresses
///     1. https://datatracker.ietf.org/doc/html/rfc4291#section-2.6.1
pub fn get_no_forwarding_addresses(prefix: &Ipv6Net) -> HashSet<Ipv6Addr> {
    let mut addr_set = HashSet::new();
    addr_set.insert(prefix.network());
    addr_set
}

//TODO: tests
