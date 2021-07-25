use ipnet::Ipv6Net;
use std::collections::HashSet;
use std::net::Ipv6Addr;

/// construct an Ipv6Addr from a vector, make sure it conatins more than 16 elements!!
pub fn construct_v6addr_from_vecu8(local_addr: &[u8]) -> Ipv6Addr {
    let mut new_octets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut i = 0;
    while i < 16 {
        new_octets[i] = local_addr[i];
        i += 1;
    }
    Ipv6Addr::from(new_octets)
}

/// calculate checksum for NPTv6
pub fn pfx_csum(prefix: &Ipv6Net) -> u16 {
    let mut ret: i32 = 0;
    for x in prefix.network().segments().iter() {
        ret += *x as i32;
    }

    ((ret.rem_euclid(0xffff)) ^ 0xffff) as u16
}

/// see https://datatracker.ietf.org/doc/html/rfc6296
pub fn nptv6(
    upstream_pfx_csum: u16,
    downstream_pfx_csum: u16,
    upstream_addr: Ipv6Net,
    downstream_pfx: Ipv6Net,
) -> Ipv6Addr {
    let pfx_len = upstream_addr.prefix_len() / 16;
    let mut segments = upstream_addr.addr().segments();
    let downstream_segs = downstream_pfx.network().segments();
    let to_be_translated_segment = segments[pfx_len as usize];

    let sum2 = downstream_pfx_csum as i32 - upstream_pfx_csum as i32 + to_be_translated_segment as i32;

    let mut i: usize = 0;
    while i < pfx_len as usize {
        segments[i] = downstream_segs[i];
        i += 1;
    }

    segments[pfx_len as usize] = sum2.rem_euclid(0xffff) as u16;
    Ipv6Addr::from(segments)
}

/// rewrite the prefix
pub fn netmapv6(upstream_addr: Ipv6Addr, downstream_prefix: &Ipv6Net) -> Ipv6Addr {
    let net_u128 = u128::from_be_bytes(upstream_addr.octets())
        & u128::from_be_bytes(downstream_prefix.hostmask().octets());
    let prefix_u128 = u128::from_be_bytes(downstream_prefix.addr().octets())
        & u128::from_be_bytes(downstream_prefix.netmask().octets());
    Ipv6Addr::from((prefix_u128 + net_u128).to_be_bytes())
}

/// NOT forwarding NS for some special addresses
///     1. https://datatracker.ietf.org/doc/html/rfc4291#section-2.6.1
pub fn get_no_forwarding_addresses(prefix: &Ipv6Net) -> HashSet<Ipv6Addr> {
    let mut addr_set = HashSet::new();
    addr_set.insert(prefix.network());
    addr_set
}

//TODO: tests
