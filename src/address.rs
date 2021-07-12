use std::net::Ipv6Addr;

// construct an Ipv6Addr from a vector, make sure it conatins more than 16 elements!!
pub fn construct_v6addr_from_vecu8(local_addr: &[u8]) -> Ipv6Addr {
    let mut new_octets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut i = 0;
    while i < 16 {
        new_octets[i] = local_addr[i];
        i += 1;
    }
    Ipv6Addr::from(new_octets)
}
