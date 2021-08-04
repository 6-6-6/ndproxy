use crate::conf;
use pnet::datalink;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

#[derive(getset::Getters, Clone, Debug, PartialEq)]
pub struct NDInterface {
    #[get = "pub with_prefix"]
    name: String,
    #[get = "pub with_prefix"]
    scope_id: u32,
    #[get = "pub with_prefix"]
    link_addr: Ipv6Addr,
    #[get = "pub with_prefix"]
    hwaddr: MacAddr,
    #[get = "pub with_prefix"]
    from_pnet: datalink::NetworkInterface,
}

// convert datalink::NetworkInterface to NDInterface
fn get_specified_iface(raw: datalink::NetworkInterface) -> Option<NDInterface> {
    for addr in raw.ips.iter() {
        if let IpAddr::V6(ip) = addr.ip() {
            /*
             * get
             * TODO: use is_unicast_link_local_strict() once its stablized.
            if ip.is_unicast_link_local_strict() {
                link_addr = ip;
            }
            */
            if ip.octets()[0] == 0xfe && ip.octets()[1] == 0x80 {
                //
                let link_addr = ip;
                //
                let hwaddr = match raw.mac {
                    Some(v) => v,
                    None => MacAddr::new(0, 0, 0, 0, 0, 0),
                };
                //
                return Some(NDInterface {
                    name: String::from(&raw.name),
                    scope_id: raw.index,
                    link_addr,
                    hwaddr,
                    from_pnet: raw,
                });
            }
        }
    }
    None
}

// given a list of names of interfaces, return a list of NDInterfaces
pub fn get_ifaces_with_name(names: &[String]) -> HashMap<u32, NDInterface> {
    let mut ret = HashMap::new();

    if names.contains(&String::from("*")) {
        for iface in datalink::interfaces() {
            if let Some(v) = get_specified_iface(iface) {
                ret.insert(v.scope_id, v);
            }
        }
    } else {
        for iface in datalink::interfaces() {
            if names.contains(&iface.name) {
                if let Some(v) = get_specified_iface(iface) {
                    ret.insert(v.scope_id, v);
                }
            }
        }
    }

    ret
}

// return the proxied interface and the forwarded interface
pub fn get_ifaces_defined_by_config(
    ndconf: &conf::NDConfig,
) -> (HashMap<u32, NDInterface>, HashMap<u32, NDInterface>) {
    let proxied_ifaces = get_ifaces_with_name(&ndconf.get_proxied_ifaces());
    let forwarded_ifaces = get_ifaces_with_name(&ndconf.get_forwarded_ifaces());
    (proxied_ifaces, forwarded_ifaces)
}

#[test]
fn test_get_ifaces_with_name() {
    let ret = get_ifaces_with_name(&vec![String::from("lo")]);
    assert_eq!(ret.len(), 0);
}
