use std::net::{IpAddr,Ipv6Addr,SocketAddrV6};
use pnet::datalink;
use socket2::{Socket,Type,Domain,Protocol};
use crate::conf;

#[derive(getset::Getters)]
pub struct NDInterface {
    #[get = "pub with_prefix"]
    name: String,
    #[get = "pub with_prefix"]
    scope_id: u32,
    #[get = "pub with_prefix"]
    link_addr: Ipv6Addr,
    #[get = "pub with_prefix"]
    sender: Socket,
}

fn get_specified_iface(raw: &datalink::NetworkInterface) -> Option<NDInterface> {
    for addr in raw.ips.iter() {
        match addr.ip() {
            IpAddr::V4(_) => continue,
            IpAddr::V6(ip) => {
                if ip.octets()[0] == 0xfe && ip.octets()[1] == 0x80 {
                    //
                    let link_addr = ip;
                    // create sender
                    let sender = Socket::new(Domain::IPV6,
                        Type::RAW,
                        Some(Protocol::ICMPV6)).unwrap();
                    let addr = SocketAddrV6::new(ip, 0, 0, raw.index);
                    println!("{:?}", addr);
                    // panic if it fails to bind
                    let _res = sender.bind(&addr.into()).unwrap();
                    //
                    return Some(NDInterface {
                        name: String::from(&raw.name),
                        scope_id: raw.index,
                        link_addr,
                        sender,
                    });
                }
                /*
                 * TODO: use is_unicast_link_local_strict() once its stablized.
                if ip.is_unicast_link_local_strict() {
                    link_addr = ip;
                }
                */
            }
        }
    };
    None
}

// given a list of names of interfaces, return a list of NDInterfaces
fn get_ifaces_with_name(names: &Vec<String>) -> Vec<NDInterface> {
    let mut ret = Vec::new();

    if names.contains(&String::from("*")) {
        for iface in datalink::interfaces().iter() {
            match get_specified_iface(iface) {
                Some(v) => ret.push(v),
                _ => ()
            }
        }
    } else {
        for iface in datalink::interfaces().iter() {
            if names.contains(&iface.name) {
                match get_specified_iface(iface) {
                    Some(v) => ret.push(v),
                    _ => ()
                }
            }
        }
    }

    ret
}

// return the proxied interface and the forwarded interface
pub fn get_ifaces_defined_by_config(ndconf: &conf::NDConfig) -> (Vec<NDInterface>, Vec<NDInterface>) {
    let proxied_ifaces = get_ifaces_with_name(&ndconf.get_proxied_ifaces());
    let forwarded_ifaces = get_ifaces_with_name(&ndconf.get_forwarded_ifaces());
    (proxied_ifaces, forwarded_ifaces)
}

#[test]
fn test_get_ifaces_with_name() {
    let ret = get_ifaces_with_name(&vec![String::from("lo")]);
    assert_eq!(ret.len(), 0);
}
