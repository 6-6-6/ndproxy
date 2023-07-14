use crate::error::Error;
use ipnet::Ipv6Net;
use std::time::Duration;

#[derive(getset::Getters, Debug, std::cmp::PartialEq, Clone)]
pub struct NDConfig {
    #[get = "pub with_prefix"]
    name: String,
    #[get = "pub with_prefix"]
    proxy_type: Proxy,
    #[get = "pub with_prefix"]
    proxied_pfx: Ipv6Net,
    #[get = "pub with_prefix"]
    proxied_ifaces: Vec<String>,
    #[get = "pub with_prefix"]
    forwarded_ifaces: Vec<String>,
    #[get = "pub with_prefix"]
    address_mangling: u8,
    #[get = "pub with_prefix"]
    dst_pfx: Ipv6Net,
}

const PROXY_FORWARD_STRING: &str = "forward";
const ADDRESS_NETMAP_STRING: &str = "netmap";
const ADDRESS_NPT_STRING: &str = "npt";

// proxy types
#[derive(Debug, std::cmp::PartialEq, Clone, Copy)]
pub enum Proxy {
    Static,
    Forward,
}
// address mangling methods
pub const ADDRESS_NOCHANGE: u8 = 0;
pub const ADDRESS_NETMAP: u8 = 1;
pub const ADDRESS_NPT: u8 = 2;

// TODO: magic number or set it in config file?
pub const TTL_OF_CACHE: Duration = Duration::from_secs(600);
pub const MPSC_CAPACITY: usize = 1;

impl NDConfig {
    pub fn new(name: String, value: config::Value) -> Result<Self, Error> {
        let mut config_table = value.into_table()?;
        /*
         * there must be a field for "type",
         * so that we can decide the way to proxy Neighbor Discoverys
         */
        let proxy_type_string = config_table.remove("type").unwrap().into_string()?;

        let proxy_type = if proxy_type_string == PROXY_FORWARD_STRING {
            Proxy::Forward
        } else {
            Proxy::Static
        };

        /*
         * there must be a field for "proxied_prefix",
         * to inform us which prefix is going to be proxied
         */
        let proxied_pfx: Ipv6Net = config_table
            .remove("proxied_prefix")
            .unwrap()
            .into_string()?
            .parse()?;
        // TODO: is it necessary to check the prefix length and address type?

        /*
         * get the interfaces whose Neighbor Solicitations are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let proxied_ifaces = match config_table.remove("proxied_ifaces") {
            Some(v) => match v.clone().into_array() {
                Ok(if_vec) => if_vec
                    .into_iter()
                    // TODO: at leaset leave some messages here
                    .map(|iface| iface.into_string().unwrap())
                    .collect(),
                Err(_) => vec![v.into_string()?],
            },
            None => vec![String::from("*")],
        };

        /*
         * get the interfaces whose Neighbor Advertisements are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let forwarded_ifaces = match proxy_type {
            Proxy::Static => [].into(),
            Proxy::Forward => match config_table.remove("forwarded_ifaces") {
                Some(v) => match v.clone().into_array() {
                    Ok(if_vec) => if_vec
                        .into_iter()
                        // TODO: at leaset leave some messages here
                        .map(|iface| iface.into_string().unwrap())
                        .collect(),
                    Err(_) => vec![v.into_string()?],
                },
                None => vec![String::from("*")],
            },
        };

        /*
         * extra recipe: rewrite the address
         * let's say your network relies on Network Prefix Translation.
         *
         * For instance:
         *   2001:db8:1::/64                  2001:db8:ffff::/64
         *         ↑                                  ↑
         *        ISP1                               ISP2
         *         |-------- fec1:2:3:4::/64 ---------|
         *
         * Maybe it is suitble for you to specify the Rewrite field like:
         * ```
         * rewrite = "fec1:2:3:4::/64"
         * ```
         */
        let dst_pfx: Ipv6Net;
        let address_mangling: u8;
        match config_table.remove("rewrite_method") {
            Some(v) => {
                let how_to_mangle = v.into_string()?;
                dst_pfx = config_table
                    .remove("local_prefix")
                    .unwrap()
                    .into_string()?
                    .parse()?;
                if how_to_mangle == ADDRESS_NETMAP_STRING {
                    address_mangling = ADDRESS_NETMAP;
                } else if how_to_mangle == ADDRESS_NPT_STRING {
                    address_mangling = ADDRESS_NPT;
                } else {
                    address_mangling = ADDRESS_NOCHANGE;
                }
            }
            None => {
                dst_pfx = proxied_pfx;
                address_mangling = ADDRESS_NOCHANGE;
            }
        }

        Ok(NDConfig {
            name,
            proxy_type,
            proxied_pfx,
            proxied_ifaces,
            forwarded_ifaces,
            address_mangling,
            dst_pfx,
        })
    }
}

/// parse the toml configuration file, returns a vector of NDConfig
///
/// Note that there MUST be a master section called "ndp"
pub fn parse_config(cfile: &str) -> Result<Vec<NDConfig>, Error> {
    let myconfig = config::Config::builder()
        .add_source(config::File::with_name(cfile))
        .build()?;

    // TODO: magic word: ndp
    // is it necessary?
    let mut ret = Vec::new();
    for item in myconfig
        .get_table("ndp")?
        .into_iter()
        .map(|(key, value)| NDConfig::new(key, value))
    {
        ret.push(item?)
    }
    Ok(ret)
}

#[test]
fn test_config_parser() {
    let config1 = parse_config("test/test1.toml").unwrap().pop().unwrap();
    let config2 = parse_config("test/test2.toml").unwrap().pop().unwrap();
    let config3 = parse_config("test/test3.toml").unwrap().pop().unwrap();

    let result1 = NDConfig {
        name: "conf1".to_string(),
        proxy_type: Proxy::Forward,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("*")],
        forwarded_ifaces: vec![String::from("*")],
        address_mangling: ADDRESS_NOCHANGE,
        dst_pfx: "2001:db8::/64".parse().unwrap(),
    };
    let result2 = NDConfig {
        name: "conf2".to_string(),
        proxy_type: Proxy::Forward,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo")],
        forwarded_ifaces: vec![String::from("veth0")],
        address_mangling: ADDRESS_NETMAP,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };
    let result3 = NDConfig {
        name: "conf3".to_string(),
        proxy_type: Proxy::Static,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo"), String::from("eth0")],
        forwarded_ifaces: vec![],
        address_mangling: ADDRESS_NPT,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };

    assert_eq!(config1, result1);
    assert_eq!(config2, result2);
    assert_eq!(config3, result3);
}
