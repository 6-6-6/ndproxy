use ipnet::Ipv6Net;
use std::collections::HashMap;

#[derive(getset::Getters, Debug, std::cmp::PartialEq, Clone)]
pub struct NDConfig {
    #[get = "pub with_prefix"]
    name: String,
    #[get = "pub with_prefix"]
    proxy_type: u8,
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
pub const PROXY_STATIC: u8 = 0;
pub const PROXY_FORWARD: u8 = 1;
// address mangling methods
pub const ADDRESS_NOCHANGE: u8 = 0;
pub const ADDRESS_NETMAP: u8 = 1;
pub const ADDRESS_NPT: u8 = 2;

impl NDConfig {
    pub fn new(name: String, mut config_table: HashMap<String, config::Value>) -> Self {
        /*
         * there must be a field for "type",
         * so that we can decide the way to proxy Neighbor Discoverys
         */
        let proxy_type_string = config_table.remove("type").unwrap().into_str().unwrap();

        let proxy_type: u8;
        if proxy_type_string == PROXY_FORWARD_STRING {
            proxy_type = PROXY_FORWARD;
        } else {
            proxy_type = PROXY_STATIC;
        }

        /*
         * there must be a field for "proxied_prefix",
         * to inform us which prefix is going to be proxied
         */
        let proxied_pfx: Ipv6Net = config_table
            .remove("proxied_prefix")
            .unwrap()
            .into_str()
            .unwrap()
            .parse()
            .unwrap();
        // TODO: is it necessary to check the prefix length and address type?

        /*
         * get the interfaces whose Neighbor Solicitations are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let proxied_ifaces = match config_table.remove("proxied_ifaces") {
            Some(v) => match v.clone().into_array() {
                Ok(if_vec) => if_vec
                    .into_iter()
                    .map(|iface| iface.into_str().unwrap())
                    .collect(),
                Err(_) => vec![v.into_str().unwrap()],
            },
            None => vec![String::from("*")],
        };

        /*
         * get the interfaces whose Neighbor Advertisements are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let forwarded_ifaces = match config_table.remove("forwarded_ifaces") {
            Some(v) => match v.clone().into_array() {
                Ok(if_vec) => if_vec
                    .into_iter()
                    .map(|iface| iface.into_str().unwrap())
                    .collect(),
                Err(_) => vec![v.into_str().unwrap()],
            },
            None => vec![String::from("*")],
        };

        /*
         * extra recipe: rewrite the address
         * let's say your network relies on Network Prefix Translation.
         *
         * For instance:
         *   2001:db8:1::/64                  2001:db8:ffff::/64
         *         ???                                  ???
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
                let how_to_mangle = v.into_str().unwrap();
                dst_pfx = config_table
                    .remove("local_prefix")
                    .unwrap()
                    .into_str()
                    .unwrap()
                    .parse()
                    .unwrap();
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

        NDConfig {
            name,
            proxy_type,
            proxied_pfx,
            proxied_ifaces,
            forwarded_ifaces,
            address_mangling,
            dst_pfx,
        }
    }
}

/// parse the toml configuration file, returns a vector of NDConfig
///
/// Note that there MUST be a master section called "ndp"
pub fn parse_config(cfile: &str) -> Vec<NDConfig> {
    let mut myconfig = config::Config::new();

    myconfig.merge(config::File::with_name(cfile)).unwrap();

    // TODO: magic word: ndp
    // is it necessary?
    myconfig
        .get_table("ndp")
        .unwrap()
        .into_iter()
        .map(|(key, value)| NDConfig::new(key, value.into_table().unwrap()))
        .collect()
}

#[test]
fn test_config_parser() {
    let config1 = parse_config("test/test1.toml").pop().unwrap();
    let config2 = parse_config("test/test2.toml").pop().unwrap();
    let config3 = parse_config("test/test3.toml").pop().unwrap();

    let result1 = NDConfig {
        name: "conf1".to_string(),
        proxy_type: 1,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("*")],
        forwarded_ifaces: vec![String::from("*")],
        address_mangling: ADDRESS_NOCHANGE,
        dst_pfx: "2001:db8::/64".parse().unwrap(),
    };
    let result2 = NDConfig {
        name: "conf2".to_string(),
        proxy_type: 0,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo")],
        forwarded_ifaces: vec![String::from("veth0")],
        address_mangling: ADDRESS_NETMAP,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };
    let result3 = NDConfig {
        name: "conf3".to_string(),
        proxy_type: 0,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo"), String::from("eth0")],
        forwarded_ifaces: vec![String::from("veth0")],
        address_mangling: ADDRESS_NPT,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };

    assert_eq!(config1, result1);
    assert_eq!(config2, result2);
    assert_eq!(config3, result3);
}
