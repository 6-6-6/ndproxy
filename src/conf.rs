use ipnet::Ipv6Net;
use std::collections::HashMap;

#[derive(getset::Getters, Debug, std::cmp::PartialEq, Clone)]
pub struct NDConfig {
    #[get = "pub with_prefix"]
    proxy_type: u8,
    #[get = "pub with_prefix"]
    proxied_pfx: Ipv6Net,
    #[get = "pub with_prefix"]
    proxied_ifaces: Vec<String>,
    #[get = "pub with_prefix"]
    forwarded_ifaces: Vec<String>,
    #[get = "pub with_prefix"]
    rewrite: bool,
    #[get = "pub with_prefix"]
    dst_pfx: Ipv6Net,
}

const PROXY_FORWARD: &str = "forward";

impl NDConfig {
    pub fn new(config_table: HashMap<String, config::Value>) -> Self {
        /*
         * there must be a field for "type",
         * so that we can decide the way to proxy Neighbor Discoverys
         */
        let proxy_type_string = config_table
            .get("type")
            .unwrap()
            .clone()
            .into_str()
            .unwrap();

        let proxy_type: u8;
        if proxy_type_string == PROXY_FORWARD {
            proxy_type = 1;
        } else {
            proxy_type = 0;
        }

        /*
         * there must be a field for "proxied_prefix",
         * to inform us which prefix is going to be proxied
         */
        let proxied_pfx: Ipv6Net = config_table
            .get("proxied_prefix")
            .unwrap()
            .clone()
            .into_str()
            .unwrap()
            .parse()
            .unwrap();
        // TODO: is it necessary to check the prefix length and address type?

        /*
         * get the interfaces whose Neighbor Solicitations are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let proxied_ifaces = match config_table.get("proxied_ifaces") {
            Some(v) => {
                let mut ifaces = Vec::new();
                match v.clone().into_array() {
                    Ok(if_vec) => {
                        for iface in if_vec.iter() {
                            ifaces.push(iface.clone().into_str().unwrap());
                        }
                    }
                    Err(_) => ifaces.push(v.clone().into_str().unwrap()),
                }
                ifaces
            }
            None => vec![String::from("*")],
        };

        /*
         * get the interfaces whose Neighbor Advertisements are proxied by me
         * if it is not specified, I will listen on all of the interfaces
         */
        let forwarded_ifaces = match config_table.get("forwarded_ifaces") {
            Some(v) => {
                let mut ifaces = Vec::new();
                match v.clone().into_array() {
                    Ok(if_vec) => {
                        for iface in if_vec.iter() {
                            ifaces.push(iface.clone().into_str().unwrap());
                        }
                    }
                    Err(_) => ifaces.push(v.clone().into_str().unwrap()),
                }
                ifaces
            }
            None => vec![String::from("*")],
        };

        /*
         * extra recipe: rewrite the address
         * let's say your network relys on Network Prefix Translation.
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
        let rewrite: bool;
        match config_table.get("rewrite") {
            Some(v) => {
                dst_pfx = v.clone().into_str().unwrap().parse().unwrap();
                rewrite = true;
            }
            None => {
                dst_pfx = proxied_pfx;
                rewrite = false;
            }
        }

        NDConfig {
            proxy_type,
            proxied_pfx,
            proxied_ifaces,
            forwarded_ifaces,
            rewrite,
            dst_pfx,
        }
    }
}

/*
 * parse the toml configuration file, returns a vector of NDConfig
 *
 * Note that there MUST be a master section called "ndp"
 */
pub fn parse_config(cfile: &str) -> Vec<NDConfig> {
    let mut ret = Vec::new();
    let mut myconfig = config::Config::new();

    myconfig.merge(config::File::with_name(cfile)).unwrap();

    // magic word: ndp
    for value in myconfig.get_table("ndp").unwrap().values() {
        ret.push(NDConfig::new(value.clone().into_table().unwrap()));
    }
    ret
}

#[test]
fn test_config_parser() {
    let config1 = parse_config("test/test1.toml").pop().unwrap();
    let config2 = parse_config("test/test2.toml").pop().unwrap();
    let config3 = parse_config("test/test3.toml").pop().unwrap();

    let result1 = NDConfig {
        proxy_type: 1,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("*")],
        forwarded_ifaces: vec![String::from("*")],
        rewrite: false,
        dst_pfx: "2001:db8::/64".parse().unwrap(),
    };
    let result2 = NDConfig {
        proxy_type: 0,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo")],
        forwarded_ifaces: vec![String::from("veth0")],
        rewrite: true,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };
    let result3 = NDConfig {
        proxy_type: 0,
        proxied_pfx: "2001:db8::/64".parse().unwrap(),
        proxied_ifaces: vec![String::from("lo"), String::from("eth0")],
        forwarded_ifaces: vec![String::from("veth0")],
        rewrite: true,
        dst_pfx: "2001:db9::/64".parse().unwrap(),
    };

    assert_eq!(config1, result1);
    assert_eq!(config2, result2);
    assert_eq!(config3, result3);
}
