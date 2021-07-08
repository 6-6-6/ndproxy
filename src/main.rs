
//extern crate pnet;
//extern crate tokio;

mod conf;
mod packets;
mod interfaces;
mod neighors;
mod proxy;
mod address;

#[tokio::main]
async fn main() -> Result<(),()> {
    println!("Hello, world!");
    println!("{:?}", conf::parse_config("test.toml"));
    let myconf = conf::parse_config("test2.toml");
    let myndproxy = proxy::NeighborDiscoveryProxyItem::new(myconf[0].clone());
    myndproxy.monitor_NS(0);

    Ok(())
}


