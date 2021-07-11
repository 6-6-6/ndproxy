
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
    println!("{:?}", conf::parse_config("test2.toml"));
    let myconf = conf::parse_config("test2.toml");
    let myndproxy = proxy::NeighborDiscoveryProxyItem::new(myconf[0].clone());
    myndproxy.run();

    let mut myfilter = packets::ICMP6Filter::new(0xffffffff);
    myfilter.set_pass(136);
    println!("{:?}", myfilter);

    Ok(())
}


