mod address;
mod conf;
mod interfaces;
mod neighors;
mod packets;
mod proxy;

use argparse::{ArgumentParser, Store};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let mut config_filename = String::from("./ndproxy.toml");

    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("proxies your neighbor discovery messages.");
        ap.refer(&mut config_filename)
            .add_option(&["-c", "--conf"], Store,
            "The location of your config file. Default: ./noproxy.toml");
        ap.parse_args_or_exit();
    }

    let myconf = conf::parse_config(&config_filename);
    // TODO: support multiple sections
    let myndproxy = proxy::NeighborDiscoveryProxyItem::new(myconf[0].clone());
    myndproxy.run()
}
