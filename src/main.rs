mod conf;
mod datalink;
mod interfaces;
mod nd_proxy;
mod neighbors;
mod ns_monitor;
mod packets;
mod routing;

use argparse::{ArgumentParser, Store};
use futures::select;
use futures::stream::FuturesUnordered;
use tokio::task::spawn_blocking;

#[tokio::main]
async fn main() -> Result<(), ()> {
    pretty_env_logger::init();

    let mut config_filename = String::from("./ndproxy.toml");
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("proxies your neighbor discovery messages.");
        ap.refer(&mut config_filename).add_option(
            &["-c", "--conf"],
            Store,
            "The location of your config file. Default: ./npproxy.toml",
        );
        ap.parse_args_or_exit();
    }

    // terminate the program if any thread get panicked
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic(info);
        std::process::exit(1);
    }));

    let myconf = conf::parse_config(&config_filename);
    //
    let ndproxiers = FuturesUnordered::new();
    //
    let mut route_map = std::collections::HashMap::new();
    //
    let (iface1, _iface2) = interfaces::get_ifaces_defined_by_config(&myconf[0]);
    for conf in myconf.into_iter() {
        let mut proxifier = nd_proxy::NDProxier::new(conf).unwrap();
        route_map.insert(
            *proxifier.get_proxied_prefix(),
            proxifier.mpsc_sender_mut().take().unwrap(),
        );
        ndproxiers.push(proxifier.run());
    }
    //
    let nsmonitors = FuturesUnordered::new();
    for (_u, ifs) in iface1 {
        let nsm =
            ns_monitor::NSMonitor::new(routing::construst_route_table(route_map.clone()), ifs)
                .unwrap();
        nsmonitors.push(spawn_blocking(move || nsm.run()));
    }
    // because route_map contains mpsc::Sender, I will drop it to make these Senders unavailable
    drop(route_map);
    // main loop
    select! {
        default => Err(()),
        complete => Ok(()),
    }
}
