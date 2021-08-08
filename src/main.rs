mod conf;
mod datalink;
mod interfaces;
mod nd_proxy;
mod neighbors;
mod ns_monitor;
mod packets;
mod routing;

use crate::ns_monitor::NSMonitor;
use crate::routing::construst_routing_table;
use argparse::{ArgumentParser, Store};
use futures::future::{select, select_all, FutureExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
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

    // parse the config file
    let myconf = conf::parse_config(&config_filename);

    //
    let mut monitored_ifaces = HashMap::new();
    let mut route_map = std::collections::HashMap::new();
    let neighbors = Arc::new(Mutex::new(neighbors::Neighbors::new()));
    // prepare proxies for proxied_prefixes
    let mut ndproxies = Vec::new();
    for conf in myconf.into_iter() {
        // update the monitors interfaces
        let (ifaces, _) = interfaces::get_ifaces_defined_by_config(&conf);
        monitored_ifaces.extend(ifaces);
        //
        let mut proxy = nd_proxy::NDProxy::new(conf, neighbors.clone()).unwrap();
        route_map.insert(
            *proxy.get_proxied_prefix(),
            proxy.mpsc_sender_mut().take().unwrap(),
        );
        ndproxies.push(proxy.run().boxed());
    }

    // prepare monitors for Neighbor Solicitations
    let nsmonitors: Vec<_> = monitored_ifaces
        .into_iter()
        .map(|(_, iface)| NSMonitor::new(construst_routing_table(route_map.clone()), iface))
        .into_iter()
        .map(|inst| spawn_blocking(move || inst.unwrap().run()))
        .collect();

    // because route_map contains mpsc::Sender, I will drop it to make these Senders unavailable
    drop(route_map);
    // drop useless variables
    drop(neighbors);
    // main loop
    select(select_all(ndproxies), select_all(nsmonitors)).await;
    Ok(())
}
