mod conf;
mod datalink;
mod dev;
mod error;
mod interfaces;
mod na_monitor;
mod nd_proxy;
mod ns_monitor;
mod packets;
mod routing;
mod types;

use crate::na_monitor::NAMonitor;
use crate::ns_monitor::NSMonitor;
use crate::routing::construst_routing_table;
use futures::future::{select_all, FutureExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use ttl_cache::TtlCache;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// path to config file
    #[arg(short, long, default_value = "/etc/ndproxy.toml")]
    config: String,
    ///
    #[arg(long)]
    monitor_this_interface: Option<String>,
    ///
    #[arg(long)]
    send_pkt_to_this_interface: Option<String>,
    ///
    #[arg(long)]
    send_pkt_for_this_addr: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Nsmonitor,
    Namonitor,
    Nssender,
    Nasender,
}

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    pretty_env_logger::init();

    let args = Args::parse();

    match &args.command {
        Some(Commands::Namonitor) => dev::namonitor(&[args.monitor_this_interface.unwrap()]).await,
        Some(Commands::Nsmonitor) => dev::nsmonitor(&[args.monitor_this_interface.unwrap()]).await,
        Some(Commands::Nssender) => {
            dev::send_ns_to(
                &[args.send_pkt_to_this_interface.unwrap()],
                args.send_pkt_for_this_addr.unwrap().parse().unwrap(),
            )
            .await
        }
        Some(Commands::Nasender) => {
            dev::send_na_to(
                &[args.send_pkt_to_this_interface.unwrap()],
                args.send_pkt_for_this_addr.unwrap().parse().unwrap(),
            )
            .await
        }
        None => ndproxy_main(args.config).await,
    }
}

async fn ndproxy_main(config_filename: String) -> Result<(), error::Error> {
    // parse the config file
    let myconf = conf::parse_config(&config_filename)?;

    //
    let mut monitored_ns_ifaces = HashMap::new();
    let mut monitored_na_ifaces = HashMap::new();
    let mut route_map = std::collections::HashMap::new();
    let neighbors_cache = Arc::new(Mutex::new(TtlCache::new(256)));

    // prepare proxies for proxied_prefixes
    let mut ndproxies = Vec::new();
    for conf in myconf.into_iter() {
        // update the monitors interfaces
        let (upstream_ifaces, downstream_ifaces) = interfaces::get_ifaces_defined_by_config(&conf);
        monitored_ns_ifaces.extend(upstream_ifaces);
        monitored_na_ifaces.extend(downstream_ifaces);
        //
        let mut proxy = nd_proxy::NDProxy::new(conf, neighbors_cache.clone()).unwrap();
        route_map.insert(
            *proxy.get_proxied_prefix(),
            proxy.mpsc_sender_mut().take().unwrap(),
        );
        ndproxies.push(proxy.run().boxed());
    }

    // prepare monitors for Neighbor Solicitations
    let nsmonitors: Vec<_> = monitored_ns_ifaces
        .into_values()
        .map(|iface| NSMonitor::new(construst_routing_table(route_map.clone()), iface))
        .into_iter()
        .map(|inst| spawn_blocking(move || inst.unwrap().run()))
        .collect();

    // prepare monitors for Neighbor Advertisements
    let namonitors: Vec<_> = monitored_na_ifaces
        .into_values()
        .map(|iface| NAMonitor::new(iface, neighbors_cache.clone()))
        .into_iter()
        .map(|inst| spawn_blocking(move || async { inst.unwrap().run().await }))
        .collect();

    // because route_map contains mpsc::Sender, I will drop it to make these Senders unavailable
    drop(route_map);
    // drop not using Arcs
    drop(neighbors_cache);

    // main loop
    let _a = tokio::join!(
        select_all(ndproxies),
        select_all(namonitors),
        select_all(nsmonitors)
    );
    Ok(())
}
