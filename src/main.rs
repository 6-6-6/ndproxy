mod conf; // config file
mod datalink; // about sending and receiving pkts
mod error; // error types
mod interfaces; // find interface by name / config
mod na_monitor; // monitoring NA pkts
mod nd_proxy; // main process?
mod ns_monitor; // monitoring NS pkts
mod packets; // about encoding/decoding pkts
mod routing; // a _route_ table
mod types; // self-defined types

use crate::na_monitor::NAMonitor;
use crate::ns_monitor::NSMonitor;
use crate::routing::construst_routing_table;
use conf::TTL_OF_CACHE;
use futures::FutureExt;
use futures::future::select_all;
use r_cache::cache::Cache;
use std::collections::HashMap;
use std::sync::Arc;

use clap::Parser;

#[cfg(not(feature = "dev"))]
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// path to config file
    #[arg(short, long, default_value = "/etc/ndproxy.toml")]
    config: String,
}

#[cfg(not(feature = "dev"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), error::Error> {
    pretty_env_logger::init();
    let args = Args::parse();
    ndproxy_main(args.config).await
}

#[cfg(feature = "dev")]
mod dev;
#[cfg(feature = "dev")]
use clap::Subcommand;

#[cfg(feature = "dev")]
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
    ///
    #[command(subcommand)]
    command: Option<Commands>,
}

#[cfg(feature = "dev")]
#[derive(Subcommand, Debug)]
enum Commands {
    Nsmonitor,
    Namonitor,
    Nssender,
    Nasender,
}

#[cfg(feature = "dev")]
#[tokio::main(flavor = "current_thread")]
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
    let neighbors_cache = Arc::new(Cache::new(Some(TTL_OF_CACHE)));

    // prepare proxies for proxied_prefixes
    let mut tasks = Vec::new();

    for conf in myconf.into_iter() {
        // update the monitors interfaces (by config)
        let (upstream_ifaces, downstream_ifaces) = interfaces::get_ifaces_defined_by_config(&conf);
        monitored_ns_ifaces.extend(upstream_ifaces);
        monitored_na_ifaces.extend(downstream_ifaces);
        //
        let mut ndproxy = nd_proxy::NDProxy::new(conf, neighbors_cache.clone())?;
        // route prefix to its corresponding ndproxy
        route_map.insert(
            *ndproxy.get_proxied_prefix(),
            ndproxy.get_mpsc_sender_mut().take().unwrap_or_else(|| {
                panic!(
                    "cannot take mpsc sender from ndproxy of {}",
                    ndproxy.get_proxied_prefix()
                )
            }),
        );
        tasks.push(ndproxy.run().boxed());
    }

    // prepare monitors for Neighbor Solicitations
    for nsmonitor in monitored_ns_ifaces
        .into_values()
        .map(|iface| NSMonitor::new(construst_routing_table(route_map.clone()), iface))
    {
        tasks.push(nsmonitor?.run().boxed())
    }

    // prepare monitors for Neighbor Advertisements
    for namonitor in monitored_na_ifaces
        .into_values()
        .map(|iface| NAMonitor::new(iface, neighbors_cache.clone()))
    {
        tasks.push(namonitor?.run().boxed())
    }

    // because route_map contains mpsc::Sender, I will drop it to make these Senders unavailable
    drop(route_map);
    // drop unused Arc
    drop(neighbors_cache);

    // main loop, if any task failed, return the Result and exit?
    select_all(tasks).await.0
}
