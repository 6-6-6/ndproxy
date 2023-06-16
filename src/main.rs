mod conf;
mod datalink;
mod error;
mod interfaces;
mod nd_proxy;
mod neighbors;
mod ns_monitor;
mod packets;
mod routing;
mod dev;

use crate::ns_monitor::NSMonitor;
use crate::routing::construst_routing_table;
use futures::future::{select, select_all, FutureExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

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
}


#[tokio::main]
async fn main() -> Result<(), error::Error> {
    pretty_env_logger::init();

    let args = Args::parse();


    match &args.command {
        Some(Commands::Namonitor) => {
            dev::NAMonitor::new(&[args.monitor_this_interface.unwrap()]).unwrap().run()
        }
        Some(Commands::Nsmonitor) => {
            dev::nsmonitor(&[args.monitor_this_interface.unwrap()]).await
        }
        Some(Commands::Nssender) => {
            dev::send_ns_to(&[args.send_pkt_to_this_interface.unwrap()], args.send_pkt_for_this_addr.unwrap().parse().unwrap()).await
        }
        None => {
            ndproxy_main(args.config).await
        }
    }

}

async fn ndproxy_main(config_filename: String) -> Result<(), error::Error> {

    // parse the config file
    let myconf = conf::parse_config(&config_filename)?;

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
    let nsmonitors: Vec<_> = monitored_ifaces.into_values().map(|iface| NSMonitor::new(construst_routing_table(route_map.clone()), iface))
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
