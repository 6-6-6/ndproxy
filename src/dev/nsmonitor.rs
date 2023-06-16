use crate::dev::recv_handler::mpsc_recv_and_drop;
use crate::error::Error;
use crate::interfaces;
use crate::ns_monitor::NSMonitor;
use crate::routing::construst_routing_table;
use futures::future::{select, select_all, FutureExt};
use ipnet::Ipv6Net;
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;

pub async fn nsmonitor(iface_names: &[String]) -> Result<(), Error> {
    //
    let mut route_map = std::collections::HashMap::new();
    let monitored_ifaces = interfaces::get_ifaces_with_name(iface_names);
    let (mpsc_sender, mpsc_receiver) = mpsc::unbounded_channel();

    let net: Ipv6Net = "::/0".parse().unwrap();
    route_map.insert(net, mpsc_sender);

    // prepare monitors for Neighbor Solicitations
    let nsmonitors: Vec<_> = monitored_ifaces
        .into_values()
        .map(|iface| NSMonitor::new(construst_routing_table(route_map.clone()), iface))
        .into_iter()
        .map(|inst| spawn_blocking(move || inst.unwrap().run()))
        .collect();

    // because route_map contains mpsc::Sender, I will drop it to make these Senders unavailable
    drop(route_map);
    // main loop
    select(
        mpsc_recv_and_drop(mpsc_receiver).boxed(),
        select_all(nsmonitors),
    )
    .await;
    Ok(())
}
