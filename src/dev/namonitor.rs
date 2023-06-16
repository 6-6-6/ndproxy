use crate::error;
use crate::interfaces::{self, NDInterface};
use crate::na_monitor::NAMonitor;
use std::sync::Arc;
use tokio::sync::Mutex;
use ttl_cache::TtlCache;

pub async fn namonitor(iface_names: &[String]) -> Result<(), error::Error> {
    //
    let tmp: Vec<NDInterface> = interfaces::get_ifaces_with_name(iface_names)
        .into_values()
        .collect();
    let iface: NDInterface = tmp[0].clone();
    //
    let neighbors_cache = Arc::new(Mutex::new(TtlCache::new(256)));
    //
    NAMonitor::new(iface, neighbors_cache)?.run().await
}
