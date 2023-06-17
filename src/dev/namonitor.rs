use crate::conf::TTL_OF_CACHE;
use crate::error::Error;
use crate::interfaces::{self, NDInterface};
use crate::na_monitor::NAMonitor;
use r_cache::cache::Cache;
use std::sync::Arc;

pub fn namonitor(iface_names: &[String]) -> Result<(), Error> {
    //
    let tmp: Vec<NDInterface> = interfaces::get_ifaces_with_name(iface_names)
        .into_values()
        .collect();
    let iface: NDInterface = tmp[0].clone();
    //
    let neighbors_cache = Arc::new(Cache::new(Some(TTL_OF_CACHE)));
    //
    NAMonitor::new(iface, neighbors_cache)?.run()
}
