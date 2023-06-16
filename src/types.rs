use std::{net::Ipv6Addr, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use ttl_cache::TtlCache;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::UnboundedSender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::UnboundedReceiver<SharedNSPacket>;

pub type NeighborsCache = Arc<Mutex<TtlCache<Ipv6Addr, bool>>>;

#[derive(Debug)]
pub enum NDTypes {
    NeighborAdv,
    NeighborSol,
}
