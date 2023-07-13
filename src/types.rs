use dashmap::DashMap;
use r_cache::cache::Cache;
use std::{net::Ipv6Addr, sync::Arc};
use tokio::sync::mpsc;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::Sender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::Receiver<SharedNSPacket>;

/// caches the result of neighbour discovery
/// u32 is the scope id of the object
pub type NeighborSource = Cache<u32, ()>;
pub type NeighborsCache = Arc<DashMap<Ipv6Addr, NeighborSource>>;

#[derive(Debug)]
pub enum NDTypes {
    NeighborAdv,
    NeighborSol,
}

#[derive(Debug)]
pub enum SocketOptTypes {
    AllMulti,
    AttachBPF,
    BindToIface,
    SetMultiHop,
    SetUniHop,
    #[cfg(feature = "dev")]
    SocketGeneration,
}
