use r_cache::cache::Cache;
use std::{net::Ipv6Addr, sync::Arc};
use tokio::sync::mpsc;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::UnboundedSender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::UnboundedReceiver<SharedNSPacket>;

pub type NeighborsCache = Arc<Cache<Ipv6Addr, bool>>;

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
