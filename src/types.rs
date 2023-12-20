use r_cache::cache::Cache;
use std::{net::Ipv6Addr, sync::Arc};
use tokio::sync::mpsc;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::Sender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::Receiver<SharedNSPacket>;

/// caches the result of neighbour discovery
/// u32 is the scope id of the object
pub type NeighborsCache = Arc<Cache<(u32, Ipv6Addr), ()>>;

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

// proxy types
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Proxy {
    Static,
    Forward,
}

// address mangling methods
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddressMangling {
    Nochange,
    Netmap,
    Npt,
}

#[test]
fn test_my_enums() {
    assert!(AddressMangling::Netmap == AddressMangling::Netmap);
    assert!(AddressMangling::Netmap != AddressMangling::Nochange);
    assert!(AddressMangling::Netmap != AddressMangling::Npt);

    assert!(Proxy::Static == Proxy::Static);
    assert!(Proxy::Static != Proxy::Forward);
}
