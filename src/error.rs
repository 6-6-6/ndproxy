use crate::types::*;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ipnet parse error")]
    IPNet(#[from] ipnet::AddrParseError),
    #[error("config error")]
    Config(#[from] config::ConfigError),
    #[error("tokio mpsc send error")]
    Mpsc(#[from] tokio::sync::mpsc::error::SendError<SharedNSPacket>),
    #[error("tokio mpsc recv error")]
    MpscRecvNone(),
    #[error("std io errors")]
    Io(#[from] std::io::Error),
    #[error("socketopt error")]
    SocketOpt(SocketOptTypes),
    #[error("NA/NS packet generation error")]
    PacketGeneration(NDTypes),
    #[error("tokio join error")]
    JoinError(#[from] JoinError),
    #[error("Neighbors Cache: Cache item does not exist.")]
    NeighborsCacheError(),
}
