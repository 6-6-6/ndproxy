use crate::types::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ipnet parse error")]
    IPNet(#[from] ipnet::AddrParseError),
    #[error("config error")]
    Config(#[from] config::ConfigError),
    #[error("tokio mpsc error")]
    Mpsc(#[from] tokio::sync::mpsc::error::SendError<SharedNSPacket>),
    #[error("std io errors")]
    Io(#[from] std::io::Error),
    #[error("socketopt error")]
    SocketOpt(SocketOptTypes),
    #[error("NA/NS packet generation error")]
    PacketGeneration(NDTypes),
}
