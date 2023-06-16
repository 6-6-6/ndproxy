use crate::types::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ipnet parse error")]
    IPNet(#[from] ipnet::AddrParseError),
    #[error("config error")]
    Config(#[from] config::ConfigError),
    #[error("std io errors")]
    Io(()),
    #[error("socketopt error")]
    SocketOpt(i32),
    #[error("NA/NS packet generation error")]
    PacketGeneration(NDTypes),
}
