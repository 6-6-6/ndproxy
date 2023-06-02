use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ipnet parse error")]
    IPNet(#[from] ipnet::AddrParseError),
    #[error("config error")]
    Config(#[from] config::ConfigError),
}
