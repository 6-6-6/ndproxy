use std::net::Ipv6Addr;
use tokio::sync::mpsc;

pub type SharedNSPacket = (u32, Box<Ipv6Addr>, Box<Vec<u8>>);
pub type SharedNSPacketSender = mpsc::UnboundedSender<SharedNSPacket>;
pub type SharedNSPacketReceiver = mpsc::UnboundedReceiver<SharedNSPacket>;