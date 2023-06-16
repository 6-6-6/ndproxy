//#[cfg(target_os = "linux")]
mod linux;
pub use linux::*;

use crate::interfaces;
use crate::error;
use socket2::{Domain, Protocol, Socket, Type};

use std::mem::MaybeUninit;

pub trait PacketReceiverOpts {
    /// bind the socket to a particular interface
    fn bind_to_interface(&self, iface: &interfaces::NDInterface) -> Result<(), error::Error>;
    /// set the socket to receive all of the multicast messages
    fn set_allmulti(&self, iface: &interfaces::NDInterface) -> Result<(), error::Error>;
    /// setup a packet filter (in-kernel) to drop the irrelavant packets
    /// and copy only Neighbor Solicitation packets to userland
    ///
    /// for Unix-like systems, crate classic_bpf is used
    fn set_filter_pass_ipv6_ns(&self) -> Result<(), error::Error>;
    fn set_filter_pass_ipv6_na(&self) -> Result<(), error::Error>;
}

/// wrapper for socket::Socket
pub struct PacketReceiver {
    socket: Socket,
    buf: Vec<MaybeUninit<u8>>,
}

impl PacketReceiver {
    pub fn new() -> Self {
        let socket = Socket::new(Domain::PACKET, Type::DGRAM, Some(Protocol::ICMPV6)).unwrap();
        let buf = vec![MaybeUninit::<u8>::zeroed(); 1500];
        PacketReceiver { socket, buf }
    }
}

impl Iterator for PacketReceiver {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let len = self.socket.recv(&mut self.buf).unwrap();
        Some(
            self.buf[0..len]
                .iter()
                .map(|x| unsafe { x.assume_init() })
                .collect(),
        )
    }
}
