//#[cfg(target_os = "linux")]
mod linux;
pub use linux::*;

use crate::error::Error;
use crate::interfaces;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

use std::mem::MaybeUninit;

pub trait PacketReceiverOpts {
    /// bind the socket to a particular interface
    fn bind_to_interface(&self, iface: &interfaces::NDInterface) -> Result<(), Error>;
    /// set the socket to receive all of the multicast messages
    fn set_allmulti(&self, iface: &interfaces::NDInterface) -> Result<(), Error>;
    /// setup a packet filter (in-kernel) to drop the irrelavant packets
    /// and copy only Neighbor Solicitation packets to userland
    ///
    /// for Unix-like systems, crate classic_bpf is used
    fn set_filter_pass_ipv6_ns(&self) -> Result<(), Error>;
    fn set_filter_pass_ipv6_na(&self) -> Result<(), Error>;
}

/// TODO: async it
/// wrapper for socket::Socket
pub struct PacketReceiver {
    socket: AsyncFd<Socket>,
    buf: Vec<MaybeUninit<u8>>,
}

impl PacketReceiver {
    pub fn new() -> Result<Self, Error> {
        let socket = AsyncFd::new(Socket::new(
            Domain::PACKET,
            Type::DGRAM,
            Some(Protocol::ICMPV6),
        )?)?;
        let buf = vec![MaybeUninit::<u8>::zeroed(); 1500];
        Ok(PacketReceiver { socket, buf })
    }
}

impl PacketReceiver {
    pub async fn recv_pkt(&mut self) -> Result<Vec<u8>, Error> {
        let len = self
            .socket
            .readable()
            .await?
            .try_io(|socket| socket.get_ref().recv(&mut self.buf))
            .map_err(Error::TokioTryIo)??;
        Ok(self.buf[0..len]
            .iter()
            .map(|x| unsafe { x.assume_init() })
            .collect())
    }
}
