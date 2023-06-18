//#[cfg(target_os = "linux")]
mod linux;
pub use linux::*;

use crate::error::Error;
use crate::interfaces;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
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

pub struct PacketReceiver {
    socket: AsyncFd<Socket>,
    buf: Vec<MaybeUninit<u8>>,
}

impl PacketReceiver {
    pub fn new() -> Result<Self, Error> {
        let inner = Socket::new(Domain::PACKET, Type::DGRAM, Some(Protocol::ICMPV6))?;
        inner.set_nonblocking(true)?;
        let buf = vec![MaybeUninit::<u8>::zeroed(); 1500];
        Ok(Self {
            socket: AsyncFd::new(inner)?,
            buf,
        })
    }
}

impl PacketReceiver {
    pub async fn recv_pkt(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            match self
                .socket
                .readable()
                .await?
                .try_io(|socket| socket.get_ref().recv(&mut self.buf))
            {
                Ok(len) => {
                    return Ok(self.buf[0..len?]
                        .iter()
                        .map(|x| unsafe { x.assume_init() })
                        .collect())
                }
                Err(_) => continue,
            }
        }
    }
}

pub trait PacketSenderOpts {
    fn set_multicast_hops_v6(&self, hops: u32) -> Result<(), Error>;
    fn set_unicast_hops_v6(&self, hops: u32) -> Result<(), Error>;
}

/// TODO: async it
/// wrapper for socket::Socket
pub struct PacketSender {
    socket: AsyncFd<Socket>,
}

impl PacketSender {
    pub fn new() -> Result<Self, Error> {
        let inner = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        inner.set_nonblocking(true)?;
        Ok(Self {
            socket: AsyncFd::new(inner)?,
        })
    }
}

impl PacketSender {
    pub async fn send_pkt_to(&self, pkt: &[u8], addr: &SockAddr) -> Result<usize, Error> {
        loop {
            match self
                .socket
                .writable()
                .await?
                .try_io(|socket| socket.get_ref().send_to(pkt, addr))
            {
                Ok(len) => return len.map_err(Error::Io),
                Err(_) => continue,
            }
        }
    }
}
