use pnet::packet::Packet;
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborSolicitPacket};
use pnet::packet::icmpv6::{Icmpv6Types, ndp};
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

use crate::error::Error;
use crate::types::*;

/// generate a Neighbor Advertisement packet, necessary information should be provided
#[allow(non_snake_case)]
pub fn generate_NA_forwarded<'a>(
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    proxied_addr: &Ipv6Addr,
    src_hwaddr: &MacAddr,
    flag: u8,
) -> Result<ndp::NeighborAdvertPacket<'a>, Error> {
    let pkt_buf: Vec<u8> = vec![0; 32];
    let mut ret = ndp::MutableNeighborAdvertPacket::owned(pkt_buf)
        .ok_or(Error::PacketGeneration(NDTypes::NeighborAdv))?;
    // basic info
    ret.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
    // set the to-be-announced addr
    ret.set_target_addr(*proxied_addr);
    // force O flag to be 0
    ret.set_flags(flag & 0xdf);
    // NS option: target link local address
    let new_options: Vec<ndp::NdpOption> = vec![ndp::NdpOption {
        option_type: ndp::NdpOptionTypes::TargetLLAddr,
        length: 1,
        data: src_hwaddr.octets().to_vec(),
    }];
    ret.set_options(&new_options);
    // icmpv6 cehcksum
    let csum = pnet::util::ipv6_checksum(
        ret.packet(),
        1,
        &[],
        src_addr,
        dst_addr,
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
    );
    ret.set_checksum(csum);

    Ok(ret.consume_to_immutable())
}

/// taking over the process of Neighbor Discovery myself
///
/// src_addr: my src addr
/// src_addr: the dst addr (could be multicast addr or the solicited_addr)
/// solicited_addr: the addr I am soliciting
/// src_hwaddr: the hwaddr of the interface
#[allow(non_snake_case)]
pub fn generate_NS_packet<'a>(
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    solicited_addr: &Ipv6Addr,
    src_hwaddr: Option<&MacAddr>,
) -> Result<NeighborSolicitPacket<'a>, Error> {
    let pkt_buf: Vec<u8> = match src_hwaddr {
        Some(_) => vec![0; 32],
        None => vec![0; 24],
    };
    let mut ret = MutableNeighborSolicitPacket::owned(pkt_buf)
        .ok_or(Error::PacketGeneration(NDTypes::NeighborSol))?;
    // update the option field if needed
    ret.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    // set the to-be-announced addr
    ret.set_target_addr(*solicited_addr);
    // NS option: target link local address
    if let Some(my_hwaddr) = src_hwaddr {
        let new_options: Vec<ndp::NdpOption> = vec![ndp::NdpOption {
            option_type: ndp::NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: my_hwaddr.octets().to_vec(),
        }];
        ret.set_options(&new_options);
    }
    // icmpv6 cehcksum
    let csum = pnet::util::ipv6_checksum(
        ret.packet(),
        1,
        &[],
        src_addr,
        dst_addr,
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
    );
    ret.set_checksum(csum);

    Ok(ret.consume_to_immutable())
}

//TODO: tests
