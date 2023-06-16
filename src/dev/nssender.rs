use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

use crate::error::Error;
use crate::interfaces;
use crate::interfaces::NDInterface;
use crate::packets;
use crate::types::SocketOptTypes;
use pnet::packet::icmpv6::ndp::MutableNeighborSolicitPacket;
use pnet::packet::Packet;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;

/// construct a NS packet, and send it to the interface
pub async fn send_ns_to(iface_names: &[String], ns_addr: Ipv6Addr) -> Result<(), Error> {
    //
    let tmp: Vec<NDInterface> = interfaces::get_ifaces_with_name(iface_names)
        .into_values()
        .collect();
    let iface: NDInterface = tmp[0].clone();
    //
    let pkt_sender = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
        Ok(v) => v,
        Err(_) => return Err(Error::SocketOpt(SocketOptTypes::SocketGeneration)),
    };

    println!("Send NS for {} to interface {}", ns_addr, iface.get_name());

    let pkt_buf: Vec<u8> = vec![0; 1024];
    let pseudo_pkt = MutableNeighborSolicitPacket::owned(pkt_buf)
        .unwrap()
        .consume_to_immutable();
    // construct the NA packet
    let na_pkt = packets::generate_NS_packet(
        &pseudo_pkt,
        iface.get_link_addr(),
        &Ipv6Addr::UNSPECIFIED,
        &ns_addr,
        Some(iface.get_hwaddr()),
    )
    .unwrap();
    // send the packet via send_to()
    pkt_sender
        .send_to(
            na_pkt.packet(),
            &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, *iface.get_scope_id()).into(),
        )
        .unwrap();

    let pkt_buf: Vec<u8> = vec![0; 1024];
    let pseudo_pkt = MutableNeighborSolicitPacket::owned(pkt_buf)
        .unwrap()
        .consume_to_immutable();
    // construct the NA packet
    let na_pkt = packets::generate_NS_packet(
        &pseudo_pkt,
        iface.get_link_addr(),
        &ns_addr,
        &ns_addr,
        Some(iface.get_hwaddr()),
    )
    .unwrap();
    // send the packet via send_to()
    pkt_sender
        .send_to(
            na_pkt.packet(),
            &SocketAddrV6::new(ns_addr, 0, 0, *iface.get_scope_id()).into(),
        )
        .unwrap();

    Ok(())
}
