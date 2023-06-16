use std::net::Ipv6Addr;
use std::net::SocketAddrV6;

use crate::error;
use crate::interfaces;
use crate::interfaces::NDInterface;
use crate::packets;
use pnet::packet::Packet;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;

/// construct a NA packet, and send it to the interface
pub async fn send_na_to(
    iface_names: &[String],
    proxied_na_addr: Ipv6Addr,
) -> Result<(), error::Error> {
    //
    let tmp: Vec<NDInterface> = interfaces::get_ifaces_with_name(iface_names)
        .into_values()
        .collect();
    let iface: NDInterface = tmp[0].clone();
    //
    let pkt_sender = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
        Ok(v) => v,
        Err(_) => return Err(error::Error::SocketOpt(0)),
    };

    println!(
        "Send NA for {} to interface {}",
        proxied_na_addr,
        iface.get_name()
    );

    let dst_addr = "ff02::1".parse().unwrap();
    // construct the NA packet
    let na_pkt = packets::generate_NA_forwarded(
        iface.get_link_addr(),
        &dst_addr,
        &proxied_na_addr,
        iface.get_hwaddr(),
        0,
    )
    .unwrap();

    // send the packet via send_to()
    pkt_sender
        .send_to(
            na_pkt.packet(),
            &SocketAddrV6::new(dst_addr, 0, 0, *iface.get_scope_id()).into(),
        )
        .unwrap();

    Ok(())
}
