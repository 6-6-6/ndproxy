use pnet::packet::icmpv6::{ndp, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::{Packet, PacketSize};
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

/// generate a Neighbor Advertisement packet, necessary information should be provided
#[allow(non_snake_case)]
pub fn generate_NA_forwarded<'a>(
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    proxied_addr: &Ipv6Addr,
    src_hwaddr: &MacAddr,
    flag: u8,
) -> Option<ndp::NeighborAdvertPacket<'a>> {
    let pkt_buf: Vec<u8> = vec![0; 32];
    let mut ret = match ndp::MutableNeighborAdvertPacket::owned(pkt_buf) {
        Some(v) => v,
        None => return None,
    };
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

    Some(ret.consume_to_immutable())
}

/// Instead of taking over the process of Neighbor Discovery myself,
/// I decided to form an Icmpv6 Echo Request packet,
/// and let the OS complete the Neighbor Discovery process.
#[allow(non_snake_case)]
pub fn generate_NS_trick<'a, 'b>(
    original_packet: &ndp::NeighborSolicitPacket<'a>,
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
) -> Option<Icmpv6Packet<'b>> {
    let pkt_buf: Vec<u8> =
        vec![0; original_packet.packet_size() + Icmpv6Packet::minimum_packet_size()];
    let mut ret = match MutableIcmpv6Packet::owned(pkt_buf) {
        Some(v) => v,
        None => return None,
    };
    // update the option field if needed
    // convert it into a icmp echo request
    ret.set_icmpv6_type(Icmpv6Types::EchoRequest);
    ret.set_payload(original_packet.packet());
    //
    let csum = pnet::util::ipv6_checksum(
        ret.packet(),
        1,
        &[],
        src_addr,
        dst_addr,
        pnet::packet::ip::IpNextHeaderProtocols::Icmpv6,
    );
    ret.set_checksum(csum);

    Some(ret.consume_to_immutable())
}

//TODO: tests
