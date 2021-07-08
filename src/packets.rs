use std::net::Ipv6Addr;
use pnet::packet::icmpv6::ndp;
use pnet::packet::PacketSize;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;


pub fn generate_NS_proxied<'a>(original_packet: &'a ndp::NeighborSolicitPacket,
        src_addr: &Ipv6Addr,
        dst_addr: &Ipv6Addr,
        ) -> Option<ndp::NeighborSolicitPacket <'a>> {

    let pkt_buf: Vec<u8> = vec![0; original_packet.packet_size()];
    let mut ret = match ndp::MutableNeighborSolicitPacket::owned(pkt_buf) {
        Some(v) => v,
        None => return None,
    };
    // copy most of the information from the original one
    ret.clone_from(original_packet);
    // update the option field if needed
    // TODO: carefully deal with it with reference to RFC 4861/RFC 4389
    let mut new_options: Vec<ndp::NdpOption> = Vec::new();
    for option in original_packet.get_options() {
        match option.option_type {
            ndp::NdpOptionTypes::SourceLLAddr => {
                new_options.push(ndp::NdpOption{
                    option_type: ndp::NdpOptionTypes::SourceLLAddr,
                    length: 1,
                    data: src_addr.octets().to_vec(),
                })
            },
            _ => new_options.push(option)
        }
    }
    ret.set_options(&new_options);
    //
    let csum = pnet::util::ipv6_checksum(
        ret.packet(), 1, &[], src_addr, dst_addr, pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ret.set_checksum(csum);

    Some(ret.consume_to_immutable())
}

pub fn generate_NA_proxied<'a>(original_packet: &'a ndp::NeighborAdvertPacket,
        src_addr: &Ipv6Addr,
        dst_addr: &Ipv6Addr,
        ) -> Option<ndp::NeighborAdvertPacket <'a>> {

    let pkt_buf: Vec<u8> = vec![0; original_packet.packet_size()];
    let mut ret = match ndp::MutableNeighborAdvertPacket::owned(pkt_buf) {
        Some(v) => v,
        None => return None,
    };
    // copy most of the information from the original one
    ret.clone_from(original_packet);
    // force O flag to be 0
    ret.set_flags(ret.get_flags() & 0xdf);
    // update the option field if needed
    // TODO: carefully deal with it with reference to RFC 4861/RFC 4389
    let mut new_options: Vec<ndp::NdpOption> = Vec::new();
    for option in original_packet.get_options() {
        match option.option_type {
            ndp::NdpOptionTypes::TargetLLAddr => {
                new_options.push(ndp::NdpOption{
                    option_type: ndp::NdpOptionTypes::TargetLLAddr,
                    length: 1,
                    data: src_addr.octets().to_vec(),
                })
            },
            _ => new_options.push(option)
        }
    }
    ret.set_options(&new_options);
    //
    let csum = pnet::util::ipv6_checksum(
        ret.packet(), 1, &[], src_addr, dst_addr, pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ret.set_checksum(csum);

    Some(ret.consume_to_immutable())
}

//TODO: tests