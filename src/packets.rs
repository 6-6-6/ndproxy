use std::net::Ipv6Addr;
use pnet::util::MacAddr;
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::ndp;
use pnet::packet::PacketSize;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::icmpv6::{Icmpv6Packet, MutableIcmpv6Packet};

#[derive(Debug, Clone)]
pub struct ICMP6Filter {
    filters: [u32;8]
}

impl ICMP6Filter {
    pub fn new(default: u32) -> Self {
        ICMP6Filter {
            filters: [default;8]
        }
    }

    pub fn set_pass(&mut self, icmp6_type: u8) {
        let index:usize = icmp6_type.into();
        self.filters[index >> 5] &= !(1u32 << (icmp6_type & 31));
    }

    pub unsafe fn as_ptr_cvoid(&mut self) -> *const libc::c_void{
        self.filters.as_mut_ptr() as *const libc::c_void
    }
}

/*
pub fn generate_NS_proxied<'a>(original_packet: &'a ndp::NeighborSolicitPacket,
        src_addr: &Ipv6Addr,
        dst_addr: &Ipv6Addr,
        src_hwaddr: &MacAddr,
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
    ret.set_options(&new_options);
    for option in original_packet.get_options() {
        match option.option_type {
            ndp::NdpOptionTypes::SourceLLAddr => {
                println!("{:?}", option);
                new_options.push(ndp::NdpOption{
                    option_type: ndp::NdpOptionTypes::SourceLLAddr,
                    length: 1,
                    data: src_hwaddr.octets().to_vec(),
                })
            },
            _ => new_options.push(option)
        }
    }
    println!("{:?}", new_options);
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
*/

pub fn generate_NA_forwarded<'a>(
        src_addr: &Ipv6Addr,
        dst_addr: &Ipv6Addr,
        proxied_addr: &Ipv6Addr,
        src_hwaddr: &MacAddr,
        flag: u8,
        ) -> Option<ndp::NeighborAdvertPacket <'a>> {

    let pkt_buf: Vec<u8> = vec![0; 32];
    let mut ret = match ndp::MutableNeighborAdvertPacket::owned(pkt_buf) {
        Some(v) => v,
        None => return None,
    };
    // basic info
    ret.set_icmpv6_type(icmpv6::Icmpv6Types::NeighborAdvert);
    // set the to-be-announced addr
    ret.set_target_addr(*proxied_addr);
    // force O flag to be 0
    ret.set_flags(flag);
    ret.set_flags(ret.get_flags() & 0xdf);
    // update the option field if needed
    // TODO: carefully deal with it with reference to RFC 4861/RFC 4389
    let mut new_options: Vec<ndp::NdpOption> = Vec::new();
    new_options.push(
        ndp::NdpOption{
            option_type: ndp::NdpOptionTypes::TargetLLAddr,
            length: 1,
            data: src_hwaddr.octets().to_vec()});
    ret.set_options(&new_options);
    //
    let csum = pnet::util::ipv6_checksum(
        ret.packet(), 1, &[], src_addr, dst_addr, pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ret.set_checksum(csum);

    Some(ret.consume_to_immutable())
}

pub fn generate_NS_trick<'a>(original_packet: &'a ndp::NeighborSolicitPacket,
        src_addr: &Ipv6Addr,
        dst_addr: &Ipv6Addr,
        ) -> Option<Icmpv6Packet <'a>> {

    let pkt_buf: Vec<u8> = vec![0; original_packet.packet_size()+Icmpv6Packet::minimum_packet_size()];
    let mut ret = MutableIcmpv6Packet::owned(pkt_buf).unwrap();
    // update the option field if needed
    // convert it into a icmp echo request
    ret.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
    ret.set_payload(original_packet.packet());
    //
    let csum = pnet::util::ipv6_checksum(
        ret.packet(), 1, &[], src_addr, dst_addr, pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
    ret.set_checksum(csum);

    Some(ret.consume_to_immutable())
}
//TODO: tests