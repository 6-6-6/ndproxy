use crate::datalink::bpf::*;
use crate::datalink::{PacketReceiver, PacketReceiverOpts};
use crate::interfaces;
use pnet::packet::icmpv6::Icmpv6Types;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

impl PacketReceiverOpts for PacketReceiver {
    fn bind_to_interface(&self, iface: &interfaces::NDInterface) -> Result<(), i32> {
        let socket_for_iface = libc::sockaddr_ll {
            sll_family: libc::PF_PACKET as u16,
            sll_protocol: (libc::ETH_P_IPV6 as u16).to_be(),
            sll_ifindex: *iface.get_scope_id() as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        match unsafe {
            libc::bind(
                self.socket.as_raw_fd(),
                &socket_for_iface as *const libc::sockaddr_ll as *const libc::sockaddr,
                size_of::<libc::sockaddr_ll>() as u32,
            )
        } {
            0 => Ok(()),
            errno => Err(errno),
        }
    }

    fn set_promiscuous(&self, iface: &interfaces::NDInterface) -> Result<(), i32> {
        let mut pmr: libc::packet_mreq = unsafe { std::mem::zeroed() };
        pmr.mr_ifindex = *iface.get_scope_id() as i32;
        pmr.mr_type = libc::PACKET_MR_PROMISC as u16;

        match unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&pmr as *const libc::packet_mreq) as *const libc::c_void,
                size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        } {
            0 => Ok(()),
            errno => Err(errno),
        }
    }

    fn set_filter_pass_ipv6_ns(&self) -> Result<(), i32> {
        let mut ipv6_ns_filter = [
            // offsetof(ipv6 header, ipv6 next header)
            bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 6),
            bpf_jump(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                libc::IPPROTO_ICMPV6 as u32,
                0,
                3,
            ),
            // sizeof(ipv6 header) + offsetof(icmpv6 header, icmp6_type)
            bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 40 + 0),
            bpf_jump(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                Icmpv6Types::NeighborSolicit.0 as u32,
                0,
                1,
            ),
            bpf_stmt((BPF_RET | BPF_K) as u16, u32::MAX),
            bpf_stmt((BPF_RET | BPF_K) as u16, 0),
        ];
        let ipv6_socket_fprog = libc::sock_fprog {
            len: 6,
            filter: &mut ipv6_ns_filter as *mut libc::sock_filter,
        };

        match unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &ipv6_socket_fprog as *const _ as *const libc::c_void,
                size_of::<libc::sock_fprog>() as u32,
            )
        } {
            0 => Ok(()),
            errno => Err(errno),
        }
    }
}