use crate::datalink::bpf::*;
use crate::datalink::PacketReceiver;
use crate::datalink::PacketReceiverOpts;
use crate::interfaces;
use pnet::packet::icmpv6::Icmpv6Types;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

impl PacketReceiverOpts for PacketReceiver {
    fn bind_to_interface(&self, iface: &interfaces::NDInterface) -> Result<(), i32> {
        Ok(())
    }
    fn set_promiscuous(&self, iface: &interfaces::NDInterface) -> Result<(), i32> {
        Ok(())
    }
    fn set_filter_pass_ipv6_ns(&self) -> Result<(), i32> {
        Ok(())
    }
}
