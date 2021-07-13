use crate::interfaces;
use pnet::datalink;

pub fn create_datalink_monitor(
    iface: &interfaces::NDInterface,
) -> Box<dyn datalink::DataLinkReceiver> {
    // assume it is ethernet
    // TODO: try to determine what link type it is.
    let mut monitor_config: datalink::Config = Default::default();
    monitor_config.channel_type = datalink::ChannelType::Layer3(0x86DD);
    // initialize the monitor
    let (_tx, monitor) = match datalink::channel(iface.get_from_pnet(), monitor_config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    drop(_tx);
    monitor
}
