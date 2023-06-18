use std::net::Ipv6Addr;

use log::info;
use tokio::sync::mpsc;

#[allow(clippy::box_collection)]
pub async fn mpsc_recv_and_drop(
    mut receiver: mpsc::Receiver<(u32, Box<Ipv6Addr>, Box<Vec<u8>>)>,
) -> Result<(), ()> {
    loop {
        let (scope_id, tgt_addr, packet) = receiver.recv().await.unwrap();
        info!(
            "scope_id: {}, target_addr: {}, packet_len: {}",
            scope_id,
            tgt_addr,
            packet.len()
        )
    }
}
