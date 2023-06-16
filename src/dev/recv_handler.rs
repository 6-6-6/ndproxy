use std::net::Ipv6Addr;

use tokio::sync::mpsc;

#[allow(clippy::box_collection)]
pub async fn mpsc_recv_and_drop(
    mut receiver: mpsc::UnboundedReceiver<(u32, Box<Ipv6Addr>, Box<Vec<u8>>)>,
) -> Result<(), ()> {
    while let Some((scope_id, tgt_addr, packet)) = receiver.recv().await {
        println!(
            "scope_id: {}, target_addr: {}, packet_len: {}",
            scope_id,
            tgt_addr,
            packet.len()
        )
    }
    Ok(())
}
