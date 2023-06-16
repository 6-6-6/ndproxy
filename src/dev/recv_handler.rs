
use std::net::Ipv6Addr;

use tokio::sync::{mpsc};

pub async fn mpsc_recv_and_drop(mut receiver: mpsc::UnboundedReceiver<(u32, Box<Ipv6Addr>, Box<Vec<u8>>)>) -> Result<(),()> {
    while let Some((_scope_id, _tgt_addr, _packet)) = receiver.recv().await { }
    Ok(())
}