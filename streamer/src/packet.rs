//! The `packet` module defines data structures and methods to pull data from the network.
use {
    crate::{
        recvmmsg::{recv_mmsg, NUM_RCVMMSGS},
        socket::SocketAddrSpace,
    },
    std::{
        io::Result,
        net::UdpSocket,
        time::{Duration, Instant},
    },
};
pub use {
    solana_perf::packet::{
        to_packet_batches, PacketBatch, PacketBatchRecycler, NUM_PACKETS, PACKETS_PER_BATCH,
    },
    solana_sdk::packet::{Meta, Packet, PACKET_DATA_SIZE},
};

pub fn recv_from(batch: &mut PacketBatch, socket: &UdpSocket, max_wait: Duration) -> Result<usize> {
    let mut i = 0;
    //DOCUMENTED SIDE-EFFECT
    //Performance out of the IO without poll
    //  * block on the socket until it's readable
    //  * set the socket to non blocking
    //  * read until it fails
    //  * set it back to blocking before returning
    socket.set_nonblocking(false)?;
    trace!("receiving on {}", socket.local_addr().unwrap());
    let start = Instant::now();
    loop {
        batch.resize(
            std::cmp::min(i + NUM_RCVMMSGS, PACKETS_PER_BATCH),
            Packet::default(),
        );
        match recv_mmsg(socket, &mut batch[i..]) {
            Err(_) if i > 0 => {
                if start.elapsed() > max_wait {
                    break;
                }
            }
            Err(e) => {
                trace!("recv_from err {:?}", e);
                return Err(e);
            }
            Ok(npkts) => {
                if i == 0 {
                    socket.set_nonblocking(true)?;
                }
                trace!("got {} packets", npkts);
                i += npkts;
                // Try to batch into big enough buffers
                // will cause less re-shuffling later on.
                if start.elapsed() > max_wait || i >= PACKETS_PER_BATCH {
                    break;
                }
            }
        }
    }
    batch.truncate(i);
    Ok(i)
}

pub fn send_to(
    batch: &PacketBatch,
    socket: &UdpSocket,
    socket_addr_space: &SocketAddrSpace,
) -> Result<()> {
    for p in batch.iter() {
        let addr = p.meta().socket_addr();
        if socket_addr_space.check(&addr) {
            if let Some(data) = p.data(..) {
                socket.send_to(data, addr)?;
            }
        }
    }
    Ok(())
}
