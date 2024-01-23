//! The `recvmmsg` module provides a nonblocking recvmmsg() API implementation

use {
    crate::{
        packet::{Meta, Packet},
        recvmmsg::NUM_RCVMMSGS,
    },
    std::{cmp, io},
    tokio::net::UdpSocket,
};

/// Pulls some packets from the socket into the specified container
/// returning how many packets were read
pub async fn recv_mmsg(
    socket: &UdpSocket,
    packets: &mut [Packet],
) -> io::Result</*num packets:*/ usize> {
    debug_assert!(packets.iter().all(|pkt| pkt.meta() == &Meta::default()));
    let count = cmp::min(NUM_RCVMMSGS, packets.len());
    socket.readable().await?;
    let mut i = 0;
    for p in packets.iter_mut().take(count) {
        p.meta_mut().size = 0;
        match socket.try_recv_from(p.buffer_mut()) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => {
                return Err(e);
            }
            Ok((nrecv, from)) => {
                p.meta_mut().size = nrecv;
                p.meta_mut().set_socket_addr(&from);
            }
        }
        i += 1;
    }
    Ok(i)
}

/// Reads the exact number of packets required to fill `packets`
pub async fn recv_mmsg_exact(
    socket: &UdpSocket,
    packets: &mut [Packet],
) -> io::Result</*num packets:*/ usize> {
    let total = packets.len();
    let mut remaining = total;
    while remaining != 0 {
        let first = total - remaining;
        let res = recv_mmsg(socket, &mut packets[first..]).await?;
        remaining -= res;
    }
    Ok(packets.len())
}
