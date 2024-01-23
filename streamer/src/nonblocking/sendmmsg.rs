//! The `sendmmsg` module provides a nonblocking sendmmsg() API implementation

use {
    crate::sendmmsg::SendPktsError,
    futures_util::future::join_all,
    std::{borrow::Borrow, iter::repeat, net::SocketAddr},
    tokio::net::UdpSocket,
};

pub async fn batch_send<S, T>(sock: &UdpSocket, packets: &[(T, S)]) -> Result<(), SendPktsError>
where
    S: Borrow<SocketAddr>,
    T: AsRef<[u8]>,
{
    let mut num_failed = 0;
    let mut erropt = None;
    let futures = packets
        .iter()
        .map(|(p, a)| sock.send_to(p.as_ref(), a.borrow()))
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results {
        if let Err(e) = result {
            num_failed += 1;
            if erropt.is_none() {
                erropt = Some(e);
            }
        }
    }

    if let Some(err) = erropt {
        Err(SendPktsError::IoError(err, num_failed))
    } else {
        Ok(())
    }
}

pub async fn multi_target_send<S, T>(
    sock: &UdpSocket,
    packet: T,
    dests: &[S],
) -> Result<(), SendPktsError>
where
    S: Borrow<SocketAddr>,
    T: AsRef<[u8]>,
{
    let dests = dests.iter().map(Borrow::borrow);
    let pkts: Vec<_> = repeat(&packet).zip(dests).collect();
    batch_send(sock, &pkts).await
}
