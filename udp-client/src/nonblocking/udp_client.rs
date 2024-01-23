//! Simple UDP client that communicates with the given UDP port with UDP and provides
//! an interface for sending data

use {
    async_trait::async_trait, core::iter::repeat,
    solana_connection_cache::nonblocking::client_connection::ClientConnection,
    solana_sdk::transport::Result as TransportResult,
    solana_streamer::nonblocking::sendmmsg::batch_send, std::net::SocketAddr,
    tokio::net::UdpSocket,
};

pub struct UdpClientConnection {
    pub socket: UdpSocket,
    pub addr: SocketAddr,
}

impl UdpClientConnection {
    pub fn new_from_addr(socket: std::net::UdpSocket, server_addr: SocketAddr) -> Self {
        socket.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(socket).unwrap();
        Self {
            socket,
            addr: server_addr,
        }
    }
}

#[async_trait]
impl ClientConnection for UdpClientConnection {
    fn server_addr(&self) -> &SocketAddr {
        &self.addr
    }

    async fn send_data(&self, buffer: &[u8]) -> TransportResult<()> {
        self.socket.send_to(buffer, self.addr).await?;
        Ok(())
    }

    async fn send_data_batch(&self, buffers: &[Vec<u8>]) -> TransportResult<()> {
        let pkts: Vec<_> = buffers.iter().zip(repeat(self.server_addr())).collect();
        batch_send(&self.socket, &pkts).await?;
        Ok(())
    }
}
