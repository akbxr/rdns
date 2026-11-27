use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct UdpResolver {
    pub target: SocketAddr,
    pub name: String,
}

impl UdpResolver {
    pub fn new(target: SocketAddr) -> Self {
        Self {
            name: format!("udp:{target}"),
            target,
        }
    }

    pub async fn resolve(&self, query: &Message, query_timeout: Duration) -> Result<Message, String> {
        let bytes = query
            .to_vec()
            .map_err(|e| format!("Failed to serialize query: {e}"))?;
        self.resolve_wire(&bytes, query.metadata.id, query_timeout).await
    }

    /// A socket per query: its random source port is part of what protects against
    /// spoofed answers.
    pub(crate) async fn resolve_wire(&self, bytes: &[u8], id: u16, query_timeout: Duration) -> Result<Message, String> {
        let bind_addr = if self.target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind UDP socket: {e}"))?;

        socket
            .connect(self.target)
            .await
            .map_err(|e| format!("Failed to connect to {}: {e}", self.target))?;

        timeout(query_timeout, async {
            socket
                .send(bytes)
                .await
                .map_err(|e| format!("Failed to send query: {e}"))?;

            let mut buf = [0u8; 4096];
            let len = socket
                .recv(&mut buf)
                .await
                .map_err(|e| format!("Failed to receive response: {e}"))?;

            let resp = Message::from_vec(&buf[..len])
                .map_err(|e| format!("Failed to parse response: {e}"))?;

            if resp.metadata.id != id {
                return Err(format!(
                    "DNS ID mismatch: expected {id}, got {}",
                    resp.metadata.id
                ));
            }

            Ok(resp)
        })
        .await
        .map_err(|_| format!("UDP query to {} timed out after {:?}", self.target, query_timeout))?
    }
}
