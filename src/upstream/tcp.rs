use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct TcpResolver {
    pub target: SocketAddr,
    pub name: String,
}

impl TcpResolver {
    pub fn new(target: SocketAddr) -> Self {
        Self {
            name: format!("tcp:{target}"),
            target,
        }
    }

    pub async fn resolve(&self, query: &Message, query_timeout: Duration) -> Result<Message, String> {
        let bytes = query
            .to_vec()
            .map_err(|e| format!("Failed to serialize query: {e}"))?;

        if bytes.len() > u16::MAX as usize {
            return Err("DNS query exceeds maximum TCP DNS message length (65535 bytes)".to_string());
        }

        timeout(query_timeout, async {
            let mut stream = TcpStream::connect(self.target)
                .await
                .map_err(|e| format!("Failed to connect TCP to {}: {e}", self.target))?;

            let len_prefix = (bytes.len() as u16).to_be_bytes();
            stream
                .write_all(&len_prefix)
                .await
                .map_err(|e| format!("Failed to write length prefix: {e}"))?;
            stream
                .write_all(&bytes)
                .await
                .map_err(|e| format!("Failed to write query body: {e}"))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("Failed to flush stream: {e}"))?;

            let mut resp_len_buf = [0u8; 2];
            stream
                .read_exact(&mut resp_len_buf)
                .await
                .map_err(|e| format!("Failed to read response length prefix: {e}"))?;

            let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream
                .read_exact(&mut resp_buf)
                .await
                .map_err(|e| format!("Failed to read response body: {e}"))?;

            let resp = Message::from_vec(&resp_buf)
                .map_err(|e| format!("Failed to parse response: {e}"))?;

            if resp.metadata.id != query.metadata.id {
                return Err(format!(
                    "DNS ID mismatch: expected {}, got {}",
                    query.metadata.id, resp.metadata.id
                ));
            }

            Ok(resp)
        })
        .await
        .map_err(|_| format!("TCP query to {} timed out after {:?}", self.target, query_timeout))?
    }
}
