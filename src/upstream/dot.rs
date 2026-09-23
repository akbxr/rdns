use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

pub fn create_tls_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("Failed to configure safe default TLS versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

#[derive(Clone)]
pub struct DotResolver {
    pub target: SocketAddr,
    pub server_name: String,
    pub name: String,
    connector: TlsConnector,
}

impl std::fmt::Debug for DotResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotResolver")
            .field("name", &self.name)
            .field("target", &self.target)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl DotResolver {
    pub fn new(target: SocketAddr, server_name: String) -> Self {
        let tls_config = create_tls_config();
        let connector = TlsConnector::from(tls_config);
        Self {
            name: format!("dot:{target}#{server_name}"),
            target,
            server_name,
            connector,
        }
    }

    pub async fn resolve(&self, query: &Message, query_timeout: Duration) -> Result<Message, String> {
        let bytes = query
            .to_vec()
            .map_err(|e| format!("Failed to serialize query: {e}"))?;

        if bytes.len() > u16::MAX as usize {
            return Err("DNS query exceeds maximum TCP/DoT DNS message length (65535 bytes)".to_string());
        }

        let sni = ServerName::try_from(self.server_name.clone())
            .map_err(|e| format!("Invalid SNI '{}': {e}", self.server_name))?;

        timeout(query_timeout, async {
            let tcp_stream = TcpStream::connect(self.target)
                .await
                .map_err(|e| format!("Failed to connect TCP to {}: {e}", self.target))?;

            let mut tls_stream = self
                .connector
                .connect(sni, tcp_stream)
                .await
                .map_err(|e| format!("TLS handshake failed with {}: {e}", self.server_name))?;

            let len_prefix = (bytes.len() as u16).to_be_bytes();
            tls_stream
                .write_all(&len_prefix)
                .await
                .map_err(|e| format!("Failed to write length prefix: {e}"))?;
            tls_stream
                .write_all(&bytes)
                .await
                .map_err(|e| format!("Failed to write query body: {e}"))?;
            tls_stream
                .flush()
                .await
                .map_err(|e| format!("Failed to flush stream: {e}"))?;

            let mut resp_len_buf = [0u8; 2];
            tls_stream
                .read_exact(&mut resp_len_buf)
                .await
                .map_err(|e| format!("Failed to read response length prefix: {e}"))?;

            let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            tls_stream
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
        .map_err(|_| format!("DoT query to {} timed out after {:?}", self.target, query_timeout))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config() {
        let _config = create_tls_config();
    }
}
