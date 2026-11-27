use super::pool::{exchange, frame, ConnPool};
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

/// TLS client configuration shared by all DoT upstreams: one copy of the root
/// certificates, and one session cache so reconnects can resume TLS sessions.
pub fn create_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("Failed to configure safe default TLS versions")
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

#[derive(Clone)]
pub struct DotResolver {
    pub target: SocketAddr,
    pub server_name: String,
    pub name: String,
    sni: Option<ServerName<'static>>,
    connector: TlsConnector,
    pool: Arc<ConnPool<TlsStream<TcpStream>>>,
}

impl std::fmt::Debug for DotResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotResolver")
            .field("name", &self.name)
            .field("target", &self.target)
            .field("server_name", &self.server_name)
            .field("pool", &self.pool)
            .finish()
    }
}

impl DotResolver {
    pub fn new(target: SocketAddr, server_name: String) -> Self {
        Self {
            name: format!("dot:{target}#{server_name}"),
            target,
            sni: ServerName::try_from(server_name.clone()).ok(),
            server_name,
            connector: TlsConnector::from(create_tls_config()),
            pool: Arc::new(ConnPool::new()),
        }
    }

    pub async fn resolve(&self, query: &Message, query_timeout: Duration) -> Result<Message, String> {
        let bytes = query
            .to_vec()
            .map_err(|e| format!("Failed to serialize query: {e}"))?;
        self.resolve_wire(&bytes, query.metadata.id, query_timeout).await
    }

    pub(crate) async fn resolve_wire(&self, wire: &[u8], id: u16, query_timeout: Duration) -> Result<Message, String> {
        let framed = frame(wire)?;
        let this = self.clone();
        // Own task: a parallel race drops the losing queries, and a connection dropped
        // mid-exchange cannot go back to the pool. The task finishes it (within the
        // timeout) and keeps the connection.
        tokio::spawn(async move {
            timeout(query_timeout, this.exchange_pooled(&framed, id, query_timeout))
                .await
                .map_err(|_| format!("DoT query to {} timed out after {:?}", this.target, query_timeout))?
        })
        .await
        .map_err(|e| format!("DoT query task failed: {e}"))?
    }

    async fn exchange_pooled(&self, framed: &[u8], id: u16, query_timeout: Duration) -> Result<Message, String> {
        if let Some(mut stream) = self.pool.take() {
            // A connection the server closed fails fast; one that silently went away gets
            // half the time budget before a new connection is tried.
            if let Ok(Ok(resp)) = timeout(query_timeout / 2, exchange(&mut stream, framed, id)).await {
                self.pool.put(stream);
                return Ok(resp);
            }
        }

        let mut stream = self.connect().await?;
        let resp = exchange(&mut stream, framed, id).await?;
        self.pool.put(stream);
        Ok(resp)
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, String> {
        let sni = self
            .sni
            .clone()
            .ok_or_else(|| format!("Invalid SNI '{}'", self.server_name))?;
        let tcp_stream = TcpStream::connect(self.target)
            .await
            .map_err(|e| format!("Failed to connect TCP to {}: {e}", self.target))?;
        let _ = tcp_stream.set_nodelay(true);
        self.connector
            .connect(sni, tcp_stream)
            .await
            .map_err(|e| format!("TLS handshake failed with {}: {e}", self.server_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config() {
        let config = create_tls_config();
        assert!(Arc::ptr_eq(&config, &create_tls_config()));
    }
}
