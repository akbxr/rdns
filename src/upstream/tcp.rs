use super::pool::{exchange, frame, ConnPool};
use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct TcpResolver {
    pub target: SocketAddr,
    pub name: String,
    pool: Arc<ConnPool<TcpStream>>,
}

impl TcpResolver {
    pub fn new(target: SocketAddr) -> Self {
        Self {
            name: format!("tcp:{target}"),
            target,
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
                .map_err(|_| format!("TCP query to {} timed out after {:?}", this.target, query_timeout))?
        })
        .await
        .map_err(|e| format!("TCP query task failed: {e}"))?
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

        let mut stream = TcpStream::connect(self.target)
            .await
            .map_err(|e| format!("Failed to connect TCP to {}: {e}", self.target))?;
        let _ = stream.set_nodelay(true);
        let resp = exchange(&mut stream, framed, id).await?;
        self.pool.put(stream);
        Ok(resp)
    }
}
