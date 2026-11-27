use hickory_proto::op::Message;
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Idle connections kept per upstream.
const MAX_IDLE: usize = 8;
/// Idle connections older than this are not reused: servers close idle TCP and TLS
/// connections after some seconds, and a closed one costs a failed attempt.
const MAX_IDLE_AGE: Duration = Duration::from_secs(10);

/// Idle connections to one TCP or DoT upstream, so queries skip the TCP and TLS
/// handshakes (two to three round trips, and the TLS key exchange) of a new connection.
pub(crate) struct ConnPool<S> {
    idle: Mutex<Vec<(S, Instant)>>,
}

impl<S> ConnPool<S> {
    pub(crate) fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
        }
    }

    /// The most recently used idle connection that is still fresh.
    pub(crate) fn take(&self) -> Option<S> {
        let mut idle = self.idle.lock();
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() < MAX_IDLE_AGE {
                return Some(stream);
            }
        }
        None
    }

    pub(crate) fn put(&self, stream: S) {
        let mut idle = self.idle.lock();
        if idle.len() < MAX_IDLE {
            idle.push((stream, Instant::now()));
        }
    }
}

impl<S> std::fmt::Debug for ConnPool<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnPool")
            .field("idle", &self.idle.lock().len())
            .finish()
    }
}

/// A query with its 2-byte length prefix (RFC 1035 4.2.2), to send in a single write.
/// Writing the prefix and the message separately lets Nagle's algorithm hold the second
/// segment until the first is acknowledged, which a peer delays by up to 40 ms or more.
pub(crate) fn frame(wire: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(wire.len())
        .map_err(|_| "DNS message exceeds maximum TCP DNS message length (65535 bytes)".to_string())?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    Ok(framed)
}

/// Sends a framed query and reads the response to it.
pub(crate) async fn exchange<S>(stream: &mut S, framed: &[u8], id: u16) -> Result<Message, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(framed)
        .await
        .map_err(|e| format!("Failed to write query: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("Failed to flush stream: {e}"))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("Failed to read response length prefix: {e}"))?;
    let mut resp_buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    let resp = Message::from_vec(&resp_buf).map_err(|e| format!("Failed to parse response: {e}"))?;
    if resp.metadata.id != id {
        return Err(format!(
            "DNS ID mismatch: expected {id}, got {}",
            resp.metadata.id
        ));
    }
    Ok(resp)
}
