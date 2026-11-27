use crate::blocking::BlockEngine;
use crate::cache::DnsCache;
use crate::client::ClientMatcher;
use crate::config::{Config, QueryLogType};
use crate::custom_dns::CustomDnsManager;
use crate::metrics::Metrics;
use crate::query_log::QueryLogger;
use crate::upstream::UpstreamRegistry;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::Name;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// How long a TCP connection may sit idle between queries before it is closed.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Same for DoT: longer, as clients (Android Private DNS) reuse it to skip handshakes.
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed for a TLS handshake, and for a started message to arrive or be sent.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServerContext {
    pub config: Arc<Config>,
    pub block_engine: Arc<BlockEngine>,
    pub cache: Arc<DnsCache>,
    pub custom_dns: Arc<CustomDnsManager>,
    pub upstream_registry: Arc<UpstreamRegistry>,
    pub client_matcher: Arc<ClientMatcher>,
    pub metrics: Arc<Metrics>,
    pub query_logger: Arc<QueryLogger>,
    pub shutdown_notify: Arc<tokio::sync::Notify>,
}

pub struct DnsServer {
    pub ctx: Arc<ServerContext>,
}

/// Result of `DnsServer::answer_locally`.
pub enum LocalAnswer {
    Answered(Message),
    /// The query needs an upstream server: pass this to `resolve_upstream`.
    Upstream(Pending),
}

/// A query left for the upstream servers, with what resolving and logging it needs.
pub struct Pending {
    client_addr: SocketAddr,
    client_group: String,
    domain: String,
    qtype: &'static str,
    start: Instant,
    /// Conditional forwarding group for the domain, if any.
    conditional: Option<String>,
}

/// Query name as matched against lists and records: ASCII (internationalized labels
/// stay in punycode, as lists carry them), lowercase, without the root dot.
fn normalize_qname(name: &Name) -> String {
    let mut domain = name.to_ascii();
    if domain.ends_with('.') {
        domain.pop();
    }
    domain.make_ascii_lowercase();
    domain
}

impl DnsServer {
    pub fn new(ctx: Arc<ServerContext>) -> Self {
        Self { ctx }
    }

    /// Process a single DNS query through the complete pipeline
    pub async fn process_query(&self, query: &Message, client_addr: SocketAddr) -> Message {
        match self.answer_locally(query, client_addr) {
            LocalAnswer::Answered(resp) => resp,
            LocalAnswer::Upstream(pending) => self.resolve_upstream(query, pending).await,
        }
    }

    /// Answers from custom records, the blocklists or the cache, without awaiting
    /// anything; most queries end here. Otherwise returns what `resolve_upstream` needs.
    pub fn answer_locally(&self, query: &Message, client_addr: SocketAddr) -> LocalAnswer {
        let start = Instant::now();

        let question = match query.queries.first() {
            Some(q) => q,
            None => {
                return LocalAnswer::Answered(Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::FormErr));
            }
        };

        let client_ip = client_addr.ip();
        let client_group = self.ctx.client_matcher.get_primary_group(client_ip);
        let domain = normalize_qname(&question.name);
        let qtype: &'static str = question.query_type.into();

        self.ctx.metrics.inc_query(client_group, qtype);

        let log = |status: fmt::Arguments<'_>, rcode: ResponseCode| {
            self.log_query(client_addr, client_group, &domain, qtype, status, rcode, start);
        };

        // 1. Check Custom DNS / Local Records
        if let Some(custom_resp) = self.ctx.custom_dns.resolve_domain(query, &domain) {
            self.ctx.metrics.inc_custom_dns_hit();
            self.ctx.query_logger.record(client_ip, false);
            log(format_args!("CUSTOM_DNS"), custom_resp.metadata.response_code);
            return LocalAnswer::Answered(custom_resp);
        }

        // 2. Check Blocking Engine
        if let Some(reason) = self.ctx.block_engine.check_blocked(client_group, &domain) {
            self.ctx.metrics.inc_blocked(client_group, &reason.metric_label());
            let blocked_resp = self.ctx.block_engine.build_blocked_response(query);
            self.ctx.query_logger.record(client_ip, true);
            if self.ctx.config.query_log.log_blocked {
                log(format_args!("BLOCKED ({reason})"), blocked_resp.metadata.response_code);
            }
            return LocalAnswer::Answered(blocked_resp);
        }
        self.ctx.query_logger.record(client_ip, false);

        // 3. Conditional forwarding domains are cached too, but not prefetched
        let conditional = self.ctx.upstream_registry.get_for_domain(&domain);

        // 4. Check DNS Cache
        if let Some((cached_resp, needs_prefetch)) = self.ctx.cache.get(query) {
            self.ctx.metrics.inc_cache_hit();

            if needs_prefetch && conditional.is_none() {
                let ctx_clone = self.ctx.clone();
                let query_clone = query.clone();
                tokio::spawn(async move {
                    if let Some(default_group) = ctx_clone.upstream_registry.get_default_group() {
                        if let Ok(fresh_resp) = default_group.resolve(&query_clone).await {
                            ctx_clone.cache.put(&query_clone, &fresh_resp);
                        }
                    }
                });
            }

            if conditional.is_some() {
                log(format_args!("CACHE (CONDITIONAL)"), cached_resp.metadata.response_code);
            } else {
                log(format_args!("CACHE"), cached_resp.metadata.response_code);
            }
            return LocalAnswer::Answered(cached_resp);
        }

        self.ctx.metrics.inc_cache_miss();

        LocalAnswer::Upstream(Pending {
            client_addr,
            client_group: client_group.to_string(),
            qtype,
            start,
            conditional: conditional.map(|group| group.name.clone()),
            domain,
        })
    }

    /// 5. Upstream resolution, through the conditional forwarding group or the default one
    pub async fn resolve_upstream(&self, query: &Message, pending: Pending) -> Message {
        let registry = &self.ctx.upstream_registry;
        let group = match &pending.conditional {
            Some(name) => registry.get_group(name),
            None => registry.get_default_group(),
        };
        let Some(group) = group else {
            error!("No default upstream group configured");
            return Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail);
        };
        let route = if pending.conditional.is_some() { "CONDITIONAL" } else { "UPSTREAM" };

        self.ctx.metrics.inc_upstream_query(&group.name);

        match group.resolve(query).await {
            Ok(resp) => {
                self.ctx.cache.put(query, &resp);
                self.log_query(
                    pending.client_addr,
                    &pending.client_group,
                    &pending.domain,
                    pending.qtype,
                    format_args!("{route} ({})", group.name),
                    resp.metadata.response_code,
                    pending.start,
                );
                resp
            }
            Err(e) => {
                self.ctx.metrics.inc_upstream_error(&group.name);
                warn!(error = %e, domain = %pending.domain, route = route, "Upstream resolution failed");
                Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail)
            }
        }
    }

    /// Logs a processed query. The `info!` macro formats its fields only when the INFO
    /// level is enabled, so with logging off nothing here allocates.
    #[allow(clippy::too_many_arguments)]
    fn log_query(
        &self,
        client: SocketAddr,
        client_group: &str,
        domain: &str,
        qtype: &str,
        status: fmt::Arguments<'_>,
        rcode: ResponseCode,
        start: Instant,
    ) {
        if self.ctx.config.query_log.log_type == QueryLogType::None {
            return;
        }

        info!(
            client = %client.ip(),
            group = %client_group,
            domain = %domain,
            qtype = %qtype,
            status = %status,
            rcode = ?rcode,
            duration = %format_args!("{:.2}ms", start.elapsed().as_secs_f64() * 1000.0),
            "DNS query processed"
        );
    }

    /// Start UDP listener
    pub async fn run_udp(self: Arc<Self>, addr: SocketAddr) -> Result<(), std::io::Error> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!(addr = %addr, "DNS UDP listener started");

        let mut buf = [0u8; 4096];
        loop {
            let (len, client_addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    error!("UDP recv error: {e}");
                    continue;
                }
            };

            let query = match Message::from_vec(&buf[..len]) {
                Ok(m) => m,
                Err(e) => {
                    warn!(client = %client_addr, error = %e, "Invalid DNS UDP packet");
                    continue;
                }
            };

            // Local answers take microseconds: send them from this loop. Spawning a task
            // per packet cost more CPU in thread wake-ups than the answer itself. Only
            // queries that wait for an upstream get their own task.
            match self.answer_locally(&query, client_addr) {
                LocalAnswer::Answered(resp) => send_udp_response(&socket, &query, resp, client_addr).await,
                LocalAnswer::Upstream(pending) => {
                    let server = self.clone();
                    let sock = socket.clone();
                    tokio::spawn(async move {
                        let resp = server.resolve_upstream(&query, pending).await;
                        send_udp_response(&sock, &query, resp, client_addr).await;
                    });
                }
            }
        }
    }

    /// Start TCP listener
    pub async fn run_tcp(self: Arc<Self>, addr: SocketAddr) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, "DNS TCP listener started");

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    error!("TCP accept error: {e}");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);

            let server = self.clone();
            tokio::spawn(async move {
                server.serve_stream(stream, client_addr, TCP_IDLE_TIMEOUT, "TCP").await;
            });
        }
    }

    /// Start DoT (DNS-over-TLS, port 853) listener
    pub async fn run_dot(
        self: Arc<Self>,
        addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let acceptor = TlsAcceptor::from(tls_config);
        info!(addr = %addr, "DNS DoT listener started (port 853)");

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    error!("DoT accept error: {e}");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);

            let server = self.clone();
            let acc = acceptor.clone();

            tokio::spawn(async move {
                let tls_stream = match timeout(IO_TIMEOUT, acc.accept(stream)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        debug!(client = %client_addr, error = %e, "DoT TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        debug!(client = %client_addr, "DoT TLS handshake timed out");
                        return;
                    }
                };

                server.serve_stream(tls_stream, client_addr, DOT_IDLE_TIMEOUT, "DoT").await;
            });
        }
    }

    /// Answers length-prefixed queries on a TCP or TLS stream (RFC 7766 / RFC 7858) until
    /// the client closes it, sends garbage, or stays idle for `idle_timeout`. Without the
    /// timeouts, clients that vanish without closing (NAT, mobile) would keep their task
    /// and buffers forever.
    async fn serve_stream<S>(&self, mut stream: S, client_addr: SocketAddr, idle_timeout: Duration, proto: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut msg_buf = Vec::new();
        loop {
            let mut len_buf = [0u8; 2];
            match timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                // Closed by the client, or idle
                _ => break,
            }

            msg_buf.resize(u16::from_be_bytes(len_buf) as usize, 0);
            match timeout(IO_TIMEOUT, stream.read_exact(&mut msg_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!(client = %client_addr, error = %e, "Failed to read {proto} DNS message");
                    break;
                }
                Err(_) => {
                    debug!(client = %client_addr, "Timed out reading {proto} DNS message");
                    break;
                }
            }

            let query = match Message::from_vec(&msg_buf) {
                Ok(m) => m,
                Err(e) => {
                    warn!(client = %client_addr, error = %e, "Invalid {proto} DNS packet");
                    break;
                }
            };

            let resp = self.process_query(&query, client_addr).await;
            let Some(framed) = frame_response(&resp, proto) else {
                break;
            };

            // One write for prefix and message: see `upstream::pool::frame`
            let written = timeout(IO_TIMEOUT, async {
                stream.write_all(&framed).await?;
                stream.flush().await
            })
            .await;
            if !matches!(written, Ok(Ok(()))) {
                debug!(client = %client_addr, "Failed to write {proto} DNS response");
                break;
            }
        }
    }
}

async fn send_udp_response(socket: &UdpSocket, query: &Message, resp: Message, client_addr: SocketAddr) {
    // Check max UDP payload size from EDNS (default 512 bytes)
    let max_udp_payload = query
        .edns
        .as_ref()
        .map(|e| e.max_payload() as usize)
        .unwrap_or(512);

    let mut resp_bytes = match resp.to_vec() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize DNS response: {e}");
            return;
        }
    };

    // Truncate if response exceeds client's max UDP buffer
    if resp_bytes.len() > max_udp_payload {
        let mut truncated_resp = resp;
        truncated_resp.metadata.truncation = true;
        truncated_resp.answers.clear();
        truncated_resp.authorities.clear();
        truncated_resp.additionals.clear();
        if let Ok(b) = truncated_resp.to_vec() {
            resp_bytes = b;
        }
    }

    if let Err(e) = socket.send_to(&resp_bytes, client_addr).await {
        warn!(client = %client_addr, error = %e, "Failed to send UDP response");
    }
}

/// Serializes a response with its 2-byte length prefix.
fn frame_response(resp: &Message, proto: &str) -> Option<Vec<u8>> {
    let bytes = match resp.to_vec() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize {proto} DNS response: {e}");
            return None;
        }
    };
    let Ok(len) = u16::try_from(bytes.len()) else {
        error!(len = bytes.len(), "{proto} DNS response exceeds 65535 bytes");
        return None;
    };
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&bytes);
    Some(framed)
}

/// Load TLS server configuration from PEM certificate and private key files
pub fn load_tls_server_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>, String> {
    let cert_file = File::open(cert_path)
        .map_err(|e| format!("Failed to open certificate file '{cert_path}': {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certificate chain from '{cert_path}': {e}"))?;

    if certs.is_empty() {
        return Err(format!("No certificates found in '{cert_path}'"));
    }

    let key_file = File::open(key_path)
        .map_err(|e| format!("Failed to open private key file '{key_path}': {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Failed to parse private key from '{key_path}': {e}"))?
        .ok_or_else(|| format!("No private key found in '{key_path}'"))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("Failed to configure safe TLS versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Invalid certificate/key pair: {e}"))?;

    Ok(Arc::new(server_config))
}
