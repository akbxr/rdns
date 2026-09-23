use crate::blocking::BlockEngine;
use crate::cache::DnsCache;
use crate::client::ClientMatcher;
use crate::config::{Config, QueryLogType};
use crate::custom_dns::CustomDnsManager;
use crate::metrics::Metrics;
use crate::query_log::QueryLogger;
use crate::upstream::UpstreamRegistry;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

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

impl DnsServer {
    pub fn new(ctx: Arc<ServerContext>) -> Self {
        Self { ctx }
    }

    /// Process a single DNS query through the complete pipeline
    pub async fn process_query(&self, query: &Message, client_addr: SocketAddr) -> Message {
        let start = Instant::now();

        let question = match query.queries.first() {
            Some(q) => q,
            None => {
                return Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::FormErr);
            }
        };

        let client_ip = client_addr.ip();
        let client_group = self.ctx.client_matcher.get_primary_group(client_ip);
        let qname_str = question.name.to_utf8();
        let domain = qname_str.trim().trim_end_matches('.').to_lowercase();
        let qtype_str = format!("{:?}", question.query_type);

        self.ctx.metrics.inc_query(client_group, &qtype_str);

        // 1. Check Custom DNS / Local Records
        if let Some(custom_resp) = self.ctx.custom_dns.resolve(query) {
            self.ctx.metrics.inc_custom_dns_hit();
            self.ctx.query_logger.record(client_ip, false);
            self.log_query(
                client_addr,
                client_group,
                &domain,
                &qtype_str,
                "CUSTOM_DNS",
                custom_resp.metadata.response_code,
                start.elapsed().as_secs_f64() * 1000.0,
            );
            return custom_resp;
        }

        // 2. Check Blocking Engine
        if let Some(reason) = self.ctx.block_engine.check_blocked(client_group, &domain) {
            self.ctx.metrics.inc_blocked(client_group, &reason.to_string());
            let blocked_resp = self.ctx.block_engine.build_blocked_response(query);
            self.ctx.query_logger.record(client_ip, true);
            self.log_query(
                client_addr,
                client_group,
                &domain,
                &qtype_str,
                &format!("BLOCKED ({reason})"),
                blocked_resp.metadata.response_code,
                start.elapsed().as_secs_f64() * 1000.0,
            );
            return blocked_resp;
        }
        self.ctx.query_logger.record(client_ip, false);

        // 3. Check Conditional Forwarding
        if let Some(cond_group) = self.ctx.upstream_registry.get_for_domain(&domain) {
            // Check cache first for conditional queries
            if let Some((cached_resp, _)) = self.ctx.cache.get(query) {
                self.ctx.metrics.inc_cache_hit();
                self.log_query(
                    client_addr,
                    client_group,
                    &domain,
                    &qtype_str,
                    "CACHE (CONDITIONAL)",
                    cached_resp.metadata.response_code,
                    start.elapsed().as_secs_f64() * 1000.0,
                );
                return cached_resp;
            }

            self.ctx.metrics.inc_cache_miss();
            self.ctx.metrics.inc_upstream_query(&cond_group.name);

            match cond_group.resolve(query).await {
                Ok(resp) => {
                    self.ctx.cache.put(query, &resp);
                    self.log_query(
                        client_addr,
                        client_group,
                        &domain,
                        &qtype_str,
                        &format!("CONDITIONAL ({})", cond_group.name),
                        resp.metadata.response_code,
                        start.elapsed().as_secs_f64() * 1000.0,
                    );
                    return resp;
                }
                Err(e) => {
                    self.ctx.metrics.inc_upstream_error(&cond_group.name);
                    warn!(error = %e, domain = %domain, "Conditional upstream resolution failed");
                    return Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail);
                }
            }
        }

        // 4. Check DNS Cache
        if let Some((cached_resp, needs_prefetch)) = self.ctx.cache.get(query) {
            self.ctx.metrics.inc_cache_hit();

            if needs_prefetch {
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

            self.log_query(
                client_addr,
                client_group,
                &domain,
                &qtype_str,
                "CACHE",
                cached_resp.metadata.response_code,
                start.elapsed().as_secs_f64() * 1000.0,
            );
            return cached_resp;
        }

        self.ctx.metrics.inc_cache_miss();

        // 5. Upstream Resolution
        let default_group = match self.ctx.upstream_registry.get_default_group() {
            Some(g) => g,
            None => {
                error!("No default upstream group configured");
                return Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail);
            }
        };

        self.ctx.metrics.inc_upstream_query(&default_group.name);

        match default_group.resolve(query).await {
            Ok(resp) => {
                self.ctx.cache.put(query, &resp);
                self.log_query(
                    client_addr,
                    client_group,
                    &domain,
                    &qtype_str,
                    &format!("UPSTREAM ({})", default_group.name),
                    resp.metadata.response_code,
                    start.elapsed().as_secs_f64() * 1000.0,
                );
                resp
            }
            Err(e) => {
                self.ctx.metrics.inc_upstream_error(&default_group.name);
                warn!(error = %e, domain = %domain, "Default upstream resolution failed");
                Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail)
            }
        }
    }

    fn log_query(
        &self,
        client: SocketAddr,
        client_group: &str,
        domain: &str,
        qtype: &str,
        status: &str,
        rcode: ResponseCode,
        duration_ms: f64,
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
            duration = %format!("{:.2}ms", duration_ms),
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

            let bytes = buf[..len].to_vec();
            let server = self.clone();
            let sock = socket.clone();

            tokio::spawn(async move {
                let query = match Message::from_vec(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(client = %client_addr, error = %e, "Invalid DNS UDP packet");
                        return;
                    }
                };

                let resp = server.process_query(&query, client_addr).await;

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
                    let mut truncated_resp = resp.clone();
                    truncated_resp.metadata.truncation = true;
                    truncated_resp.answers.clear();
                    truncated_resp.authorities.clear();
                    truncated_resp.additionals.clear();
                    if let Ok(b) = truncated_resp.to_vec() {
                        resp_bytes = b;
                    }
                }

                if let Err(e) = sock.send_to(&resp_bytes, client_addr).await {
                    warn!(client = %client_addr, error = %e, "Failed to send UDP response");
                }
            });
        }
    }

    /// Start TCP listener
    pub async fn run_tcp(self: Arc<Self>, addr: SocketAddr) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, "DNS TCP listener started");

        loop {
            let (mut stream, client_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    error!("TCP accept error: {e}");
                    continue;
                }
            };

            let server = self.clone();

            tokio::spawn(async move {
                // Read 2-byte length prefix
                let mut len_buf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    debug!(client = %client_addr, error = %e, "TCP connection closed early");
                    return;
                }

                let msg_len = u16::from_be_bytes(len_buf) as usize;
                let mut msg_buf = vec![0u8; msg_len];
                if let Err(e) = stream.read_exact(&mut msg_buf).await {
                    warn!(client = %client_addr, error = %e, "Failed to read TCP DNS message");
                    return;
                }

                let query = match Message::from_vec(&msg_buf) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(client = %client_addr, error = %e, "Invalid TCP DNS packet");
                        return;
                    }
                };

                let resp = server.process_query(&query, client_addr).await;

                let resp_bytes = match resp.to_vec() {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to serialize TCP DNS response: {e}");
                        return;
                    }
                };

                let resp_len_prefix = (resp_bytes.len() as u16).to_be_bytes();
                if let Err(e) = stream.write_all(&resp_len_prefix).await {
                    warn!(client = %client_addr, error = %e, "Failed to write TCP length prefix");
                    return;
                }
                if let Err(e) = stream.write_all(&resp_bytes).await {
                    warn!(client = %client_addr, error = %e, "Failed to write TCP response body");
                    return;
                }
                let _ = stream.flush().await;
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

            let server = self.clone();
            let acc = acceptor.clone();

            tokio::spawn(async move {
                let mut tls_stream = match acc.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(client = %client_addr, error = %e, "DoT TLS handshake failed");
                        return;
                    }
                };

                // Handle multiple queries over the same TLS connection (connection reuse)
                loop {
                    let mut len_buf = [0u8; 2];
                    if let Err(_) = tls_stream.read_exact(&mut len_buf).await {
                        break;
                    }

                    let msg_len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg_buf = vec![0u8; msg_len];
                    if let Err(e) = tls_stream.read_exact(&mut msg_buf).await {
                        warn!(client = %client_addr, error = %e, "Failed to read DoT query body");
                        break;
                    }

                    let query = match Message::from_vec(&msg_buf) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!(client = %client_addr, error = %e, "Invalid DoT DNS packet");
                            break;
                        }
                    };

                    let resp = server.process_query(&query, client_addr).await;

                    let resp_bytes = match resp.to_vec() {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to serialize DoT DNS response: {e}");
                            break;
                        }
                    };

                    let resp_len_prefix = (resp_bytes.len() as u16).to_be_bytes();
                    if let Err(_) = tls_stream.write_all(&resp_len_prefix).await {
                        break;
                    }
                    if let Err(_) = tls_stream.write_all(&resp_bytes).await {
                        break;
                    }
                    if let Err(_) = tls_stream.flush().await {
                        break;
                    }
                }
            });
        }
    }
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
