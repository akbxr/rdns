use crate::config::parse_duration;
use crate::server::{DnsServer, ServerContext};
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_TYPE, HeaderMap};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use hickory_proto::op::Message;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::info;

pub fn create_router(ctx: Arc<ServerContext>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/health", get(health_handler))
        .route(
            "/dns-query",
            get(doh_get_handler).post(doh_post_handler),
        )
        .route("/api/blocking/status", get(blocking_status_handler))
        .route(
            "/api/blocking/disable",
            get(blocking_disable_handler).post(blocking_disable_handler),
        )
        .route(
            "/api/blocking/enable",
            get(blocking_enable_handler).post(blocking_enable_handler),
        )
        .route(
            "/api/blocking/refresh",
            get(blocking_refresh_handler).post(blocking_refresh_handler),
        )
        .route("/api/cache/stats", get(cache_stats_handler))
        .route(
            "/api/cache/clear",
            get(cache_clear_handler).post(cache_clear_handler),
        )
        .route("/api/querylog/summary", get(querylog_summary_handler))
        .route(
            "/api/querylog/flush",
            get(querylog_flush_handler).post(querylog_flush_handler),
        )
        .route(
            "/api/shutdown",
            get(shutdown_handler).post(shutdown_handler),
        )
        .route("/metrics", get(metrics_handler))
        .with_state(ctx)
}

pub async fn run_http_server(ctx: Arc<ServerContext>, addr: SocketAddr) -> Result<(), std::io::Error> {
    let app = create_router(ctx);
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP API & DoH server started (endpoint: /dns-query)");
    axum::serve(listener, app).await
}
pub async fn run_https_server(
    ctx: Arc<ServerContext>,
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_router(ctx);
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
    info!(addr = %addr, "HTTPS DoH server started (port 443, endpoint: /dns-query)");
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}


async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// RFC 8484 DoH POST handler
async fn doh_post_handler(
    State(ctx): State<Arc<ServerContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let client_addr = extract_client_addr(&headers);

    let query = Message::from_vec(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DNS wire query: {e}")))?;

    let server = DnsServer::new(ctx);
    let resp = server.process_query(&query, client_addr).await;

    let resp_bytes = resp
        .to_vec()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize response: {e}")))?;

    let min_ttl = resp
        .answers
        .iter()
        .map(|r| r.ttl)
        .min()
        .unwrap_or(60);

    Ok((
        [
            (CONTENT_TYPE, "application/dns-message"),
            (
                axum::http::header::CACHE_CONTROL,
                &format!("max-age={min_ttl}")[..],
            ),
        ],
        resp_bytes,
    )
        .into_response())
}

/// RFC 8484 DoH GET handler (?dns=<base64url>)
async fn doh_get_handler(
    State(ctx): State<Arc<ServerContext>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    let dns_b64 = params.get("dns").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Missing 'dns' query parameter containing base64url encoded DNS query".to_string(),
        )
    })?;

    // Try decoding base64url without padding first, then with padding
    let raw_bytes = URL_SAFE_NO_PAD
        .decode(dns_b64)
        .or_else(|_| URL_SAFE.decode(dns_b64))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64url encoding: {e}")))?;

    let client_addr = extract_client_addr(&headers);

    let query = Message::from_vec(&raw_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DNS wire query: {e}")))?;

    let server = DnsServer::new(ctx);
    let resp = server.process_query(&query, client_addr).await;

    let resp_bytes = resp
        .to_vec()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize response: {e}")))?;

    let min_ttl = resp
        .answers
        .iter()
        .map(|r| r.ttl)
        .min()
        .unwrap_or(60);

    Ok((
        [
            (CONTENT_TYPE, "application/dns-message"),
            (
                axum::http::header::CACHE_CONTROL,
                &format!("max-age={min_ttl}")[..],
            ),
        ],
        resp_bytes,
    )
        .into_response())
}

fn extract_client_addr(headers: &HeaderMap) -> SocketAddr {
    // Check X-Forwarded-For or X-Real-IP if running behind reverse proxy
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        if let Some(first_ip) = forwarded.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse() {
                return SocketAddr::new(ip, 0);
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse() {
            return SocketAddr::new(ip, 0);
        }
    }

    "127.0.0.1:0".parse().unwrap()
}

async fn blocking_status_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    let (enabled, remaining_disabled, total_rules) = ctx.block_engine.get_status();
    Json(json!({
        "enabled": enabled,
        "disabled_remaining_secs": remaining_disabled.map(|d| d.as_secs()),
        "total_rules": total_rules
    }))
}

async fn blocking_disable_handler(
    State(ctx): State<Arc<ServerContext>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let duration_str = params.get("duration").map(|s| s.as_str()).unwrap_or("0");
    let duration = parse_duration(duration_str).unwrap_or(Duration::from_secs(0));

    ctx.block_engine.disable_for(duration);

    Json(json!({
        "status": "disabled",
        "duration": duration_str,
        "duration_secs": duration.as_secs()
    }))
}

async fn blocking_enable_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    ctx.block_engine.enable();
    Json(json!({
        "status": "enabled"
    }))
}

async fn blocking_refresh_handler(
    State(ctx): State<Arc<ServerContext>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match ctx.block_engine.reload().await {
        Ok(()) => {
            let (_, _, total_rules) = ctx.block_engine.get_status();
            Ok(Json(json!({
                "status": "refreshed",
                "total_rules": total_rules
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to refresh blocklists: {e}"),
        )),
    }
}

async fn cache_stats_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    let (hits, misses, evictions, count, hit_ratio) = ctx.cache.get_stats_summary();
    Json(json!({
        "hits": hits,
        "misses": misses,
        "evictions": evictions,
        "entries": count,
        "hit_ratio": hit_ratio
    }))
}

async fn cache_clear_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    ctx.cache.clear();
    Json(json!({
        "status": "cleared"
    }))
}
async fn querylog_summary_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    let summary = ctx.query_logger.get_summary();
    Json(json!({
        "enabled": ctx.query_logger.is_csv_enabled(),
        "entries": summary
    }))
}

async fn querylog_flush_handler(
    State(ctx): State<Arc<ServerContext>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ctx.query_logger
        .flush_to_disk()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to flush query log: {e}")))?;
    Ok(Json(json!({
        "status": "flushed"
    })))
}
async fn shutdown_handler(State(ctx): State<Arc<ServerContext>>) -> Json<serde_json::Value> {
    ctx.shutdown_notify.notify_one();
    Json(json!({ "status": "shutting_down" }))
}


async fn metrics_handler(State(ctx): State<Arc<ServerContext>>) -> Response {
    let (_, _, total_rules) = ctx.block_engine.get_status();
    let cache_entries = ctx.cache.len();
    let body = ctx.metrics.render_prometheus(total_rules, cache_entries);

    (
        [(
            CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocking::BlockEngine;
    use crate::cache::DnsCache;
    use crate::client::ClientMatcher;
    use crate::config::Config;
    use crate::custom_dns::CustomDnsManager;
    use crate::metrics::Metrics;
    use crate::upstream::UpstreamRegistry;
    use axum::body::Body;
    use axum::http::Request;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_api_endpoints() {
        let mut config = Config::default();
        config.custom_dns.mapping.insert(
            "router.local".to_string(),
            vec!["192.168.1.1".to_string()],
        );

        let config = Arc::new(config);
        let block_engine = Arc::new(BlockEngine::new(config.blocking.clone()));
        let cache = Arc::new(DnsCache::new(config.caching.clone()));
        let custom_dns = Arc::new(CustomDnsManager::from_config(&config.custom_dns));
        let upstream_registry = Arc::new(
            UpstreamRegistry::from_config(&config.upstreams, &config.conditional.mapping).unwrap(),
        );
        let client_matcher = Arc::new(ClientMatcher::from_config(&config.client_lookup));
        let metrics = Arc::new(Metrics::new());
        let query_logger = Arc::new(crate::query_log::QueryLogger::new(config.query_log.clone()));

        let ctx = Arc::new(ServerContext {
            config,
            block_engine,
            cache,
            custom_dns,
            upstream_registry,
            client_matcher,
            metrics,
            query_logger,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        });

        let app = create_router(ctx);

        // Test /health
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test DoH POST /dns-query
        let mut query = Message::new(1234, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = "router.local.".parse().unwrap();
        q.query_type = RecordType::A;
        query.queries.push(q);
        let wire_query = query.to_vec().unwrap();

        let doh_post_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/dns-query")
                    .header("content-type", "application/dns-message")
                    .body(Body::from(wire_query.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(doh_post_response.status(), StatusCode::OK);
        assert_eq!(
            doh_post_response.headers().get("content-type").unwrap(),
            "application/dns-message"
        );

        // Test DoH GET /dns-query?dns=<base64url>
        let b64 = URL_SAFE_NO_PAD.encode(&wire_query);
        let doh_get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/dns-query?dns={b64}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(doh_get_response.status(), StatusCode::OK);
        assert_eq!(
            doh_get_response.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
    }
}
