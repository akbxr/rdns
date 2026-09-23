use axum::body::Body;
use axum::http::{Request, StatusCode};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use rdns::api::create_router;
use rdns::blocking::{BlockEngine, ParsedList};
use rdns::cache::DnsCache;
use rdns::client::ClientMatcher;
use rdns::config::{BlockType, BlockingConfig, CachingConfig, ClientLookupConfig, Config, CustomDnsConfig};
use rdns::custom_dns::CustomDnsManager;
use rdns::metrics::Metrics;
use rdns::server::{DnsServer, ServerContext};
use rdns::upstream::UpstreamRegistry;
use regex::Regex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tower::ServiceExt;

async fn setup_test_server() -> (Arc<ServerContext>, Arc<DnsServer>) {
    let mut config = Config::default();

    // Blocking setup
    let mut blocking_cfg = BlockingConfig::default();
    blocking_cfg.block_type = BlockType::ZeroIp;
    blocking_cfg.block_ttl = Duration::from_secs(3600);
    let mut client_groups = HashMap::new();
    client_groups.insert("default".to_string(), vec!["ads".to_string()]);
    client_groups.insert("kids".to_string(), vec!["ads".to_string(), "gambling".to_string()]);
    blocking_cfg.client_groups = client_groups;

    // Custom DNS setup
    let mut custom_cfg = CustomDnsConfig::default();
    custom_cfg.custom_ttl = Duration::from_secs(300);
    custom_cfg.mapping.insert(
        "myrouter.local".to_string(),
        vec!["192.168.1.1".to_string(), "fd00::1".to_string()],
    );
    custom_cfg.mapping.insert(
        "alias.local".to_string(),
        vec!["myrouter.local".to_string()],
    );

    // Client lookup setup
    let mut client_cfg = ClientLookupConfig::default();
    client_cfg
        .clients
        .insert("192.168.1.100".to_string(), vec!["kids".to_string()]);
    client_cfg
        .clients
        .insert("192.168.1.0/24".to_string(), vec!["default".to_string()]);

    // Caching setup
    let mut caching_cfg = CachingConfig::default();
    caching_cfg.min_ttl = Duration::from_secs(60);
    caching_cfg.max_ttl = Duration::from_secs(3600);

    config.blocking = blocking_cfg.clone();
    config.custom_dns = custom_cfg.clone();
    config.client_lookup = client_cfg.clone();
    config.caching = caching_cfg.clone();

    let _block_engine = Arc::new(BlockEngine::new(blocking_cfg));
    // Populate some sample blocklist and whitelist entries
    {
        // We use reload simulation by injecting into the engine
        // Create sample lists
        let mut ads_list = ParsedList::new();
        ads_list.domains.insert("doubleclick.net".to_string());
        ads_list.domains.insert("badtracker.com".to_string());
        ads_list
            .regexes
            .push(Regex::new(r"^ad[0-9]*\.example\.com$").unwrap());

        let mut gambling_list = ParsedList::new();
        gambling_list.domains.insert("betonline.com".to_string());

        let mut whitelist = ParsedList::new();
        whitelist.domains.insert("whitelist.badtracker.com".to_string());

        // We can test check_blocked directly or through the engine
        // Load via engine's config
        let mut config_block = config.blocking.clone();
        config_block
            .whitelists
            .insert("ads".to_string(), vec!["whitelist.badtracker.com".to_string()]);
        config_block.blacklists.insert(
            "ads".to_string(),
            vec![
                "doubleclick.net".to_string(),
                "badtracker.com".to_string(),
                "/^ad[0-9]*\\.example\\.com$/".to_string(),
            ],
        );
        config_block
            .blacklists
            .insert("gambling".to_string(), vec!["betonline.com".to_string()]);

        let populated_engine = Arc::new(BlockEngine::new(config_block));
        populated_engine.reload().await.unwrap();

        let cache = Arc::new(DnsCache::new(caching_cfg));
        let custom_dns = Arc::new(CustomDnsManager::from_config(&custom_cfg));
        let upstream_registry = Arc::new(
            UpstreamRegistry::from_config(&config.upstreams, &config.conditional.mapping).unwrap(),
        );
        let client_matcher = Arc::new(ClientMatcher::from_config(&client_cfg));
        let metrics = Arc::new(Metrics::new());

        let query_logger = Arc::new(rdns::query_log::QueryLogger::new(config.query_log.clone()));
        let ctx = Arc::new(ServerContext {
            config: Arc::new(config),
            block_engine: populated_engine,
            cache,
            custom_dns,
            upstream_registry,
            client_matcher,
            metrics,
            query_logger,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        });
        let server = Arc::new(DnsServer::new(ctx.clone()));
        (ctx, server)
    }
}

#[tokio::test]
async fn test_pipeline_custom_dns() {
    let (_, server) = setup_test_server().await;
    let client_addr: SocketAddr = "192.168.1.50:12345".parse().unwrap();

    // Query custom A record
    let mut query = Message::new(101, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.name = "myrouter.local.".parse().unwrap();
    q.query_type = RecordType::A;
    query.queries.push(q);

    let resp = server.process_query(&query, client_addr).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].data {
        RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 1)),
        other => panic!("Unexpected rdata: {:?}", other),
    }

    // Query custom CNAME alias
    let mut query_cname = Message::new(102, MessageType::Query, OpCode::Query);
    let mut q_cname = Query::new();
    q_cname.name = "alias.local.".parse().unwrap();
    q_cname.query_type = RecordType::A;
    query_cname.queries.push(q_cname);

    let resp_cname = server.process_query(&query_cname, client_addr).await;
    assert_eq!(resp_cname.metadata.response_code, ResponseCode::NoError);
    assert!(resp_cname.answers.len() >= 2); // CNAME + target A record
}

#[tokio::test]
async fn test_pipeline_blocking_and_whitelisting() {
    let (ctx, server) = setup_test_server().await;
    let client_default: SocketAddr = "192.168.1.50:12345".parse().unwrap();
    let _client_kids: SocketAddr = "192.168.1.100:12345".parse().unwrap();

    // 1. Exact match blocked on default client
    let mut q1 = Message::new(201, MessageType::Query, OpCode::Query);
    let mut query1 = Query::new();
    query1.name = "doubleclick.net.".parse().unwrap();
    query1.query_type = RecordType::A;
    q1.queries.push(query1);

    let resp1 = server.process_query(&q1, client_default).await;
    assert_eq!(resp1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp1.answers.len(), 1);
    match &resp1.answers[0].data {
        RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(0, 0, 0, 0)),
        other => panic!("Expected 0.0.0.0, got: {:?}", other),
    }

    // 2. Subdomain wildcard match blocked: sub.ad.doubleclick.net
    let mut q2 = Message::new(202, MessageType::Query, OpCode::Query);
    let mut query2 = Query::new();
    query2.name = "sub.ad.doubleclick.net.".parse().unwrap();
    query2.query_type = RecordType::A;
    q2.queries.push(query2);

    let resp2 = server.process_query(&q2, client_default).await;
    assert_eq!(resp2.answers.len(), 1);
    match &resp2.answers[0].data {
        RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(0, 0, 0, 0)),
        other => panic!("Expected 0.0.0.0, got: {:?}", other),
    }

    // 3. Regex match blocked: ad123.example.com
    let mut q3 = Message::new(203, MessageType::Query, OpCode::Query);
    let mut query3 = Query::new();
    query3.name = "ad123.example.com.".parse().unwrap();
    query3.query_type = RecordType::A;
    q3.queries.push(query3);

    let resp3 = server.process_query(&q3, client_default).await;
    assert_eq!(resp3.answers.len(), 1);
    match &resp3.answers[0].data {
        RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(0, 0, 0, 0)),
        other => panic!("Expected 0.0.0.0, got: {:?}", other),
    }

    // 4. Whitelist override: whitelist.badtracker.com should NOT be blocked
    let mut q4 = Message::new(204, MessageType::Query, OpCode::Query);
    let mut query4 = Query::new();
    query4.name = "whitelist.badtracker.com.".parse().unwrap();
    query4.query_type = RecordType::A;
    q4.queries.push(query4);

    // Should bypass blocking engine
    let block_check = ctx.block_engine.check_blocked("default", "whitelist.badtracker.com");
    assert!(block_check.is_none());

    // 5. Client group differentiation: "betonline.com" is in gambling list
    // Should NOT be blocked for default client
    let block_default = ctx.block_engine.check_blocked("default", "betonline.com");
    assert!(block_default.is_none());

    // Should be blocked for kids client (192.168.1.100)
    let block_kids = ctx.block_engine.check_blocked("kids", "betonline.com");
    assert!(block_kids.is_some());

    // 6. Disable blocking temporarily via API
    ctx.block_engine.disable_for(Duration::from_secs(60));
    let block_disabled = ctx.block_engine.check_blocked("default", "doubleclick.net");
    assert!(block_disabled.is_none());

    // Re-enable
    ctx.block_engine.enable();
    let block_re_enabled = ctx.block_engine.check_blocked("default", "doubleclick.net");
    assert!(block_re_enabled.is_some());
}

#[tokio::test]
async fn test_pipeline_caching() {
    let (ctx, server) = setup_test_server().await;
    let client_addr: SocketAddr = "192.168.1.50:12345".parse().unwrap();

    let mut query = Message::new(301, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.name = "cached-domain.com.".parse().unwrap();
    q.query_type = RecordType::A;
    q.query_class = DNSClass::IN;
    query.queries.push(q);

    // Prime cache with a response
    let mut resp = Message::new(301, MessageType::Response, OpCode::Query);
    resp.queries = query.queries.clone();
    resp.add_answer(Record::from_rdata(
        "cached-domain.com.".parse().unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
    ));
    ctx.cache.put(&query, &resp);

    // Query through server
    let cached_result = server.process_query(&query, client_addr).await;
    assert_eq!(cached_result.answers.len(), 1);
    match &cached_result.answers[0].data {
        RData::A(A(ip)) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
        other => panic!("Unexpected rdata: {:?}", other),
    }

    let (hits, _, _, _, _) = ctx.cache.get_stats_summary();
    assert_eq!(hits, 1);
}

#[tokio::test]
async fn test_live_udp_and_tcp_dns_listeners() {
    let (ctx, server) = setup_test_server().await;

    // Bind UDP listener on ephemeral port
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp_socket.local_addr().unwrap();
    drop(udp_socket); // release port for server

    let srv_udp = server.clone();
    tokio::spawn(async move {
        let _ = srv_udp.run_udp(udp_addr).await;
    });

    // Bind TCP listener on ephemeral port
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    drop(tcp_listener); // release port for server

    let srv_tcp = server.clone();
    tokio::spawn(async move {
        let _ = srv_tcp.run_tcp(tcp_addr).await;
    });

    // Allow servers a moment to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test UDP client
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut query = Message::new(555, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.name = "myrouter.local.".parse().unwrap();
    q.query_type = RecordType::A;
    query.queries.push(q);

    let query_bytes = query.to_vec().unwrap();
    client_udp.send_to(&query_bytes, udp_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut buf))
        .await
        .expect("UDP query timed out")
        .unwrap();

    let resp = Message::from_vec(&buf[..len]).unwrap();
    assert_eq!(resp.metadata.id, 555);
    assert_eq!(resp.answers.len(), 1);

    // Test TCP client
    let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
    let len_prefix = (query_bytes.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await.unwrap();
    stream.write_all(&query_bytes).await.unwrap();
    stream.flush().await.unwrap();

    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let tcp_resp = Message::from_vec(&resp_buf).unwrap();
    assert_eq!(tcp_resp.metadata.id, 555);
    assert_eq!(tcp_resp.answers.len(), 1);

    // Test HTTP API router
    let app = create_router(ctx);
    let res = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_live_dot_listener() {
    let (_, server) = setup_test_server().await;

    // Generate self-signed certificate for localhost/127.0.0.1
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert_key = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_pem = cert_key.cert.pem();
    let key_pem = cert_key.signing_key.serialize_pem();

    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let tls_config = rdns::server::load_tls_server_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
    )
    .expect("Failed to load TLS server config");

    let dot_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dot_addr = dot_listener.local_addr().unwrap();
    drop(dot_listener);

    let srv_dot = server.clone();
    tokio::spawn(async move {
        let _ = srv_dot.run_dot(dot_addr, tls_config).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Build client config that trusts the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    let mut cert_reader = std::io::BufReader::new(std::fs::File::open(&cert_path).unwrap());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }

    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let tcp_stream = TcpStream::connect(dot_addr).await.unwrap();
    let sni = rustls_pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(sni, tcp_stream).await.unwrap();

    // Send DNS query over TLS
    let mut query = Message::new(777, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.name = "myrouter.local.".parse().unwrap();
    q.query_type = RecordType::A;
    query.queries.push(q);
    let query_bytes = query.to_vec().unwrap();

    let len_prefix = (query_bytes.len() as u16).to_be_bytes();
    tls_stream.write_all(&len_prefix).await.unwrap();
    tls_stream.write_all(&query_bytes).await.unwrap();
    tls_stream.flush().await.unwrap();

    let mut resp_len_buf = [0u8; 2];
    tls_stream.read_exact(&mut resp_len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    tls_stream.read_exact(&mut resp_buf).await.unwrap();

    let resp = Message::from_vec(&resp_buf).unwrap();
    assert_eq!(resp.metadata.id, 777);
    assert_eq!(resp.answers.len(), 1);
}
