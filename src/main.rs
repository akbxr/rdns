use clap::{Parser, Subcommand};
use rdns::api::run_http_server;
use rdns::blocking::BlockEngine;
use rdns::cache::DnsCache;
use rdns::client::ClientMatcher;
use rdns::config::Config;
use rdns::custom_dns::CustomDnsManager;
use rdns::metrics::Metrics;
use rdns::server::{DnsServer, ServerContext};
use rdns::upstream::UpstreamRegistry;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rdns", author = "akbar", version = "0.1.0")]
#[command(about = "Fast, lightweight DNS proxy and ad-blocker written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the DNS server and HTTP API (default)
    Start {
        /// Path to YAML configuration file
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
    },
    /// Validate configuration file syntax
    Check {
        /// Path to YAML configuration file
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
    },
    /// Interact with blocking engine of a running rdns server
    Blocking {
        #[command(subcommand)]
        action: BlockingAction,
        /// HTTP API base URL
        #[arg(long, default_value = "http://127.0.0.1:4000")]
        api: String,
    },
    /// Interact with DNS cache of a running rdns server
    Cache {
        #[command(subcommand)]
        action: CacheAction,
        /// HTTP API base URL
        #[arg(long, default_value = "http://127.0.0.1:4000")]
        api: String,
    },
    /// Fetch metrics from a running rdns server
    Metrics {
        /// HTTP API base URL
        #[arg(long, default_value = "http://127.0.0.1:4000")]
        api: String,
    },
    /// Query daily per-client query statistics (privacy-focused aggregated log)
    Querylog {
        #[command(subcommand)]
        action: Option<QuerylogAction>,
        /// HTTP API base URL
        #[arg(long, default_value = "http://127.0.0.1:4000")]
        api: String,
    },
    /// Stop a running rdns server
    Stop {
        /// HTTP API base URL
        #[arg(long, default_value = "http://127.0.0.1:4000")]
        api: String,
    },
    /// Uninstall rdns binary from system
    Uninstall {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum BlockingAction {
    /// Show blocking status and active rule count
    Status,
    /// Temporarily disable blocking
    Disable {
        /// Duration to disable blocking (e.g. 5m, 1h, 30s, or 0 for indefinitely)
        #[arg(short, long, default_value = "5m")]
        duration: String,
    },
    /// Re-enable blocking
    Enable,
    /// Refresh all blocklists and whitelists immediately
    Refresh,
}

#[derive(Subcommand, Debug)]
enum CacheAction {
    /// Show cache statistics (hits, misses, entries, hit ratio)
    Stats,
    /// Clear the DNS cache
    Clear,
}
#[derive(Subcommand, Debug)]
enum QuerylogAction {
    /// Show daily aggregated query counts per client
    Summary,
    /// Force flush in-memory query counts to CSV disk files
    Flush,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            run_server(cli.config).await?;
        }
        Some(Commands::Start { config }) => {
            run_server(config).await?;
        }
        Some(Commands::Check { config }) => {
            check_config(config).await?;
        }
        Some(Commands::Blocking { action, api }) => {
            handle_blocking_cmd(action, api).await?;
        }
        Some(Commands::Cache { action, api }) => {
            handle_cache_cmd(action, api).await?;
        }
        Some(Commands::Metrics { api }) => {
            handle_metrics_cmd(api).await?;
        }
        Some(Commands::Querylog { action, api }) => {
            handle_querylog_cmd(action, api).await?;
        }
        Some(Commands::Stop { api }) => {
            handle_stop_cmd(api).await?;
        }
        Some(Commands::Uninstall { yes }) => {
            handle_uninstall_cmd(yes).await?;
        }
    }

    Ok(())
}

async fn run_server(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("Starting rdns v0.1.0...");

    let config = if config_path.exists() {
        info!("Loading configuration from {:?}", config_path);
        Config::load_from_file(&config_path)?
    } else {
        info!(
            "Configuration file {:?} not found, using default configuration",
            config_path
        );
        Config::default()
    };

    let block_engine = Arc::new(BlockEngine::new(config.blocking.clone()));
    let cache = Arc::new(DnsCache::new(config.caching.clone()));
    let custom_dns = Arc::new(CustomDnsManager::from_config(&config.custom_dns));
    let upstream_registry = Arc::new(
        UpstreamRegistry::from_config(&config.upstreams, &config.conditional.mapping)
            .map_err(|e| format!("Upstream configuration error: {e}"))?,
    );
    let client_matcher = Arc::new(ClientMatcher::from_config(&config.client_lookup));
    let metrics = Arc::new(Metrics::new());
    let config_arc = Arc::new(config.clone());
    let query_logger = Arc::new(rdns::query_log::QueryLogger::new(config.query_log.clone()));
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let ctx = Arc::new(ServerContext {
        config: config_arc.clone(),
        block_engine: block_engine.clone(),
        cache: cache.clone(),
        custom_dns: custom_dns.clone(),
        upstream_registry: upstream_registry.clone(),
        client_matcher: client_matcher.clone(),
        metrics: metrics.clone(),
        query_logger: query_logger.clone(),
        shutdown_notify: shutdown_notify.clone(),
    });

    let pid_path = std::path::Path::new("/tmp/rdns.pid");
    let _ = std::fs::write(pid_path, std::process::id().to_string());

    // Load initial blocklists
    if config.blocking.enabled {
        let engine_clone = block_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = engine_clone.reload().await {
                error!("Initial blocklist load failed: {e}");
            }
        });

        // Start periodic refresh task
        block_engine
            .clone()
            .start_refresh_task(config.blocking.refresh_period);
    }
    // Start periodic query log CSV flush task
    if query_logger.is_csv_enabled() {
        query_logger
            .clone()
            .start_flush_task(config.query_log.flush_interval);
        info!(
            dir = %config.query_log.target_dir,
            "CSV client query logger started (privacy-focused daily aggregations)"
        );
    }

    let dns_server = Arc::new(DnsServer::new(ctx.clone()));

    // Start UDP DNS server
    if let Some(dns_addr) = config.ports.dns {
        let srv = dns_server.clone();
        tokio::spawn(async move {
            if let Err(e) = srv.run_udp(dns_addr).await {
                error!("UDP server error on {dns_addr}: {e}");
            }
        });

        // Start TCP DNS server
        let srv = dns_server.clone();
        tokio::spawn(async move {
            if let Err(e) = srv.run_tcp(dns_addr).await {
                error!("TCP server error on {dns_addr}: {e}");
            }
        });
    }
    // Start DoT DNS server if configured
    if let Some(dot_addr) = config.ports.dot {
        match (&config.tls.cert, &config.tls.key) {
            (Some(cert_path), Some(key_path)) => {
                match rdns::server::load_tls_server_config(cert_path, key_path) {
                    Ok(tls_config) => {
                        let srv = dns_server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = srv.run_dot(dot_addr, tls_config).await {
                                error!("DoT server error on {dot_addr}: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to load TLS config for DoT: {e}");
                    }
                }
            }
            _ => {
                error!("ports.dot is configured ({dot_addr}), but tls.cert or tls.key is missing in config");
            }
        }
    }

    // Start HTTP API server
    if let Some(http_addr) = config.ports.http {
        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_http_server(ctx_clone, http_addr).await {
                error!("HTTP server error on {http_addr}: {e}");
            }
        });
    }
    // Start HTTPS DoH server if configured
    if let Some(https_addr) = config.ports.https {
        match (&config.tls.cert, &config.tls.key) {
            (Some(cert_path), Some(key_path)) => {
                let ctx_clone = ctx.clone();
                let cert_p = cert_path.clone();
                let key_p = key_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = rdns::api::run_https_server(ctx_clone, https_addr, &cert_p, &key_p).await {
                        error!("HTTPS server error on {https_addr}: {e}");
                    }
                });
            }
            _ => {
                error!("ports.https is configured ({https_addr}), but tls.cert or tls.key is missing in config");
            }
        }
    }

    info!("rdns is ready and listening for queries.");

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C shutdown signal...");
        }
        _ = shutdown_notify.notified() => {
            info!("Received shutdown signal from API...");
        }
    }

    info!("Shutting down rdns gracefully...");
    let _ = query_logger.flush_to_disk();
    let _ = std::fs::remove_file(pid_path);
    info!("rdns server stopped.");
    Ok(())
}

async fn check_config(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Checking configuration file: {:?}", config_path);
    let config = Config::load_from_file(&config_path)?;

    println!("✓ Configuration syntax is valid!");
    println!("  - DNS Port: {:?}", config.ports.dns);
    println!("  - HTTP Port: {:?}", config.ports.http);
    println!("  - HTTPS (DoH) Port: {:?}", config.ports.https);
    println!("  - DoT Port: {:?}", config.ports.dot);
    if config.ports.dot.is_some() {
        println!("    * TLS Cert: {:?}", config.tls.cert);
        println!("    * TLS Key: {:?}", config.tls.key);
    }
    println!("  - Upstream Groups: {}", config.upstreams.groups.len());
    for (name, upstreams) in &config.upstreams.groups {
        println!("    * Group '{name}': {} upstream(s)", upstreams.len());
    }
    println!("  - Upstream Strategy: {:?}", config.upstreams.strategy);
    println!("  - Blacklist Categories: {}", config.blocking.blacklists.len());
    println!("  - Whitelist Categories: {}", config.blocking.whitelists.len());
    println!("  - Client Groups: {}", config.blocking.client_groups.len());
    println!("  - Custom DNS Mappings: {}", config.custom_dns.mapping.len());
    println!("  - Conditional Mappings: {}", config.conditional.mapping.len());
    println!("  - Caching Enabled: {}", config.caching.enabled);

    Ok(())
}

async fn handle_blocking_cmd(
    action: BlockingAction,
    api_url: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let api_url = api_url.trim_end_matches('/');

    match action {
        BlockingAction::Status => {
            let res = client
                .get(format!("{api_url}/api/blocking/status"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
        BlockingAction::Disable { duration } => {
            let res = client
                .get(format!("{api_url}/api/blocking/disable?duration={duration}"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
        BlockingAction::Enable => {
            let res = client
                .get(format!("{api_url}/api/blocking/enable"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
        BlockingAction::Refresh => {
            println!("Triggering blocklist refresh on {api_url}...");
            let res = client
                .post(format!("{api_url}/api/blocking/refresh"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
    }

    Ok(())
}

async fn handle_cache_cmd(
    action: CacheAction,
    api_url: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let api_url = api_url.trim_end_matches('/');

    match action {
        CacheAction::Stats => {
            let res = client
                .get(format!("{api_url}/api/cache/stats"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
        CacheAction::Clear => {
            let res = client
                .post(format!("{api_url}/api/cache/clear"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
    }

    Ok(())
}

async fn handle_metrics_cmd(api_url: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let api_url = api_url.trim_end_matches('/');
    let res = client
        .get(format!("{api_url}/metrics"))
        .send()
        .await?
        .text()
        .await?;
    println!("{res}");
    Ok(())
}
async fn handle_querylog_cmd(
    action: Option<QuerylogAction>,
    api_url: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let api_url = api_url.trim_end_matches('/');

    match action.unwrap_or(QuerylogAction::Summary) {
        QuerylogAction::Summary => {
            let res = client
                .get(format!("{api_url}/api/querylog/summary"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
        QuerylogAction::Flush => {
            let res = client
                .post(format!("{api_url}/api/querylog/flush"))
                .send()
                .await?
                .text()
                .await?;
            println!("{res}");
        }
    }

    Ok(())
}
async fn handle_stop_cmd(api_url: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let api_url = api_url.trim_end_matches('/');

    // 1. Try stopping via HTTP API
    if let Ok(resp) = client.post(format!("{api_url}/api/shutdown")).send().await {
        if resp.status().is_success() {
            println!("✓ rdns server stopped gracefully via API.");
            return Ok(());
        }
    }

    // 2. Fallback: check PID file
    let pid_file = std::path::Path::new("/tmp/rdns.pid");
    if pid_file.exists() {
        if let Ok(content) = std::fs::read_to_string(pid_file) {
            let pid_str = content.trim();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let is_alive = std::process::Command::new("kill")
                    .arg("-0")
                    .arg(pid_str)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if is_alive {
                    let _ = std::process::Command::new("kill")
                        .arg("-15")
                        .arg(pid_str)
                        .status();
                    for _ in 0..30 {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        let still_alive = std::process::Command::new("kill")
                            .arg("-0")
                            .arg(pid_str)
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false);
                        if !still_alive {
                            break;
                        }
                    }
                    let _ = std::fs::remove_file(pid_file);
                    println!("✓ rdns server (PID {pid}) stopped.");
                    return Ok(());
                } else {
                    let _ = std::fs::remove_file(pid_file);
                    println!("rdns is not running (cleaned up stale PID file).");
                    return Ok(());
                }
            }
        }
    }

    println!("rdns does not appear to be running.");
    Ok(())
}

async fn handle_uninstall_cmd(yes: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;

    if !yes {
        println!("This will stop rdns (if running) and remove the rdns binary from your system.");
        print!("Are you sure you want to uninstall rdns? [y/N]: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let ans = input.trim().to_lowercase();
        if ans != "y" && ans != "yes" {
            println!("Uninstall aborted.");
            return Ok(());
        }
    }

    // 1. Stop running instance first
    let _ = handle_stop_cmd("http://127.0.0.1:4000".to_string()).await;

    // 2. Locate candidate binary paths
    let mut candidate_paths = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        candidate_paths.push(PathBuf::from(&home).join(".cargo/bin/rdns"));
        candidate_paths.push(PathBuf::from(&home).join(".local/bin/rdns"));
    }
    candidate_paths.push(PathBuf::from("/usr/local/bin/rdns"));

    let mut removed_count = 0;
    for path in candidate_paths {
        if path.exists() && path.is_file() {
            let path_str = path.to_string_lossy();
            if path_str.contains("/target/debug/") || path_str.contains("/target/release/") {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(_) => {
                    println!("✓ Removed: {:?}", path);
                    removed_count += 1;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to remove {:?}: {e}", path);
                }
            }
        }
    }

    // Clean up pid file
    let pid_file = std::path::Path::new("/tmp/rdns.pid");
    if pid_file.exists() {
        let _ = std::fs::remove_file(pid_file);
    }

    if removed_count > 0 {
        println!("✓ rdns has been successfully uninstalled from your system.");
    } else {
        println!("No global rdns installation found in ~/.cargo/bin, ~/.local/bin, or /usr/local/bin.");
    }

    Ok(())
}
