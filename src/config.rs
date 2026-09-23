use serde::{de, Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub ports: PortsConfig,
    pub tls: TlsConfig,
    pub upstreams: UpstreamsConfig,
    pub conditional: ConditionalConfig,
    pub blocking: BlockingConfig,
    pub client_lookup: ClientLookupConfig,
    pub caching: CachingConfig,
    pub custom_dns: CustomDnsConfig,
    pub query_log: QueryLogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ports: PortsConfig::default(),
            tls: TlsConfig::default(),
            upstreams: UpstreamsConfig::default(),
            conditional: ConditionalConfig::default(),
            blocking: BlockingConfig::default(),
            client_lookup: ClientLookupConfig::default(),
            caching: CachingConfig::default(),
            custom_dns: CustomDnsConfig::default(),
            query_log: QueryLogConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PortsConfig {
    #[serde(deserialize_with = "deserialize_addr_or_port_opt")]
    pub dns: Option<SocketAddr>,
    #[serde(deserialize_with = "deserialize_addr_or_port_opt")]
    pub http: Option<SocketAddr>,
    #[serde(deserialize_with = "deserialize_addr_or_port_opt")]
    pub https: Option<SocketAddr>,
    #[serde(deserialize_with = "deserialize_addr_or_port_opt")]
    pub dot: Option<SocketAddr>,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            dns: Some("0.0.0.0:53".parse().unwrap()),
            http: Some("0.0.0.0:4000".parse().unwrap()),
            https: None,
            dot: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamStrategy {
    #[default]
    Parallel,
    Strict,
    Random,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamsConfig {
    pub groups: HashMap<String, Vec<String>>,
    pub strategy: UpstreamStrategy,
    #[serde(deserialize_with = "deserialize_duration")]
    pub timeout: Duration,
}

impl Default for UpstreamsConfig {
    fn default() -> Self {
        let mut groups = HashMap::new();
        groups.insert(
            "default".to_string(),
            vec![
                "udp:1.1.1.1:53".to_string(),
                "udp:1.0.0.1:53".to_string(),
                "https://cloudflare-dns.com/dns-query".to_string(),
            ],
        );
        Self {
            groups,
            strategy: UpstreamStrategy::Parallel,
            timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConditionalConfig {
    /// Maps domain name (e.g. "lan", "local", "168.192.in-addr.arpa")
    /// to an upstream group name or upstream target address.
    pub mapping: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum BlockType {
    #[default]
    ZeroIp,
    Nxdomain,
    CustomIp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CustomIpConfig {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

impl Default for CustomIpConfig {
    fn default() -> Self {
        Self {
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            ipv6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BlockingConfig {
    pub blacklists: HashMap<String, Vec<String>>,
    pub whitelists: HashMap<String, Vec<String>>,
    pub client_groups: HashMap<String, Vec<String>>,
    pub block_type: BlockType,
    pub custom_ip: CustomIpConfig,
    #[serde(deserialize_with = "deserialize_duration")]
    pub block_ttl: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub refresh_period: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub download_timeout: Duration,
    pub download_attempts: u32,
    #[serde(deserialize_with = "deserialize_duration")]
    pub download_cooldown: Duration,
    pub enabled: bool,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        let mut client_groups = HashMap::new();
        client_groups.insert("default".to_string(), vec!["ads".to_string()]);

        Self {
            blacklists: HashMap::new(),
            whitelists: HashMap::new(),
            client_groups,
            block_type: BlockType::ZeroIp,
            custom_ip: CustomIpConfig::default(),
            block_ttl: Duration::from_secs(3600),
            refresh_period: Duration::from_secs(4 * 3600), // 4 hours
            download_timeout: Duration::from_secs(30),
            download_attempts: 3,
            download_cooldown: Duration::from_secs(2),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ClientLookupConfig {
    /// Maps IP or CIDR (e.g. "192.168.1.100", "192.168.1.0/24") to group names.
    pub clients: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CachingConfig {
    #[serde(deserialize_with = "deserialize_duration")]
    pub min_ttl: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub max_ttl: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub neg_ttl: Duration,
    pub prefetching: bool,
    #[serde(deserialize_with = "deserialize_duration")]
    pub prefetch_expires: Duration,
    pub prefetch_threshold: u32,
    pub max_items: usize,
    pub enabled: bool,
}

impl Default for CachingConfig {
    fn default() -> Self {
        Self {
            min_ttl: Duration::from_secs(300),        // 5 min
            max_ttl: Duration::from_secs(86400),      // 1 day
            neg_ttl: Duration::from_secs(1800),       // 30 min
            prefetching: false,
            prefetch_expires: Duration::from_secs(7200), // 2 hours
            prefetch_threshold: 5,
            max_items: 50_000,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CustomDnsConfig {
    #[serde(deserialize_with = "deserialize_duration")]
    pub custom_ttl: Duration,
    /// Maps domain name to list of target strings (IPv4, IPv6, or domain alias for CNAME)
    pub mapping: HashMap<String, Vec<String>>,
}

impl Default for CustomDnsConfig {
    fn default() -> Self {
        Self {
            custom_ttl: Duration::from_secs(3600),
            mapping: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum QueryLogType {
    #[default]
    Console,
    #[serde(alias = "csv_client", alias = "csvClient")]
    CsvClient,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct QueryLogConfig {
    #[serde(rename = "type")]
    pub log_type: QueryLogType,
    pub log_level: String,
    pub log_blocked: bool,
    /// Directory path where per-client daily CSV files are stored
    pub target_dir: String,
    /// How often in-memory aggregated query counts are flushed to disk
    #[serde(deserialize_with = "deserialize_duration")]
    pub flush_interval: Duration,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            log_type: QueryLogType::Console,
            log_level: "info".to_string(),
            log_blocked: true,
            target_dir: "./logs".to_string(),
            flush_interval: Duration::from_secs(30),
        }
    }
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    pub fn load_from_str(content: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config: Config = serde_yaml::from_str(content)?;
        Ok(config)
    }
}

/// Helper to parse human-readable durations like "5m", "1h", "30s", "1d" or plain numbers (seconds).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Duration::from_secs(0));
    }

    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();

    for c in s.chars() {
        if c.is_ascii_digit() {
            num_buf.push(c);
        } else {
            if num_buf.is_empty() {
                return Err(format!("Invalid duration format: '{s}'"));
            }
            let n: u64 = num_buf.parse().map_err(|e| format!("{e}"))?;
            num_buf.clear();

            match c {
                's' => total_secs += n,
                'm' => total_secs += n * 60,
                'h' => total_secs += n * 3600,
                'd' => total_secs += n * 86400,
                _ => return Err(format!("Unknown duration unit: '{c}' in '{s}'")),
            }
        }
    }

    if !num_buf.is_empty() {
        let n: u64 = num_buf.parse().map_err(|e| format!("{e}"))?;
        total_secs += n;
    }

    Ok(Duration::from_secs(total_secs))
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl<'de> de::Visitor<'de> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a duration string (e.g. '5m', '1h', '30s') or integer seconds")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Duration, E>
        where
            E: de::Error,
        {
            Ok(Duration::from_secs(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Duration, E>
        where
            E: de::Error,
        {
            if value < 0 {
                return Err(E::custom("duration cannot be negative"));
            }
            Ok(Duration::from_secs(value as u64))
        }

        fn visit_str<E>(self, value: &str) -> Result<Duration, E>
        where
            E: de::Error,
        {
            parse_duration(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

fn deserialize_addr_or_port_opt<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AddrOrPortVisitor;

    impl<'de> de::Visitor<'de> for AddrOrPortVisitor {
        type Value = Option<SocketAddr>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a port number (e.g. 53), a socket address (e.g. '0.0.0.0:53'), or null")
        }

        fn visit_none<E>(self) -> Result<Option<SocketAddr>, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Option<SocketAddr>, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_u64<E>(self, port: u64) -> Result<Option<SocketAddr>, E>
        where
            E: de::Error,
        {
            if port > 65535 {
                return Err(E::custom(format!("Invalid port: {port}")));
            }
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port as u16,
            )))
        }

        fn visit_str<E>(self, value: &str) -> Result<Option<SocketAddr>, E>
        where
            E: de::Error,
        {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            if let Ok(port) = value.parse::<u16>() {
                return Ok(Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port,
                )));
            }
            if let Ok(addr) = value.parse::<SocketAddr>() {
                return Ok(Some(addr));
            }
            // Check if it's :port
            if let Some(port_str) = value.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok(Some(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        port,
                    )));
                }
            }
            Err(E::custom(format!(
                "Failed to parse '{value}' as port or socket address"
            )))
        }
    }

    deserializer.deserialize_any(AddrOrPortVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_default_config_parsing() {
        let yaml = r#"
ports:
  dns: 5335
  http: "127.0.0.1:4000"

upstreams:
  groups:
    default:
      - "udp:1.1.1.1:53"
      - "tcp:1.0.0.1:53"
      - "https://cloudflare-dns.com/dns-query"
  strategy: strict
  timeout: 4s

blocking:
  blacklists:
    ads:
      - "https://adaway.org/hosts.txt"
      - "/tmp/test-blocklist.txt"
  whitelists:
    ads:
      - "example.com"
  client_groups:
    default:
      - "ads"
  block_type: nxdomain
  block_ttl: 1h
  refresh_period: 24h

client_lookup:
  clients:
    "192.168.1.50": ["kids"]
    "192.168.1.0/24": ["default"]

caching:
  min_ttl: 5m
  max_ttl: 1d
  prefetching: true

custom_dns:
  custom_ttl: 30m
  mapping:
    "router.lan": ["192.168.1.1"]
    "nas.lan": ["192.168.1.10", "fd00::10"]
    "alias.lan": ["nas.lan"]
"#;
        let config = Config::load_from_str(yaml).expect("Failed to parse config");
        assert_eq!(config.ports.dns.unwrap().port(), 5335);
        assert_eq!(config.ports.http.unwrap(), "127.0.0.1:4000".parse().unwrap());
        assert_eq!(config.upstreams.strategy, UpstreamStrategy::Strict);
        assert_eq!(config.upstreams.timeout, Duration::from_secs(4));
        assert_eq!(config.blocking.block_type, BlockType::Nxdomain);
        assert_eq!(config.blocking.block_ttl, Duration::from_secs(3600));
        assert_eq!(config.blocking.refresh_period, Duration::from_secs(86400));
        assert_eq!(config.caching.min_ttl, Duration::from_secs(300));
        assert!(config.caching.prefetching);
        assert_eq!(
            config.custom_dns.mapping.get("router.lan").unwrap(),
            &vec!["192.168.1.1".to_string()]
        );
    }
}
