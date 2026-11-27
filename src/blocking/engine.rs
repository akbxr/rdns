use crate::blocking::parser::{domain_hash, ListBuilder, ListParser, ParsedList};
use crate::config::{BlockType, BlockingConfig, CustomIpConfig};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use parking_lot::RwLock;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub enum BlockReason {
    Blacklist { group: String, matched: String },
    Regex { group: String, pattern: String },
}

impl BlockReason {
    /// Low-cardinality label for metrics: the rule kind and list, without the domain.
    pub fn metric_label(&self) -> String {
        match self {
            Self::Blacklist { group, .. } => format!("blacklist:{group}"),
            Self::Regex { group, .. } => format!("regex:{group}"),
        }
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blacklist { group, matched } => write!(f, "blacklist:{group}:{matched}"),
            Self::Regex { group, pattern } => write!(f, "regex:{group}:{pattern}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Blacklist,
    Whitelist,
}

impl std::fmt::Display for ListKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Blacklist => "blacklist",
            Self::Whitelist => "whitelist",
        })
    }
}

/// List contents, indexed like `BlockEngine::list_names`.
struct Lists {
    black: Vec<ParsedList>,
    white: Vec<ParsedList>,
}

impl Lists {
    fn get_mut(&mut self, kind: ListKind) -> &mut Vec<ParsedList> {
        match kind {
            ListKind::Blacklist => &mut self.black,
            ListKind::Whitelist => &mut self.white,
        }
    }
}

pub struct BlockEngine {
    /// Every list name in the config, sorted; lists are referred to by index here.
    list_names: Vec<String>,
    /// Client group -> indices of its lists, in configured order. Fixed at startup, so
    /// lookups need no lock or name lookups for it.
    client_lists: HashMap<String, Vec<usize>>,
    lists: RwLock<Lists>,
    pub block_type: BlockType,
    pub custom_ip: CustomIpConfig,
    pub block_ttl: Duration,
    pub enabled: AtomicBool,
    /// Milliseconds after `epoch` until which blocking is paused; 0 when not paused.
    disabled_until_ms: AtomicU64,
    epoch: Instant,
    total_blocked_rules: AtomicUsize,
    /// Serializes reloads: a refresh requested while another runs must not build a
    /// third copy of the lists alongside the live and the in-progress ones.
    reload_lock: tokio::sync::Mutex<()>,
    config: BlockingConfig,
    http_client: reqwest::Client,
}

impl BlockEngine {
    pub fn new(config: BlockingConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.download_timeout)
            .build()
            .unwrap_or_default();

        let mut list_names: Vec<String> = config
            .blacklists
            .keys()
            .chain(config.whitelists.keys())
            .chain(config.client_groups.values().flatten())
            .cloned()
            .collect();
        list_names.sort_unstable();
        list_names.dedup();

        let client_lists = config
            .client_groups
            .iter()
            .map(|(group, names)| {
                let indices = names
                    .iter()
                    .filter_map(|name| list_names.binary_search(name).ok())
                    .collect();
                (group.clone(), indices)
            })
            .collect();

        let lists = Lists {
            black: vec![ParsedList::new(); list_names.len()],
            white: vec![ParsedList::new(); list_names.len()],
        };

        Self {
            list_names,
            client_lists,
            lists: RwLock::new(lists),
            block_type: config.block_type,
            custom_ip: config.custom_ip.clone(),
            block_ttl: config.block_ttl,
            enabled: AtomicBool::new(config.enabled),
            disabled_until_ms: AtomicU64::new(0),
            epoch: Instant::now(),
            total_blocked_rules: AtomicUsize::new(0),
            reload_lock: tokio::sync::Mutex::new(()),
            config,
            http_client,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn is_enabled(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        let until = self.disabled_until_ms.load(Ordering::Relaxed);
        until == 0 || self.now_ms() >= until
    }

    pub fn disable_for(&self, duration: Duration) {
        if duration.is_zero() {
            // Permanently disable until enabled
            self.enabled.store(false, Ordering::Relaxed);
            self.disabled_until_ms.store(0, Ordering::Relaxed);
            info!("Blocking permanently disabled via API");
        } else {
            let until = self.now_ms().saturating_add(duration.as_millis() as u64).max(1);
            self.disabled_until_ms.store(until, Ordering::Relaxed);
            info!("Blocking disabled for {:?}", duration);
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        self.disabled_until_ms.store(0, Ordering::Relaxed);
        info!("Blocking enabled via API");
    }

    pub fn get_status(&self) -> (bool, Option<Duration>, usize) {
        let enabled = self.is_enabled();
        let until = self.disabled_until_ms.load(Ordering::Relaxed);
        let now = self.now_ms();
        let remaining_disabled = (until > now).then(|| Duration::from_millis(until - now));
        let total_rules = self.total_blocked_rules.load(Ordering::Relaxed);
        (enabled, remaining_disabled, total_rules)
    }

    /// Check if domain is blocked for the given client group.
    /// Returns Some(BlockReason) if blocked, None if allowed.
    pub fn check_blocked(&self, client_group: &str, raw_domain: &str) -> Option<BlockReason> {
        if !self.is_enabled() {
            return None;
        }

        let domain = normalize_query_domain(raw_domain);
        if domain.is_empty() {
            return None;
        }

        let indices = self
            .client_lists
            .get(client_group)
            .or_else(|| self.client_lists.get("default"))?;
        if indices.is_empty() {
            return None;
        }

        let lists = self.lists.read();

        // Walk the domain and its parents (a.b.c.com, b.c.com, c.com), hashing each once
        // for all lists. Whitelists override blacklists; of the blacklist hits, keep the
        // one from the earliest list, and within a list the longest suffix.
        let mut domain_hit: Option<(usize, &str)> = None;
        for suffix in domain_suffixes(&domain) {
            let hash = domain_hash(suffix);
            for (position, &index) in indices.iter().enumerate() {
                if lists.white[index].domains.contains_hash(hash) {
                    return None;
                }
                if domain_hit.is_none_or(|(hit_position, _)| position < hit_position)
                    && lists.black[index].domains.contains_hash(hash)
                {
                    domain_hit = Some((position, suffix));
                }
            }
        }

        for &index in indices {
            if lists.white[index].regexes.iter().any(|re| re.is_match(&domain)) {
                return None;
            }
        }

        // Lists are checked in configured order: domain rules, then regexes, per list.
        for (position, &index) in indices.iter().enumerate() {
            if let Some((hit_position, matched)) = domain_hit {
                if hit_position == position {
                    return Some(BlockReason::Blacklist {
                        group: self.list_names[index].clone(),
                        matched: matched.to_string(),
                    });
                }
            }
            if let Some(re) = lists.black[index].regexes.iter().find(|re| re.is_match(&domain)) {
                return Some(BlockReason::Regex {
                    group: self.list_names[index].clone(),
                    pattern: re.as_str().to_string(),
                });
            }
        }

        None
    }

    /// Build DNS blocked response according to configured `block_type`
    pub fn build_blocked_response(&self, query: &Message) -> Message {
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.authoritative = true;

        // Preserve queries section
        resp.queries = query.queries.clone();

        // Preserve EDNS if present
        if let Some(edns) = &query.edns {
            resp.set_edns(edns.clone());
        }

        let ttl_secs = self.block_ttl.as_secs() as u32;

        let (ipv4, ipv6) = match self.block_type {
            BlockType::Nxdomain => {
                resp.metadata.response_code = ResponseCode::NXDomain;
                return resp;
            }
            BlockType::ZeroIp => (std::net::Ipv4Addr::UNSPECIFIED, std::net::Ipv6Addr::UNSPECIFIED),
            BlockType::CustomIp => (self.custom_ip.ipv4, self.custom_ip.ipv6),
        };

        resp.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            let rdata = match q.query_type {
                RecordType::A => RData::A(A(ipv4)),
                RecordType::AAAA => RData::AAAA(AAAA(ipv6)),
                // NODATA response
                _ => continue,
            };
            resp.add_answer(Record::from_rdata(q.name.clone(), ttl_secs, rdata));
        }

        resp
    }

    /// Load all blacklists and whitelists from sources
    pub async fn reload(&self) -> Result<(), String> {
        let _reload = self.reload_lock.lock().await;
        info!("Loading blocklists and whitelists...");

        for (kind, sources_by_list) in [
            (ListKind::Blacklist, &self.config.blacklists),
            (ListKind::Whitelist, &self.config.whitelists),
        ] {
            for (name, sources) in sources_by_list {
                let Some(list) = self.load_list(kind, name, sources).await else {
                    continue;
                };
                let Ok(index) = self.list_names.binary_search(name) else {
                    continue;
                };
                // Swap each list in as soon as it is built, so its old copy is freed before
                // the next list is loaded. Free it after releasing the lock: DNS lookups take
                // the read lock, and freeing millions of entries while holding the write lock
                // stalled them.
                let old = std::mem::replace(&mut self.lists.write().get_mut(kind)[index], list);
                drop(old);
            }
        }

        let (total_rules, heap_bytes) = {
            let lists = self.lists.read();
            let rules: usize = lists.black.iter().map(ParsedList::len).sum();
            let bytes: usize = lists.black.iter().chain(&lists.white).map(ParsedList::heap_bytes).sum();
            (rules, bytes)
        };
        self.total_blocked_rules.store(total_rules, Ordering::Relaxed);

        info!(
            total_rules = total_rules,
            memory_mb = %format_args!("{:.1}", heap_bytes as f64 / (1024.0 * 1024.0)),
            "Blocklists and whitelists successfully updated"
        );
        Ok(())
    }

    /// Downloads and parses all sources of one list. Returns None to keep the current
    /// list: when every source failed (an outage should not switch blocking off until the
    /// next refresh), or when building it failed.
    async fn load_list(&self, kind: ListKind, name: &str, sources: &[String]) -> Option<ParsedList> {
        let mut builder = ListBuilder::new();
        let mut loaded_any = sources.is_empty();
        for src in sources {
            let mark = builder.mark();
            match ListParser::load_source_into(
                src,
                &self.http_client,
                self.config.download_timeout,
                self.config.download_attempts,
                self.config.download_cooldown,
                &mut builder,
            )
            .await
            {
                Ok(()) => {
                    loaded_any = true;
                    let (domains, regexes) = builder.added_since(mark);
                    info!(group = %name, source = %src, domains = domains, regexes = regexes, "Loaded {kind} source");
                }
                Err(e) => {
                    warn!(group = %name, source = %src, error = %e, "Failed to load {kind} source");
                }
            }
        }

        if !loaded_any {
            warn!(group = %name, "All {kind} sources failed, keeping the current list");
            return None;
        }

        // Sorting millions of hashes takes a while: keep it off the async workers.
        match tokio::task::spawn_blocking(move || builder.finish()).await {
            Ok(list) => Some(list),
            Err(e) => {
                error!(group = %name, error = %e, "Failed to build {kind}");
                None
            }
        }
    }

    /// Spawns periodic refresh task in background
    pub fn start_refresh_task(self: Arc<Self>, period: Duration) {
        if period.is_zero() {
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.tick().await; // first tick finishes immediately

            loop {
                interval.tick().await;
                info!("Running scheduled blocklist refresh...");
                if let Err(e) = self.reload().await {
                    error!("Error during scheduled blocklist refresh: {e}");
                }
            }
        });
    }

    #[cfg(test)]
    fn set_list(&self, kind: ListKind, name: &str, list: ParsedList) {
        let index = self.list_names.iter().position(|n| n == name).expect("unknown list");
        self.lists.write().get_mut(kind)[index] = list;
    }
}

/// Lowercase, without the root dot. Names from the DNS server arrive normalized and
/// are borrowed as they are.
fn normalize_query_domain(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
        Cow::Owned(trimmed.to_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// The domain itself, then each parent that still has a dot: a.b.c.com, b.c.com, c.com.
fn domain_suffixes(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::once(domain).chain(
        domain
            .match_indices('.')
            .map(move |(i, _)| &domain[i + 1..])
            .take_while(|rest| rest.contains('.')),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn engine_with(black: ParsedList, white: ParsedList) -> BlockEngine {
        let mut config = BlockingConfig::default();
        config.client_groups.insert("default".to_string(), vec!["ads".to_string()]);
        let engine = BlockEngine::new(config);
        engine.set_list(ListKind::Blacklist, "ads", black);
        engine.set_list(ListKind::Whitelist, "ads", white);
        engine
    }

    #[test]
    fn test_subdomain_matching() {
        let mut list = ParsedList::new();
        list.domains.insert("doubleclick.net");
        list.domains.insert("tracking.example.com");
        let engine = engine_with(list, ParsedList::new());
        let blocked = |d: &str| engine.check_blocked("default", d).is_some();

        assert!(blocked("doubleclick.net"));
        assert!(blocked("ad.doubleclick.net"));
        assert!(blocked("sub.ad.doubleclick.net"));
        assert!(blocked("Sub.AD.doubleclick.net."));
        assert!(!blocked("notdoubleclick.net"));
        assert!(!blocked("net"));

        assert!(blocked("tracking.example.com"));
        assert!(blocked("v2.tracking.example.com"));
        assert!(!blocked("example.com"));
    }

    #[test]
    fn test_engine_whitelist_override() {
        let mut bl = ParsedList::new();
        bl.domains.insert("ads.google.com");
        bl.domains.insert("analytics.google.com");
        let mut wl = ParsedList::new();
        wl.domains.insert("analytics.google.com");
        let engine = engine_with(bl, wl);

        // ads.google.com is blocked
        assert!(engine.check_blocked("default", "ads.google.com").is_some());
        // analytics.google.com is whitelisted, so NOT blocked
        assert!(engine.check_blocked("default", "analytics.google.com").is_none());
        assert!(engine.check_blocked("default", "x.analytics.google.com").is_none());
    }

    #[test]
    fn test_block_reasons_follow_list_order() {
        let mut config = BlockingConfig::default();
        config
            .client_groups
            .insert("default".to_string(), vec!["first".to_string(), "second".to_string()]);
        let engine = BlockEngine::new(config);

        let mut first = ParsedList::new();
        first.regexes.push(Regex::new(r"^ads\.").unwrap());
        let mut second = ParsedList::new();
        second.domains.insert("example.com");
        second.domains.insert("ads.example.com");
        engine.set_list(ListKind::Blacklist, "first", first);
        engine.set_list(ListKind::Blacklist, "second", second);

        match engine.check_blocked("default", "ads.example.com") {
            Some(BlockReason::Regex { group, .. }) => assert_eq!(group, "first"),
            other => panic!("expected regex from first list, got {other:?}"),
        }
        match engine.check_blocked("default", "www.example.com") {
            Some(BlockReason::Blacklist { group, matched }) => {
                assert_eq!(group, "second");
                assert_eq!(matched, "example.com");
            }
            other => panic!("expected blacklist from second list, got {other:?}"),
        }
        match engine.check_blocked("default", "x.ads.example.com") {
            Some(BlockReason::Blacklist { matched, .. }) => assert_eq!(matched, "ads.example.com"),
            other => panic!("expected longest suffix, got {other:?}"),
        }
    }

    #[test]
    fn test_disable_for_and_enable() {
        let mut list = ParsedList::new();
        list.domains.insert("ads.example.com");
        let engine = engine_with(list, ParsedList::new());

        engine.disable_for(Duration::from_secs(60));
        assert!(engine.check_blocked("default", "ads.example.com").is_none());
        let (enabled, remaining, _) = engine.get_status();
        assert!(!enabled);
        assert!(remaining.is_some_and(|r| r > Duration::from_secs(50)));

        engine.enable();
        assert!(engine.check_blocked("default", "ads.example.com").is_some());
        assert_eq!(engine.get_status().1, None);
    }
}
