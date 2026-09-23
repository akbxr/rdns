use crate::blocking::parser::{ListParser, ParsedList};
use crate::config::{BlockType, BlockingConfig, CustomIpConfig};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub enum BlockReason {
    Blacklist { group: String, matched: String },
    Regex { group: String, pattern: String },
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blacklist { group, matched } => write!(f, "blacklist:{group}:{matched}"),
            Self::Regex { group, pattern } => write!(f, "regex:{group}:{pattern}"),
        }
    }
}

pub struct BlockEngine {
    blacklists: RwLock<HashMap<String, ParsedList>>,
    whitelists: RwLock<HashMap<String, ParsedList>>,
    client_groups: RwLock<HashMap<String, Vec<String>>>,
    pub block_type: BlockType,
    pub custom_ip: CustomIpConfig,
    pub block_ttl: Duration,
    pub enabled: AtomicBool,
    disabled_until: RwLock<Option<Instant>>,
    total_blocked_rules: AtomicUsize,
    config: BlockingConfig,
    http_client: reqwest::Client,
}

impl BlockEngine {
    pub fn new(config: BlockingConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.download_timeout)
            .build()
            .unwrap_or_default();

        Self {
            blacklists: RwLock::new(HashMap::new()),
            whitelists: RwLock::new(HashMap::new()),
            client_groups: RwLock::new(config.client_groups.clone()),
            block_type: config.block_type,
            custom_ip: config.custom_ip.clone(),
            block_ttl: config.block_ttl,
            enabled: AtomicBool::new(config.enabled),
            disabled_until: RwLock::new(None),
            total_blocked_rules: AtomicUsize::new(0),
            config,
            http_client,
        }
    }

    pub fn is_enabled(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        let disabled_guard = self.disabled_until.read();
        if let Some(until) = *disabled_guard {
            if Instant::now() < until {
                return false;
            }
        }
        true
    }

    pub fn disable_for(&self, duration: Duration) {
        if duration.is_zero() {
            // Permanently disable until enabled
            self.enabled.store(false, Ordering::Relaxed);
            *self.disabled_until.write() = None;
            info!("Blocking permanently disabled via API");
        } else {
            *self.disabled_until.write() = Some(Instant::now() + duration);
            info!("Blocking disabled for {:?}", duration);
        }
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        *self.disabled_until.write() = None;
        info!("Blocking enabled via API");
    }

    pub fn get_status(&self) -> (bool, Option<Duration>, usize) {
        let enabled = self.is_enabled();
        let remaining_disabled = self.disabled_until.read().and_then(|until| {
            let now = Instant::now();
            if until > now {
                Some(until - now)
            } else {
                None
            }
        });
        let total_rules = self.total_blocked_rules.load(Ordering::Relaxed);
        (enabled, remaining_disabled, total_rules)
    }

    /// Check if domain is blocked for the given client group.
    /// Returns Some(BlockReason) if blocked, None if allowed.
    pub fn check_blocked(&self, client_group: &str, raw_domain: &str) -> Option<BlockReason> {
        if !self.is_enabled() {
            return None;
        }

        let domain = raw_domain.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            return None;
        }

        let groups_guard = self.client_groups.read();
        let list_names = groups_guard
            .get(client_group)
            .or_else(|| groups_guard.get("default"))?;

        let whitelists_guard = self.whitelists.read();
        let blacklists_guard = self.blacklists.read();

        // 1. Check whitelists first (whitelists override blacklists)
        for list_name in list_names {
            if let Some(whitelist) = whitelists_guard.get(list_name) {
                if is_domain_in_list(whitelist, &domain) {
                    return None;
                }
            }
        }

        // 2. Check blacklists
        for list_name in list_names {
            if let Some(blacklist) = blacklists_guard.get(list_name) {
                if let Some(reason) = match_blacklist(blacklist, list_name, &domain) {
                    return Some(reason);
                }
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

        match self.block_type {
            BlockType::Nxdomain => {
                resp.metadata.response_code = ResponseCode::NXDomain;
            }
            BlockType::ZeroIp => {
                resp.metadata.response_code = ResponseCode::NoError;
                for q in &query.queries {
                    match q.query_type {
                        RecordType::A => {
                            let rec = Record::from_rdata(
                                q.name.clone(),
                                ttl_secs,
                                RData::A(A(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                            );
                            resp.add_answer(rec);
                        }
                        RecordType::AAAA => {
                            let rec = Record::from_rdata(
                                q.name.clone(),
                                ttl_secs,
                                RData::AAAA(AAAA(std::net::Ipv6Addr::UNSPECIFIED)),
                            );
                            resp.add_answer(rec);
                        }
                        _ => {
                            // NODATA response
                        }
                    }
                }
            }
            BlockType::CustomIp => {
                resp.metadata.response_code = ResponseCode::NoError;
                for q in &query.queries {
                    match q.query_type {
                        RecordType::A => {
                            let rec = Record::from_rdata(
                                q.name.clone(),
                                ttl_secs,
                                RData::A(A(self.custom_ip.ipv4)),
                            );
                            resp.add_answer(rec);
                        }
                        RecordType::AAAA => {
                            let rec = Record::from_rdata(
                                q.name.clone(),
                                ttl_secs,
                                RData::AAAA(AAAA(self.custom_ip.ipv6)),
                            );
                            resp.add_answer(rec);
                        }
                        _ => {}
                    }
                }
            }
        }

        resp
    }

    /// Load all blacklists and whitelists from sources
    pub async fn reload(&self) -> Result<(), String> {
        info!("Loading blocklists and whitelists...");
        let mut new_blacklists = HashMap::new();
        let mut new_whitelists = HashMap::new();
        let mut total_rules = 0;

        // Load blacklists
        for (group, sources) in &self.config.blacklists {
            let mut parsed_group = ParsedList::new();
            for src in sources {
                match ListParser::load_source(
                    src,
                    &self.http_client,
                    self.config.download_timeout,
                    self.config.download_attempts,
                    self.config.download_cooldown,
                )
                .await
                {
                    Ok(list) => {
                        info!(group = %group, source = %src, domains = list.domains.len(), regexes = list.regexes.len(), "Loaded blacklist source");
                        parsed_group.merge(list);
                    }
                    Err(e) => {
                        warn!(group = %group, source = %src, error = %e, "Failed to load blacklist source");
                    }
                }
            }
            total_rules += parsed_group.len();
            new_blacklists.insert(group.clone(), parsed_group);
        }

        // Load whitelists
        for (group, sources) in &self.config.whitelists {
            let mut parsed_group = ParsedList::new();
            for src in sources {
                match ListParser::load_source(
                    src,
                    &self.http_client,
                    self.config.download_timeout,
                    self.config.download_attempts,
                    self.config.download_cooldown,
                )
                .await
                {
                    Ok(list) => {
                        info!(group = %group, source = %src, domains = list.domains.len(), regexes = list.regexes.len(), "Loaded whitelist source");
                        parsed_group.merge(list);
                    }
                    Err(e) => {
                        warn!(group = %group, source = %src, error = %e, "Failed to load whitelist source");
                    }
                }
            }
            new_whitelists.insert(group.clone(), parsed_group);
        }

        *self.blacklists.write() = new_blacklists;
        *self.whitelists.write() = new_whitelists;
        self.total_blocked_rules.store(total_rules, Ordering::Relaxed);

        info!(total_rules = total_rules, "Blocklists and whitelists successfully updated");
        Ok(())
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
}

/// Zero-allocation domain suffix walking
fn is_domain_in_list(list: &ParsedList, domain: &str) -> bool {
    // 1. Exact match
    if list.domains.contains(domain) {
        return true;
    }

    // 2. Suffix walk: for a.b.c.com -> check b.c.com, c.com
    let mut remainder = domain;
    while let Some(dot_idx) = remainder.find('.') {
        remainder = &remainder[dot_idx + 1..];
        if remainder.contains('.') && list.domains.contains(remainder) {
            return true;
        }
    }

    // 3. Regex match
    for re in &list.regexes {
        if re.is_match(domain) {
            return true;
        }
    }

    false
}

fn match_blacklist(list: &ParsedList, group: &str, domain: &str) -> Option<BlockReason> {
    // 1. Exact match
    if list.domains.contains(domain) {
        return Some(BlockReason::Blacklist {
            group: group.to_string(),
            matched: domain.to_string(),
        });
    }

    // 2. Suffix walk
    let mut remainder = domain;
    while let Some(dot_idx) = remainder.find('.') {
        remainder = &remainder[dot_idx + 1..];
        if remainder.contains('.') && list.domains.contains(remainder) {
            return Some(BlockReason::Blacklist {
                group: group.to_string(),
                matched: remainder.to_string(),
            });
        }
    }

    // 3. Regex match
    for re in &list.regexes {
        if re.is_match(domain) {
            return Some(BlockReason::Regex {
                group: group.to_string(),
                pattern: re.as_str().to_string(),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_matching() {
        let mut list = ParsedList::new();
        list.domains.insert("doubleclick.net".to_string());
        list.domains.insert("tracking.example.com".to_string());

        assert!(is_domain_in_list(&list, "doubleclick.net"));
        assert!(is_domain_in_list(&list, "ad.doubleclick.net"));
        assert!(is_domain_in_list(&list, "sub.ad.doubleclick.net"));
        assert!(!is_domain_in_list(&list, "notdoubleclick.net"));
        assert!(!is_domain_in_list(&list, "net"));

        assert!(is_domain_in_list(&list, "tracking.example.com"));
        assert!(is_domain_in_list(&list, "v2.tracking.example.com"));
        assert!(!is_domain_in_list(&list, "example.com"));
    }

    #[test]
    fn test_engine_whitelist_override() {
        let mut config = BlockingConfig::default();
        config.client_groups.insert("default".to_string(), vec!["ads".to_string()]);

        let engine = BlockEngine::new(config);
        {
            let mut blacklists = engine.blacklists.write();
            let mut bl = ParsedList::new();
            bl.domains.insert("ads.google.com".to_string());
            bl.domains.insert("analytics.google.com".to_string());
            blacklists.insert("ads".to_string(), bl);
        }
        {
            let mut whitelists = engine.whitelists.write();
            let mut wl = ParsedList::new();
            wl.domains.insert("analytics.google.com".to_string());
            whitelists.insert("ads".to_string(), wl);
        }

        // ads.google.com is blocked
        assert!(engine.check_blocked("default", "ads.google.com").is_some());
        // analytics.google.com is whitelisted, so NOT blocked
        assert!(engine.check_blocked("default", "analytics.google.com").is_none());
    }
}
