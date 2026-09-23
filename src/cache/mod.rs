use crate::config::CachingConfig;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: Name,
    pub query_type: RecordType,
    pub query_class: DNSClass,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub cached_at: Instant,
    pub clamped_ttl: u32,
    pub response_code: ResponseCode,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub hit_count: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
}

pub struct DnsCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    pub stats: CacheStats,
    config: CachingConfig,
}

impl DnsCache {
    pub fn new(config: CachingConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(1024)),
            stats: CacheStats::default(),
            config,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Try to get a cached response for the query.
    /// Returns (response_message, needs_prefetch).
    pub fn get(&self, query: &Message) -> Option<(Message, bool)> {
        if !self.config.enabled {
            return None;
        }

        let question = query.queries.first()?;
        let key = CacheKey {
            name: question.name.clone(),
            query_type: question.query_type,
            query_class: question.query_class,
        };

        let now = Instant::now();
        let mut expired = false;
        let mut needs_prefetch = false;
        let mut result_msg = None;

        {
            let guard = self.entries.read();
            if let Some(entry) = guard.get(&key) {
                let elapsed = now.duration_since(entry.cached_at).as_secs() as u32;
                if elapsed >= entry.clamped_ttl {
                    expired = true;
                } else {
                    let remaining_ttl = entry.clamped_ttl - elapsed;
                    let hits = entry.hit_count.fetch_add(1, Ordering::Relaxed) + 1;

                    // Prefetch trigger: when remaining TTL is < 20% of clamped TTL or < 30s
                    // and hits >= prefetch_threshold
                    if self.config.prefetching
                        && hits >= self.config.prefetch_threshold as usize
                        && (remaining_ttl < 30 || remaining_ttl <= entry.clamped_ttl / 5)
                    {
                        needs_prefetch = true;
                    }

                    // Build cached response message
                    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    resp.metadata.recursion_desired = query.metadata.recursion_desired;
                    resp.metadata.recursion_available = true;
                    resp.metadata.response_code = entry.response_code;
                    resp.queries = query.queries.clone();

                    if let Some(edns) = &query.edns {
                        resp.set_edns(edns.clone());
                    }

                    // Adjust TTL on answers
                    for record in &entry.answers {
                        let mut rec = record.clone();
                        rec.ttl = remaining_ttl;
                        resp.add_answer(rec);
                    }

                    for record in &entry.authorities {
                        let mut rec = record.clone();
                        rec.ttl = remaining_ttl;
                        resp.authorities.push(rec);
                    }

                    for record in &entry.additionals {
                        let mut rec = record.clone();
                        rec.ttl = remaining_ttl;
                        resp.additionals.push(rec);
                    }

                    result_msg = Some(resp);
                }
            }
        }

        if expired {
            self.entries.write().remove(&key);
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        } else if let Some(msg) = result_msg {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some((msg, needs_prefetch))
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert response into cache
    pub fn put(&self, query: &Message, response: &Message) {
        if !self.config.enabled {
            return;
        }

        // Only cache NoError and NXDomain
        let rcode = response.metadata.response_code;
        if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
            return;
        }

        let question = match query.queries.first() {
            Some(q) => q,
            None => return,
        };

        let key = CacheKey {
            name: question.name.clone(),
            query_type: question.query_type,
            query_class: question.query_class,
        };

        // Determine TTL
        let raw_ttl = if rcode == ResponseCode::NXDomain || response.answers.is_empty() {
            self.config.neg_ttl.as_secs() as u32
        } else {
            response
                .answers
                .iter()
                .map(|r| r.ttl)
                .min()
                .unwrap_or_else(|| self.config.min_ttl.as_secs() as u32)
        };

        // Clamp TTL between min_ttl and max_ttl
        let min_ttl_secs = self.config.min_ttl.as_secs() as u32;
        let max_ttl_secs = self.config.max_ttl.as_secs() as u32;
        let clamped_ttl = raw_ttl.max(min_ttl_secs).min(max_ttl_secs);

        let entry = CacheEntry {
            cached_at: Instant::now(),
            clamped_ttl,
            response_code: rcode,
            answers: response.answers.clone(),
            authorities: response.authorities.clone(),
            additionals: response.additionals.clone(),
            hit_count: Arc::new(AtomicUsize::new(0)),
        };

        let mut guard = self.entries.write();

        // Enforce max capacity
        if guard.len() >= self.config.max_items {
            self.evict_expired_or_oldest(&mut guard);
        }

        guard.insert(key, entry);
    }

    fn evict_expired_or_oldest(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        let now = Instant::now();
        let initial_len = entries.len();

        // 1. Remove expired
        entries.retain(|_, v| {
            (now.duration_since(v.cached_at).as_secs() as u32) < v.clamped_ttl
        });

        let removed = initial_len - entries.len();
        if removed > 0 {
            self.stats.evictions.fetch_add(removed as u64, Ordering::Relaxed);
            return;
        }

        // 2. If still at capacity, evict 10% oldest entries
        let to_remove = (initial_len / 10).max(1);
        let mut items: Vec<(CacheKey, Instant)> = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.cached_at))
            .collect();
        items.sort_by_key(|(_, t)| *t);

        for (k, _) in items.into_iter().take(to_remove) {
            entries.remove(&k);
        }

        self.stats.evictions.fetch_add(to_remove as u64, Ordering::Relaxed);
        debug!(evicted = to_remove, "Cache evicted oldest entries due to capacity limit");
    }

    pub fn get_stats_summary(&self) -> (u64, u64, u64, usize, f64) {
        let hits = self.stats.hits.load(Ordering::Relaxed);
        let misses = self.stats.misses.load(Ordering::Relaxed);
        let evictions = self.stats.evictions.load(Ordering::Relaxed);
        let count = self.len();
        let total = hits + misses;
        let hit_ratio = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };
        (hits, misses, evictions, count, hit_ratio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::RData;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn test_cache_insertion_and_retrieval() {
        let mut config = CachingConfig::default();
        config.min_ttl = Duration::from_secs(10);
        config.max_ttl = Duration::from_secs(300);

        let cache = DnsCache::new(config);

        let name = "example.com.".parse::<Name>().unwrap();
        let mut query = Message::new(100, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = name.clone();
        q.query_type = RecordType::A;
        q.query_class = DNSClass::IN;
        query.queries.push(q);

        let mut resp = Message::new(100, MessageType::Response, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));

        // Insert
        cache.put(&query, &resp);
        assert_eq!(cache.len(), 1);

        // Retrieve
        let (cached_resp, _) = cache.get(&query).expect("Expected cache hit");
        assert_eq!(cached_resp.metadata.id, 100);
        assert_eq!(cached_resp.answers.len(), 1);
        assert_eq!(cached_resp.answers[0].ttl, 60);

        let (hits, misses, _, entries, _) = cache.get_stats_summary();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
        assert_eq!(entries, 1);
    }

    #[test]
    fn test_ttl_clamping() {
        let mut config = CachingConfig::default();
        config.min_ttl = Duration::from_secs(100);
        config.max_ttl = Duration::from_secs(500);

        let cache = DnsCache::new(config);

        let name = "fast-ttl.com.".parse::<Name>().unwrap();
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = name.clone();
        q.query_type = RecordType::A;
        query.queries.push(q);

        let mut resp = Message::new(1, MessageType::Response, OpCode::Query);
        resp.queries = query.queries.clone();
        // Server returned 5s TTL
        resp.add_answer(Record::from_rdata(
            name.clone(),
            5,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        cache.put(&query, &resp);

        // Clamped TTL should be min_ttl (100)
        let (cached_resp, _) = cache.get(&query).unwrap();
        assert!(cached_resp.answers[0].ttl >= 99);
    }
}
