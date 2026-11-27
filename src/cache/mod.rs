use crate::config::CachingConfig;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: Name,
    pub query_type: RecordType,
    pub query_class: DNSClass,
}

impl CacheKey {
    fn for_query(query: &Message) -> Option<Self> {
        let question = query.queries.first()?;
        Some(Self {
            name: question.name.clone(),
            query_type: question.query_type,
            query_class: question.query_class,
        })
    }
}

#[derive(Debug)]
pub struct CacheEntry {
    pub cached_at: Instant,
    pub clamped_ttl: u32,
    hits: AtomicU32,
    /// Set once a prefetch has been started, so a popular name triggers one refresh
    /// rather than one per query near expiry.
    prefetching: AtomicBool,
    /// Response code and records in DNS wire format. Parsed records cost about ten times
    /// their wire size (hickory's `Record` is 272 bytes before any heap data).
    wire: Box<[u8]>,
}

impl CacheEntry {
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at).as_secs() >= u64::from(self.clamped_ttl)
    }
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
        let old = std::mem::take(&mut *self.entries.write());
        drop(old);
    }

    /// Try to get a cached response for the query.
    /// Returns (response_message, needs_prefetch).
    pub fn get(&self, query: &Message) -> Option<(Message, bool)> {
        if !self.config.enabled {
            return None;
        }

        let key = CacheKey::for_query(query)?;
        let now = Instant::now();

        let (mut resp, remaining_ttl, needs_prefetch) = {
            let guard = self.entries.read();
            let Some(entry) = guard.get(&key) else {
                drop(guard);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };

            if entry.is_expired(now) {
                drop(guard);
                self.entries.write().remove(&key);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            let Ok(resp) = Message::from_vec(&entry.wire) else {
                drop(guard);
                self.entries.write().remove(&key);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            };

            let elapsed = now.duration_since(entry.cached_at).as_secs() as u32;
            let remaining_ttl = entry.clamped_ttl - elapsed;
            let hits = entry.hits.fetch_add(1, Ordering::Relaxed).saturating_add(1);

            // Prefetch trigger: when remaining TTL is < 20% of clamped TTL or < 30s
            // and hits >= prefetch_threshold, once per entry
            let needs_prefetch = self.config.prefetching
                && hits >= self.config.prefetch_threshold
                && (remaining_ttl < 30 || remaining_ttl <= entry.clamped_ttl / 5)
                && entry
                    .prefetching
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok();

            (resp, remaining_ttl, needs_prefetch)
        };

        // Turn the stored records into the response to this query
        resp.metadata.id = query.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.op_code = OpCode::Query;
        resp.metadata.authoritative = false;
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.queries = query.queries.clone();
        if let Some(edns) = &query.edns {
            resp.set_edns(edns.clone());
        }

        // Adjust TTL on records
        for record in resp
            .answers
            .iter_mut()
            .chain(resp.authorities.iter_mut())
            .chain(resp.additionals.iter_mut())
        {
            record.ttl = remaining_ttl;
        }

        self.stats.hits.fetch_add(1, Ordering::Relaxed);
        Some((resp, needs_prefetch))
    }

    /// Insert response into cache
    pub fn put(&self, query: &Message, response: &Message) {
        if !self.config.enabled {
            return;
        }

        // Only cache complete NoError and NXDomain answers
        let rcode = response.metadata.response_code;
        if (rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain) || response.metadata.truncation {
            return;
        }

        let Some(key) = CacheKey::for_query(query) else {
            return;
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

        // Store only what `get` cannot rebuild from the query: rcode and records
        let mut stored = Message::new(0, MessageType::Response, OpCode::Query);
        stored.metadata.response_code = rcode;
        stored.answers = response.answers.clone();
        stored.authorities = response.authorities.clone();
        stored.additionals = response.additionals.clone();
        let Ok(wire) = stored.to_vec() else {
            return;
        };

        let entry = CacheEntry {
            cached_at: Instant::now(),
            clamped_ttl,
            hits: AtomicU32::new(0),
            prefetching: AtomicBool::new(false),
            wire: wire.into_boxed_slice(),
        };

        let mut guard = self.entries.write();

        // Enforce max capacity
        if guard.len() >= self.config.max_items && !guard.contains_key(&key) {
            self.make_room(&mut guard);
        }

        guard.insert(key, entry);
    }

    /// Frees at least a tenth of the capacity: expired entries first, then the oldest.
    /// Freeing a batch keeps this O(n) scan rare instead of running on every insert.
    fn make_room(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        let now = Instant::now();
        let initial_len = entries.len();
        entries.retain(|_, v| !v.is_expired(now));

        let target = self.config.max_items - self.config.max_items / 10;
        if entries.len() > target {
            // Cut-off time for the oldest entries, found without cloning keys or sorting
            let excess = entries.len() - target;
            let mut ages: Vec<Instant> = entries.values().map(|v| v.cached_at).collect();
            let (_, &mut cutoff, _) = ages.select_nth_unstable(excess - 1);
            entries.retain(|_, v| v.cached_at > cutoff);
        }

        let removed = initial_len - entries.len();
        self.stats.evictions.fetch_add(removed as u64, Ordering::Relaxed);
        debug!(evicted = removed, "Cache evicted entries due to capacity limit");
    }

    /// Drops expired entries; run periodically so memory is released without waiting
    /// for the cache to fill up.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.entries.write();
        let initial_len = guard.len();
        guard.retain(|_, v| !v.is_expired(now));
        let len = guard.len();
        let removed = initial_len - len;
        if guard.capacity() > 1024 && guard.capacity() > len * 4 {
            guard.shrink_to(len * 2);
        }
        drop(guard);
        self.stats.evictions.fetch_add(removed as u64, Ordering::Relaxed);
        removed
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
    use hickory_proto::op::{Edns, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{RData, Record};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn query_for(name: &str, id: u16) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = name.parse().unwrap();
        q.query_type = RecordType::A;
        q.query_class = DNSClass::IN;
        query.queries.push(q);
        query
    }

    fn response_for(query: &Message, ttl: u32) -> Message {
        let name = query.queries[0].name.clone();
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.add_answer(Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))));
        resp
    }

    #[test]
    fn test_cache_insertion_and_retrieval() {
        let mut config = CachingConfig::default();
        config.min_ttl = Duration::from_secs(10);
        config.max_ttl = Duration::from_secs(300);

        let cache = DnsCache::new(config);

        let query = query_for("example.com.", 100);
        let resp = response_for(&query, 60);

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
    fn test_cached_response_matches_the_new_query() {
        let cache = DnsCache::new(CachingConfig::default());
        let query = query_for("www.example.com.", 1);
        let mut resp = Message::new(1, MessageType::Response, OpCode::Query);
        resp.queries = query.queries.clone();
        let target: Name = "cdn.example.net.".parse().unwrap();
        resp.add_answer(Record::from_rdata(query.queries[0].name.clone(), 600, RData::CNAME(CNAME(target.clone()))));
        resp.add_answer(Record::from_rdata(target, 600, RData::A(A(Ipv4Addr::new(10, 0, 0, 1)))));
        cache.put(&query, &resp);

        // Same name in other case, other id, with EDNS
        let mut second = query_for("WWW.Example.com.", 4242);
        second.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        second.set_edns(edns);

        let (cached, _) = cache.get(&second).expect("hit");
        assert_eq!(cached.metadata.id, 4242);
        assert_eq!(cached.metadata.message_type, MessageType::Response);
        assert!(cached.metadata.recursion_desired);
        assert!(cached.metadata.recursion_available);
        assert_eq!(cached.queries, second.queries);
        assert_eq!(cached.edns.as_ref().map(|e| e.max_payload()), Some(1232));
        assert_eq!(cached.answers.len(), 2);
        assert!(matches!(cached.answers[0].data, RData::CNAME(_)));
        assert!(cached.answers.iter().all(|r| r.ttl == 600));
    }

    #[test]
    fn test_ttl_clamping() {
        let mut config = CachingConfig::default();
        config.min_ttl = Duration::from_secs(100);
        config.max_ttl = Duration::from_secs(500);

        let cache = DnsCache::new(config);

        let query = query_for("fast-ttl.com.", 1);
        // Server returned 5s TTL
        cache.put(&query, &response_for(&query, 5));

        // Clamped TTL should be min_ttl (100)
        let (cached_resp, _) = cache.get(&query).unwrap();
        assert!(cached_resp.answers[0].ttl >= 99);
    }

    #[test]
    fn test_prefetch_triggers_once() {
        let mut config = CachingConfig::default();
        config.prefetching = true;
        config.prefetch_threshold = 2;
        config.min_ttl = Duration::from_secs(1);
        let cache = DnsCache::new(config);

        // 20s TTL: inside the prefetch window right away
        let query = query_for("popular.example.", 1);
        cache.put(&query, &response_for(&query, 20));

        let prefetches: Vec<bool> = (0..10).map(|_| cache.get(&query).unwrap().1).collect();
        assert_eq!(prefetches.iter().filter(|&&p| p).count(), 1);
        assert!(!prefetches[0]);

        // The refreshed entry can be prefetched again
        cache.put(&query, &response_for(&query, 20));
        assert!((0..3).any(|_| cache.get(&query).unwrap().1));
    }

    #[test]
    fn test_capacity_evicts_a_batch_of_oldest() {
        let mut config = CachingConfig::default();
        config.max_items = 100;
        let cache = DnsCache::new(config);

        for i in 0..100 {
            let query = query_for(&format!("host{i}.example."), 1);
            cache.put(&query, &response_for(&query, 300));
        }
        assert_eq!(cache.len(), 100);

        let newest = query_for("newest.example.", 1);
        cache.put(&newest, &response_for(&newest, 300));
        assert!(cache.len() <= 91, "len {}", cache.len());
        assert!(cache.get(&newest).is_some());
        assert!(cache.get(&query_for("host0.example.", 1)).is_none());
        assert!(cache.get(&query_for("host99.example.", 1)).is_some());
    }
}
