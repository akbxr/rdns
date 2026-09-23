use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct Metrics {
    pub total_queries: AtomicU64,
    pub blocked_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub custom_dns_hits: AtomicU64,
    pub upstream_queries: AtomicU64,
    pub upstream_errors: AtomicU64,

    // Labeled counters: (metric_name, labels_key) -> count
    labeled_counters: RwLock<HashMap<(String, String), Arc<AtomicU64>>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_query(&self, client_group: &str, qtype: &str) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        let labels = format!("client=\"{client_group}\",type=\"{qtype}\"");
        self.inc_labeled("rdns_dns_queries_total", &labels);
    }

    pub fn inc_blocked(&self, client_group: &str, reason: &str) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
        let labels = format!("client=\"{client_group}\",reason=\"{reason}\"");
        self.inc_labeled("rdns_dns_blocked_total", &labels);
    }

    pub fn inc_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_custom_dns_hit(&self) {
        self.custom_dns_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_query(&self, upstream: &str) {
        self.upstream_queries.fetch_add(1, Ordering::Relaxed);
        let labels = format!("upstream=\"{upstream}\"");
        self.inc_labeled("rdns_dns_upstream_queries_total", &labels);
    }

    pub fn inc_upstream_error(&self, upstream: &str) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        let labels = format!("upstream=\"{upstream}\"");
        self.inc_labeled("rdns_dns_upstream_errors_total", &labels);
    }

    fn inc_labeled(&self, metric: &str, labels: &str) {
        let key = (metric.to_string(), labels.to_string());
        {
            let guard = self.labeled_counters.read();
            if let Some(counter) = guard.get(&key) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let mut guard = self.labeled_counters.write();
        let counter = guard
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Render metrics in Prometheus text exposition format
    pub fn render_prometheus(&self, blocked_rules: usize, cache_entries: usize) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str("# HELP rdns_dns_queries_total Total DNS queries received\n");
        out.push_str("# TYPE rdns_dns_queries_total counter\n");
        out.push_str(&format!(
            "rdns_dns_queries_total {}\n",
            self.total_queries.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP rdns_dns_blocked_total Total DNS queries blocked\n");
        out.push_str("# TYPE rdns_dns_blocked_total counter\n");
        out.push_str(&format!(
            "rdns_dns_blocked_total {}\n",
            self.blocked_queries.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP rdns_dns_cache_hits_total Total DNS cache hits\n");
        out.push_str("# TYPE rdns_dns_cache_hits_total counter\n");
        out.push_str(&format!(
            "rdns_dns_cache_hits_total {}\n",
            self.cache_hits.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP rdns_dns_cache_misses_total Total DNS cache misses\n");
        out.push_str("# TYPE rdns_dns_cache_misses_total counter\n");
        out.push_str(&format!(
            "rdns_dns_cache_misses_total {}\n",
            self.cache_misses.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP rdns_dns_custom_dns_hits_total Total Custom DNS hits\n");
        out.push_str("# TYPE rdns_dns_custom_dns_hits_total counter\n");
        out.push_str(&format!(
            "rdns_dns_custom_dns_hits_total {}\n",
            self.custom_dns_hits.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP rdns_dns_blocked_rules Total number of active blocklist rules\n");
        out.push_str("# TYPE rdns_dns_blocked_rules gauge\n");
        out.push_str(&format!("rdns_dns_blocked_rules {blocked_rules}\n"));

        out.push_str("# HELP rdns_dns_cache_entries Total number of cached DNS entries\n");
        out.push_str("# TYPE rdns_dns_cache_entries gauge\n");
        out.push_str(&format!("rdns_dns_cache_entries {cache_entries}\n"));

        // Labeled metrics
        let guard = self.labeled_counters.read();
        for ((metric, labels), counter) in guard.iter() {
            let val = counter.load(Ordering::Relaxed);
            out.push_str(&format!("{metric}{{{labels}}} {val}\n"));
        }

        out
    }
}
