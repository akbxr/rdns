use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// Counter with one label. Incrementing an existing series does not allocate.
#[derive(Default)]
struct Counter1(RwLock<HashMap<String, AtomicU64>>);

impl Counter1 {
    fn inc(&self, a: &str) {
        if let Some(counter) = self.0.read().get(a) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.0
            .write()
            .entry(a.to_owned())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, metric: &str, label: &str) {
        for (a, counter) in self.0.read().iter() {
            let _ = writeln!(out, "{metric}{{{label}=\"{a}\"}} {}", counter.load(Ordering::Relaxed));
        }
    }
}

/// Counter with two labels. Incrementing an existing series does not allocate.
#[derive(Default)]
struct Counter2(RwLock<HashMap<String, HashMap<String, AtomicU64>>>);

impl Counter2 {
    fn inc(&self, a: &str, b: &str) {
        if let Some(counter) = self.0.read().get(a).and_then(|inner| inner.get(b)) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.0
            .write()
            .entry(a.to_owned())
            .or_default()
            .entry(b.to_owned())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, metric: &str, labels: (&str, &str)) {
        for (a, inner) in self.0.read().iter() {
            for (b, counter) in inner {
                let _ = writeln!(
                    out,
                    "{metric}{{{}=\"{a}\",{}=\"{b}\"}} {}",
                    labels.0,
                    labels.1,
                    counter.load(Ordering::Relaxed)
                );
            }
        }
    }
}

#[derive(Default)]
pub struct Metrics {
    pub total_queries: AtomicU64,
    pub blocked_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub custom_dns_hits: AtomicU64,
    pub upstream_queries: AtomicU64,
    pub upstream_errors: AtomicU64,

    queries_by_client_type: Counter2,
    blocked_by_client_reason: Counter2,
    upstream_queries_by_name: Counter1,
    upstream_errors_by_name: Counter1,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_query(&self, client_group: &str, qtype: &str) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.queries_by_client_type.inc(client_group, qtype);
    }

    /// `reason` should have few distinct values (list and rule kind, see
    /// `BlockReason::metric_label`): every value is a series kept in memory forever.
    pub fn inc_blocked(&self, client_group: &str, reason: &str) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
        self.blocked_by_client_reason.inc(client_group, reason);
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
        self.upstream_queries_by_name.inc(upstream);
    }

    pub fn inc_upstream_error(&self, upstream: &str) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        self.upstream_errors_by_name.inc(upstream);
    }

    /// Render metrics in Prometheus text exposition format
    pub fn render_prometheus(&self, blocked_rules: usize, cache_entries: usize) -> String {
        let mut out = String::with_capacity(2048);
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);

        for (name, kind, help, value) in [
            ("rdns_dns_queries_total", "counter", "Total DNS queries received", load(&self.total_queries)),
            ("rdns_dns_blocked_total", "counter", "Total DNS queries blocked", load(&self.blocked_queries)),
            ("rdns_dns_cache_hits_total", "counter", "Total DNS cache hits", load(&self.cache_hits)),
            ("rdns_dns_cache_misses_total", "counter", "Total DNS cache misses", load(&self.cache_misses)),
            ("rdns_dns_custom_dns_hits_total", "counter", "Total Custom DNS hits", load(&self.custom_dns_hits)),
            ("rdns_dns_blocked_rules", "gauge", "Total number of active blocklist rules", blocked_rules as u64),
            ("rdns_dns_cache_entries", "gauge", "Total number of cached DNS entries", cache_entries as u64),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}");
        }

        // Labeled metrics
        self.queries_by_client_type
            .render(&mut out, "rdns_dns_queries_total", ("client", "type"));
        self.blocked_by_client_reason
            .render(&mut out, "rdns_dns_blocked_total", ("client", "reason"));
        self.upstream_queries_by_name
            .render(&mut out, "rdns_dns_upstream_queries_total", "upstream");
        self.upstream_errors_by_name
            .render(&mut out, "rdns_dns_upstream_errors_total", "upstream");

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_labeled_counters() {
        let metrics = Metrics::new();
        metrics.inc_query("default", "A");
        metrics.inc_query("default", "A");
        metrics.inc_query("kids", "AAAA");
        metrics.inc_blocked("default", "blacklist:ads");
        metrics.inc_upstream_query("udp:1.1.1.1:53");
        metrics.inc_upstream_error("udp:1.1.1.1:53");

        let out = metrics.render_prometheus(10, 3);
        assert!(out.contains("rdns_dns_queries_total 3\n"));
        assert!(out.contains("rdns_dns_queries_total{client=\"default\",type=\"A\"} 2\n"));
        assert!(out.contains("rdns_dns_queries_total{client=\"kids\",type=\"AAAA\"} 1\n"));
        assert!(out.contains("rdns_dns_blocked_total{client=\"default\",reason=\"blacklist:ads\"} 1\n"));
        assert!(out.contains("rdns_dns_upstream_queries_total{upstream=\"udp:1.1.1.1:53\"} 1\n"));
        assert!(out.contains("rdns_dns_upstream_errors_total{upstream=\"udp:1.1.1.1:53\"} 1\n"));
        assert!(out.contains("# TYPE rdns_dns_blocked_rules gauge\nrdns_dns_blocked_rules 10\n"));
    }
}
