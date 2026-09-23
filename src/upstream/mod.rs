pub mod doh;
pub mod dot;
pub mod tcp;
pub mod udp;

use crate::config::{UpstreamStrategy, UpstreamsConfig};
use doh::DohResolver;
use dot::DotResolver;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::Message;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tcp::TcpResolver;
use tracing::{debug, warn};
use udp::UdpResolver;

#[derive(Debug, Clone)]
pub enum Upstream {
    Udp(UdpResolver),
    Tcp(TcpResolver),
    Dot(DotResolver),
    Doh(DohResolver),
}

impl Upstream {
    pub fn name(&self) -> &str {
        match self {
            Self::Udp(u) => &u.name,
            Self::Tcp(t) => &t.name,
            Self::Dot(d) => &d.name,
            Self::Doh(h) => &h.name,
        }
    }

    pub async fn resolve(&self, query: &Message, timeout: Duration) -> Result<Message, String> {
        match self {
            Self::Udp(u) => u.resolve(query, timeout).await,
            Self::Tcp(t) => t.resolve(query, timeout).await,
            Self::Dot(d) => d.resolve(query, timeout).await,
            Self::Doh(h) => h.resolve(query, timeout).await,
        }
    }

    /// Parse upstream definition string:
    /// - "udp:1.1.1.1:53" or "1.1.1.1:53" or "1.1.1.1" -> UDP
    /// - "tcp:1.1.1.1:53" -> TCP
    /// - "dot:1.1.1.1:853#cloudflare-dns.com" or "dot:cloudflare-dns.com:853" -> DoT
    /// - "https://cloudflare-dns.com/dns-query" or "doh:https://..." -> DoH
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.starts_with("https://") || s.starts_with("http://") {
            return Ok(Self::Doh(DohResolver::new(s.to_string())));
        }
        if let Some(rest) = s.strip_prefix("doh:") {
            return Ok(Self::Doh(DohResolver::new(rest.to_string())));
        }

        if let Some(rest) = s.strip_prefix("dot:") {
            // dot:target#sni or dot:host:port
            let (target_str, sni) = if let Some((tgt, sni_part)) = rest.split_once('#') {
                (tgt, sni_part.to_string())
            } else {
                let host_only = if let Some((h, _p)) = rest.rsplit_once(':') {
                    h
                } else {
                    rest
                };
                (rest, host_only.to_string())
            };

            let socket_addr = resolve_to_socket_addr(target_str, 853)?;
            return Ok(Self::Dot(DotResolver::new(socket_addr, sni)));
        }

        if let Some(rest) = s.strip_prefix("tcp:") {
            let socket_addr = resolve_to_socket_addr(rest, 53)?;
            return Ok(Self::Tcp(TcpResolver::new(socket_addr)));
        }

        let udp_str = s.strip_prefix("udp:").unwrap_or(s);
        let socket_addr = resolve_to_socket_addr(udp_str, 53)?;
        Ok(Self::Udp(UdpResolver::new(socket_addr)))
    }
}

fn resolve_to_socket_addr(addr_str: &str, default_port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let full_str = if !addr_str.contains(':') || addr_str.starts_with('[') && !addr_str.contains("]:") {
        format!("{addr_str}:{default_port}")
    } else {
        addr_str.to_string()
    };

    if let Ok(addr) = full_str.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Try system DNS resolution for hostnames
    let addrs: Vec<SocketAddr> = full_str
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve '{full_str}': {e}"))?
        .collect();

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("No socket addresses found for '{full_str}'"))
}

#[derive(Debug, Clone)]
pub struct UpstreamGroup {
    pub name: String,
    pub upstreams: Vec<Upstream>,
    pub strategy: UpstreamStrategy,
    pub timeout: Duration,
}

impl UpstreamGroup {
    pub fn new(
        name: String,
        upstreams: Vec<Upstream>,
        strategy: UpstreamStrategy,
        timeout: Duration,
    ) -> Self {
        Self {
            name,
            upstreams,
            strategy,
            timeout,
        }
    }

    pub async fn resolve(&self, query: &Message) -> Result<Message, String> {
        if self.upstreams.is_empty() {
            return Err(format!("Upstream group '{}' has no upstreams", self.name));
        }

        match self.strategy {
            UpstreamStrategy::Parallel => self.resolve_parallel(query).await,
            UpstreamStrategy::Strict => self.resolve_strict(query).await,
            UpstreamStrategy::Random => self.resolve_random(query).await,
        }
    }

    async fn resolve_parallel(&self, query: &Message) -> Result<Message, String> {
        let mut futures = FuturesUnordered::new();
        for upstream in &self.upstreams {
            let u = upstream.clone();
            let q = query.clone();
            let t = self.timeout;
            futures.push(async move {
                let res = u.resolve(&q, t).await;
                (u.name().to_string(), res)
            });
        }

        let mut last_error = String::new();
        while let Some((name, res)) = futures.next().await {
            match res {
                Ok(msg) => {
                    debug!(upstream = %name, "Upstream answered query in parallel race");
                    return Ok(msg);
                }
                Err(err) => {
                    warn!(upstream = %name, error = %err, "Upstream failed in parallel race");
                    last_error = err;
                }
            }
        }

        Err(format!(
            "All parallel upstreams in group '{}' failed. Last error: {last_error}",
            self.name
        ))
    }

    async fn resolve_strict(&self, query: &Message) -> Result<Message, String> {
        let mut last_error = String::new();
        for upstream in &self.upstreams {
            match upstream.resolve(query, self.timeout).await {
                Ok(msg) => return Ok(msg),
                Err(err) => {
                    warn!(upstream = %upstream.name(), error = %err, "Upstream failed in strict sequence");
                    last_error = err;
                }
            }
        }
        Err(format!(
            "All strict upstreams in group '{}' failed. Last error: {last_error}",
            self.name
        ))
    }

    async fn resolve_random(&self, query: &Message) -> Result<Message, String> {
        let mut indices: Vec<usize> = (0..self.upstreams.len()).collect();
        indices.shuffle(&mut rand::thread_rng());

        let mut last_error = String::new();
        for idx in indices {
            let upstream = &self.upstreams[idx];
            match upstream.resolve(query, self.timeout).await {
                Ok(msg) => return Ok(msg),
                Err(err) => {
                    warn!(upstream = %upstream.name(), error = %err, "Upstream failed in random sequence");
                    last_error = err;
                }
            }
        }
        Err(format!(
            "All random upstreams in group '{}' failed. Last error: {last_error}",
            self.name
        ))
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamRegistry {
    pub groups: HashMap<String, UpstreamGroup>,
    /// Suffix domain to group name mapping for conditional forwarding
    pub conditional_domains: Vec<(String, String)>,
}

impl UpstreamRegistry {
    pub fn from_config(
        upstreams_cfg: &UpstreamsConfig,
        conditional_map: &HashMap<String, String>,
    ) -> Result<Self, String> {
        let mut groups = HashMap::new();

        for (grp_name, upstream_strs) in &upstreams_cfg.groups {
            let mut upstreams = Vec::new();
            for s in upstream_strs {
                let u = Upstream::parse(s)
                    .map_err(|e| format!("Failed to parse upstream '{s}' in group '{grp_name}': {e}"))?;
                upstreams.push(u);
            }
            groups.insert(
                grp_name.clone(),
                UpstreamGroup::new(
                    grp_name.clone(),
                    upstreams,
                    upstreams_cfg.strategy,
                    upstreams_cfg.timeout,
                ),
            );
        }

        // Process conditional mappings
        let mut conditional_domains = Vec::new();
        for (domain, target) in conditional_map {
            let norm_domain = domain.trim().trim_end_matches('.').to_lowercase();
            // If target is an address rather than a group name, create an ad-hoc group if needed
            if !groups.contains_key(target) {
                // Try parsing target as upstream(s)
                if let Ok(u) = Upstream::parse(target) {
                    let adhoc_group = UpstreamGroup::new(
                        format!("adhoc_{norm_domain}"),
                        vec![u],
                        UpstreamStrategy::Strict,
                        upstreams_cfg.timeout,
                    );
                    let grp_name = format!("adhoc_{norm_domain}");
                    groups.insert(grp_name.clone(), adhoc_group);
                    conditional_domains.push((norm_domain, grp_name));
                    continue;
                }
            }
            conditional_domains.push((norm_domain, target.clone()));
        }

        // Sort conditional domains by length descending so more specific suffixes match first
        conditional_domains.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Ok(Self {
            groups,
            conditional_domains,
        })
    }

    pub fn get_default_group(&self) -> Option<&UpstreamGroup> {
        self.groups.get("default")
    }

    pub fn get_group(&self, name: &str) -> Option<&UpstreamGroup> {
        self.groups.get(name)
    }

    /// Match domain against conditional forwarding rules
    pub fn get_for_domain(&self, domain: &str) -> Option<&UpstreamGroup> {
        let norm_domain = domain.trim().trim_end_matches('.').to_lowercase();
        for (cond_domain, group_name) in &self.conditional_domains {
            if norm_domain == *cond_domain || norm_domain.ends_with(&format!(".{cond_domain}")) {
                if let Some(grp) = self.groups.get(group_name) {
                    return Some(grp);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_parsing() {
        let u1 = Upstream::parse("udp:1.1.1.1:53").unwrap();
        assert!(matches!(u1, Upstream::Udp(_)));

        let u2 = Upstream::parse("tcp:1.0.0.1:53").unwrap();
        assert!(matches!(u2, Upstream::Tcp(_)));

        let u3 = Upstream::parse("https://cloudflare-dns.com/dns-query").unwrap();
        assert!(matches!(u3, Upstream::Doh(_)));

        let u4 = Upstream::parse("dot:1.1.1.1:853#cloudflare-dns.com").unwrap();
        assert!(matches!(u4, Upstream::Dot(_)));
    }

    #[test]
    fn test_conditional_routing() {
        let mut cfg = UpstreamsConfig::default();
        cfg.groups.insert(
            "lan".to_string(),
            vec!["udp:192.168.1.1:53".to_string()],
        );

        let mut conditional = HashMap::new();
        conditional.insert("home.lan".to_string(), "lan".to_string());
        conditional.insert("168.192.in-addr.arpa".to_string(), "lan".to_string());

        let reg = UpstreamRegistry::from_config(&cfg, &conditional).unwrap();
        assert!(reg.get_for_domain("server.home.lan").is_some());
        assert_eq!(
            reg.get_for_domain("server.home.lan").unwrap().name,
            "lan"
        );
        assert!(reg.get_for_domain("1.1.168.192.in-addr.arpa").is_some());
        assert!(reg.get_for_domain("google.com").is_none());
    }
}
