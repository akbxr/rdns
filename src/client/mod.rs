use crate::config::ClientLookupConfig;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
struct ClientRule {
    net: IpNet,
    groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ClientMatcher {
    rules: Vec<ClientRule>,
    default_groups: Vec<String>,
}

impl ClientMatcher {
    pub fn from_config(config: &ClientLookupConfig) -> Self {
        let mut rules = Vec::new();

        for (ip_or_cidr, groups) in &config.clients {
            let parsed_net = if let Ok(net) = ip_or_cidr.parse::<IpNet>() {
                Some(net)
            } else if let Ok(ip) = ip_or_cidr.parse::<IpAddr>() {
                Some(IpNet::from(ip))
            } else {
                None
            };

            if let Some(net) = parsed_net {
                rules.push(ClientRule {
                    net,
                    groups: groups.clone(),
                });
            }
        }

        // Sort rules by prefix length descending (most specific /32 or /128 first)
        rules.sort_by(|a, b| b.net.prefix_len().cmp(&a.net.prefix_len()));

        Self {
            rules,
            default_groups: vec!["default".to_string()],
        }
    }

    /// Match a client IP address to its configured client groups.
    /// Falls back to ["default"] if no rule matches.
    pub fn get_client_groups(&self, ip: IpAddr) -> &[String] {
        for rule in &self.rules {
            if rule.net.contains(&ip) {
                return &rule.groups;
            }
        }
        &self.default_groups
    }

    /// Get primary group name for logging/metrics
    pub fn get_primary_group(&self, ip: IpAddr) -> &str {
        self.get_client_groups(ip)
            .first()
            .map(|s| s.as_str())
            .unwrap_or("default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_client_matching_specificity() {
        let mut clients = HashMap::new();
        clients.insert("192.168.1.0/24".to_string(), vec!["lan".to_string()]);
        clients.insert("192.168.1.100".to_string(), vec!["kids".to_string()]);
        clients.insert("10.0.0.0/8".to_string(), vec!["corporate".to_string()]);

        let config = ClientLookupConfig { clients };
        let matcher = ClientMatcher::from_config(&config);

        // Exact IP 192.168.1.100 should match "kids", NOT "lan"
        let kids_ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(matcher.get_client_groups(kids_ip), &["kids".to_string()]);

        // Sibling IP 192.168.1.50 should match subnet "lan"
        let lan_ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(matcher.get_client_groups(lan_ip), &["lan".to_string()]);

        // Corporate IP
        let corp_ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(matcher.get_client_groups(corp_ip), &["corporate".to_string()]);

        // Unknown IP should fallback to "default"
        let external_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.get_client_groups(external_ip), &["default".to_string()]);
    }
}
