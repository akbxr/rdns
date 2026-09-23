use flate2::read::GzDecoder;
use regex::Regex;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, Default, Clone)]
pub struct ParsedList {
    pub domains: HashSet<String>,
    pub regexes: Vec<Regex>,
}

impl ParsedList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.regexes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.domains.len() + self.regexes.len()
    }

    pub fn merge(&mut self, other: ParsedList) {
        self.domains.extend(other.domains);
        self.regexes.extend(other.regexes);
    }
}

pub struct ListParser;

impl ListParser {
    /// Parse lines of text from any supported format into `ParsedList`
    pub fn parse_content(content: &str) -> ParsedList {
        let mut result = ParsedList::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Skip comments and headers
            if line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
                continue;
            }

            // Regex format: /pattern/
            if line.starts_with('/') && line.len() > 2 {
                if let Some(pattern) = line.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                    match Regex::new(pattern) {
                        Ok(re) => {
                            result.regexes.push(re);
                            continue;
                        }
                        Err(e) => {
                            warn!("Invalid regex pattern '/{pattern}/': {e}");
                            continue;
                        }
                    }
                }
            }

            // Adblock Plus / ABP format: ||example.com^
            if let Some(abp_rest) = line.strip_prefix("||") {
                let domain_part = abp_rest
                    .split(&['^', '$', '/', '|'][..])
                    .next()
                    .unwrap_or("")
                    .trim();
                if let Some(norm) = normalize_domain(domain_part) {
                    result.domains.insert(norm);
                }
                continue;
            }

            // Hosts file or plain domain format:
            // Strip inline comments starting with '#'
            let effective_line = if let Some((before_hash, _)) = line.split_once('#') {
                before_hash.trim()
            } else {
                line
            };

            let tokens: Vec<&str> = effective_line.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            // Check if first token is an IP address (Hosts format)
            if tokens[0].parse::<std::net::IpAddr>().is_ok() {
                // Tokens after the IP are domain names
                for &token in &tokens[1..] {
                    if let Some(norm) = normalize_domain(token) {
                        // Skip localhost and standard loopback hostnames
                        if norm != "localhost"
                            && norm != "localhost.localdomain"
                            && norm != "broadcasthost"
                            && norm != "local"
                            && norm != "ip6-localhost"
                            && norm != "ip6-loopback"
                        {
                            result.domains.insert(norm);
                        }
                    }
                }
            } else {
                // Plain domain list or single domain
                if let Some(norm) = normalize_domain(tokens[0]) {
                    result.domains.insert(norm);
                }
            }
        }

        result
    }

    /// Load list from URL, local file, or direct inline string
    pub async fn load_source(
        source: &str,
        client: &reqwest::Client,
        timeout: Duration,
        max_attempts: u32,
        cooldown: Duration,
    ) -> Result<ParsedList, String> {
        let source = source.trim();

        if source.starts_with("http://") || source.starts_with("https://") {
            let mut attempts = 0;
            let mut last_err = String::new();

            while attempts < max_attempts {
                attempts += 1;
                debug!(source = %source, attempt = attempts, "Fetching blocklist URL");

                match tokio::time::timeout(timeout, client.get(source).send()).await {
                    Ok(Ok(resp)) => {
                        if !resp.status().is_success() {
                            last_err = format!("HTTP {}", resp.status());
                        } else {
                            match resp.bytes().await {
                                Ok(bytes) => {
                                    let content = decode_bytes(&bytes, source)?;
                                    return Ok(Self::parse_content(&content));
                                }
                                Err(e) => last_err = format!("Failed to read response body: {e}"),
                            }
                        }
                    }
                    Ok(Err(e)) => last_err = format!("Request error: {e}"),
                    Err(_) => last_err = format!("Timed out after {:?}", timeout),
                }

                if attempts < max_attempts {
                    tokio::time::sleep(cooldown).await;
                }
            }

            Err(format!(
                "Failed to fetch blocklist '{source}' after {attempts} attempts: {last_err}"
            ))
        } else {
            // Check if it's a file path
            let path_str = source.strip_prefix("file://").unwrap_or(source);
            let path = Path::new(path_str);
            if path.exists() {
                let bytes = tokio::fs::read(path)
                    .await
                    .map_err(|e| format!("Failed to read file '{path_str}': {e}"))?;
                let content = decode_bytes(&bytes, path_str)?;
                Ok(Self::parse_content(&content))
            } else {
                // Treat as direct inline entry (domain or regex)
                Ok(Self::parse_content(source))
            }
        }
    }
}

fn decode_bytes(bytes: &[u8], source_hint: &str) -> Result<String, String> {
    // Check if gzipped (magic bytes: 0x1f, 0x8b or .gz extension)
    let is_gzip = source_hint.ends_with(".gz") || (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b);

    if is_gzip {
        let mut decoder = GzDecoder::new(bytes);
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .map_err(|e| format!("Gzip decompression failed for '{source_hint}': {e}"))?;
        Ok(decompressed)
    } else {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Normalizes domain name: lowercase, trim whitespace and trailing/leading dots
pub fn normalize_domain(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches('.').trim_end_matches('.').to_lowercase();
    if s.is_empty() || s.contains(' ') || s.contains('\t') {
        return None;
    }
    // Basic domain validation: letters, digits, dots, hyphens, underscores
    if s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_') && s.contains('.') {
        Some(s)
    } else if s == "localhost" {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_format() {
        let hosts = r#"
# Sample hosts file
127.0.0.1 localhost
127.0.0.1 ad.doubleclick.net ad2.doubleclick.net # inline comment
0.0.0.0 tracker.analytics.com
::1 ipv6.ads.com
"#;
        let parsed = ListParser::parse_content(hosts);
        assert!(!parsed.domains.contains("localhost"));
        assert!(parsed.domains.contains("ad.doubleclick.net"));
        assert!(parsed.domains.contains("ad2.doubleclick.net"));
        assert!(parsed.domains.contains("tracker.analytics.com"));
        assert!(parsed.domains.contains("ipv6.ads.com"));
        assert_eq!(parsed.domains.len(), 4);
    }

    #[test]
    fn test_parse_abp_format() {
        let abp = r#"
[Adblock Plus 2.0]
! Title: EasyList
||ads.example.com^
||tracking.com^$third-party
||banner.net/image.png
"#;
        let parsed = ListParser::parse_content(abp);
        assert!(parsed.domains.contains("ads.example.com"));
        assert!(parsed.domains.contains("tracking.com"));
        assert!(parsed.domains.contains("banner.net"));
        assert_eq!(parsed.domains.len(), 3);
    }

    #[test]
    fn test_parse_regex_and_plain_domains() {
        let content = r#"
adservice.google.com
/.*\.telemetry\.microsoft\.com$/
/^ad[0-9]*\.example\.com$/
"#;
        let parsed = ListParser::parse_content(content);
        assert!(parsed.domains.contains("adservice.google.com"));
        assert_eq!(parsed.regexes.len(), 2);
    }
}
