use flate2::write::GzDecoder;
use hickory_proto::rr::Name;
use regex::Regex;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

/// Sets with at least this many domains are stored bucketed (see `DomainSet`). Below it
/// the bucket index (256 KiB) costs more than the 2 bytes per domain it saves.
const BUCKETED_MIN_LEN: usize = 1 << 17;
const BUCKET_BITS: u32 = 16;
const BUCKETS: usize = 1 << BUCKET_BITS;
const LOW_BITS: u32 = 64 - BUCKET_BITS;
const LOW_MASK: u64 = (1 << LOW_BITS) - 1;

/// Longest list line kept; longer lines are not domains and are skipped, so a file
/// without newlines cannot make the parser buffer all of it.
const MAX_LINE_LEN: usize = 16 * 1024;

/// Set of domain names stored as sorted, deduplicated 64-bit hashes.
///
/// Blocklists hold millions of domains; a `HashSet<String>` costs about 100 bytes per
/// domain, which on a 1 GB server (and twice that while a refresh builds the new lists)
/// pushed the host into swap. A hash costs 8 bytes. The chance that a domain not on a
/// list matches one that is, with 5 million entries, is about 3 in 10^13 per lookup.
///
/// Large sets go further: the top 16 bits of each hash select a bucket and only the low
/// 48 bits are stored, packed into 6 bytes. The hashes are the same, so is the false-match
/// rate, but a domain costs 6 bytes instead of 8, and a lookup binary-searches one bucket
/// of about a hundred entries instead of the whole list.
#[derive(Debug, Clone)]
pub struct DomainSet {
    repr: Repr,
}

#[derive(Debug, Clone)]
enum Repr {
    Flat(Vec<u64>),
    /// `offsets[b]..offsets[b + 1]` is the range of bucket `b` in `low`.
    Bucketed { offsets: Box<[u32]>, low: Packed48 },
}

impl Default for DomainSet {
    fn default() -> Self {
        Self {
            repr: Repr::Flat(Vec::new()),
        }
    }
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from unsorted hashes that may contain duplicates.
    fn from_hashes(mut hashes: Vec<u64>) -> Self {
        hashes.sort_unstable();
        hashes.dedup();
        Self::from_sorted(hashes)
    }

    /// Builds a set from sorted, deduplicated hashes, reusing their buffer.
    fn from_sorted(mut hashes: Vec<u64>) -> Self {
        if hashes.len() < BUCKETED_MIN_LEN || hashes.len() > u32::MAX as usize {
            hashes.shrink_to_fit();
            return Self {
                repr: Repr::Flat(hashes),
            };
        }
        let mut offsets = vec![0u32; BUCKETS + 1];
        for &hash in &hashes {
            offsets[(hash >> LOW_BITS) as usize + 1] += 1;
        }
        for bucket in 0..BUCKETS {
            offsets[bucket + 1] += offsets[bucket];
        }
        Self {
            repr: Repr::Bucketed {
                offsets: offsets.into_boxed_slice(),
                low: Packed48::pack_in_place(hashes),
            },
        }
    }

    /// Adds a domain, which is expected to be normalized already. Returns false when it
    /// was present. Inserting keeps the set sorted, so it is O(n): use it for a few
    /// entries; lists are built in bulk by `ListBuilder`.
    pub fn insert(&mut self, domain: impl AsRef<str>) -> bool {
        let hash = domain_hash(domain.as_ref());
        if self.contains_hash(hash) {
            return false;
        }
        let mut hashes = match std::mem::take(&mut self.repr) {
            Repr::Flat(hashes) => hashes,
            bucketed => DomainSet { repr: bucketed }.iter().collect(),
        };
        let index = hashes.partition_point(|&h| h < hash);
        hashes.insert(index, hash);
        *self = Self::from_sorted(hashes);
        true
    }

    pub fn contains(&self, domain: &str) -> bool {
        self.contains_hash(domain_hash(domain))
    }

    /// Looks up a hash computed with `domain_hash`.
    #[inline]
    pub fn contains_hash(&self, hash: u64) -> bool {
        match &self.repr {
            Repr::Flat(hashes) => hashes.binary_search(&hash).is_ok(),
            Repr::Bucketed { offsets, low } => {
                let bucket = (hash >> LOW_BITS) as usize;
                let key = hash & LOW_MASK;
                let (mut lo, mut hi) = (offsets[bucket] as usize, offsets[bucket + 1] as usize);
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    match low.get(mid).cmp(&key) {
                        std::cmp::Ordering::Less => lo = mid + 1,
                        std::cmp::Ordering::Greater => hi = mid,
                        std::cmp::Ordering::Equal => return true,
                    }
                }
                false
            }
        }
    }

    pub fn len(&self) -> usize {
        match &self.repr {
            Repr::Flat(hashes) => hashes.len(),
            Repr::Bucketed { low, .. } => low.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes of heap memory the set holds.
    pub fn heap_bytes(&self) -> usize {
        match &self.repr {
            Repr::Flat(hashes) => hashes.capacity() * 8,
            Repr::Bucketed { offsets, low } => offsets.len() * 4 + low.words.capacity() * 8,
        }
    }

    pub fn extend(&mut self, other: DomainSet) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            *self = other;
            return;
        }
        let mut hashes = Vec::with_capacity(self.len() + other.len());
        hashes.extend(self.iter());
        hashes.extend(other.iter());
        drop(other);
        self.repr = Repr::Flat(Vec::new());
        *self = Self::from_hashes(hashes);
    }

    /// The hashes in ascending order.
    fn iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
        match &self.repr {
            Repr::Flat(hashes) => Box::new(hashes.iter().copied()),
            Repr::Bucketed { offsets, low } => Box::new((0..BUCKETS).flat_map(move |bucket| {
                (offsets[bucket] as usize..offsets[bucket + 1] as usize)
                    .map(move |i| ((bucket as u64) << LOW_BITS) | low.get(i))
            })),
        }
    }
}

impl Default for Repr {
    fn default() -> Self {
        Repr::Flat(Vec::new())
    }
}

/// 48-bit values packed back to back into 64-bit words.
#[derive(Debug, Clone)]
struct Packed48 {
    words: Vec<u64>,
    len: usize,
}

impl Packed48 {
    /// Packs the low 48 bits of each value into the vector's own buffer, so building a
    /// large set does not need a second copy of it.
    fn pack_in_place(mut values: Vec<u64>) -> Self {
        let len = values.len();
        for i in 0..len {
            let value = values[i] & LOW_MASK;
            // Entry i ends before bit 48i + 48, within word i, so writing it never
            // overwrites a value that has not been read yet.
            write48(&mut values, i, value);
        }
        values.truncate((len * LOW_BITS as usize).div_ceil(64));
        values.shrink_to_fit();
        Self { words: values, len }
    }

    #[inline]
    fn get(&self, i: usize) -> u64 {
        let bit = i * LOW_BITS as usize;
        let (word, shift) = (bit / 64, (bit % 64) as u32);
        let low = self.words[word] >> shift;
        if shift + LOW_BITS <= 64 {
            low & LOW_MASK
        } else {
            (low | (self.words[word + 1] << (64 - shift))) & LOW_MASK
        }
    }
}

fn write48(words: &mut [u64], i: usize, value: u64) {
    let bit = i * LOW_BITS as usize;
    let (word, shift) = (bit / 64, (bit % 64) as u32);
    words[word] = (words[word] & !(LOW_MASK << shift)) | (value << shift);
    if shift + LOW_BITS > 64 {
        let spill_mask = (1u64 << (shift + LOW_BITS - 64)) - 1;
        words[word + 1] = (words[word + 1] & !spill_mask) | (value >> (64 - shift));
    }
}

/// Hash of a normalized domain. `DefaultHasher::new()` uses fixed keys, so the same
/// domain always gives the same hash within a build.
pub fn domain_hash(domain: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Default, Clone)]
pub struct ParsedList {
    pub domains: DomainSet,
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

    /// Bytes of heap memory held by the domain set (regexes not counted).
    pub fn heap_bytes(&self) -> usize {
        self.domains.heap_bytes()
    }

    pub fn merge(&mut self, other: ParsedList) {
        self.domains.extend(other.domains);
        self.regexes.extend(other.regexes);
    }
}

/// Collects the entries of one list, from any number of sources, as their bytes arrive.
#[derive(Default)]
pub struct ListBuilder {
    hashes: Vec<u64>,
    regexes: Vec<Regex>,
    /// Start of a line whose end has not arrived yet.
    partial: Vec<u8>,
    /// The current line grew past `MAX_LINE_LEN`: drop it up to the next newline.
    skipping_line: bool,
    /// Reused buffer for normalizing domains.
    norm: String,
}

/// Position in a `ListBuilder`, to drop what a source added when loading it fails.
#[derive(Debug, Clone, Copy)]
pub struct ListMark {
    hashes: usize,
    regexes: usize,
}

impl ListBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark(&self) -> ListMark {
        ListMark {
            hashes: self.hashes.len(),
            regexes: self.regexes.len(),
        }
    }

    /// Drops the entries added since `mark`, and any unfinished line.
    pub fn rollback(&mut self, mark: ListMark) {
        self.hashes.truncate(mark.hashes);
        self.regexes.truncate(mark.regexes);
        self.partial.clear();
        self.skipping_line = false;
    }

    /// Domain and regex entries added since `mark` (domains before deduplication).
    pub fn added_since(&self, mark: ListMark) -> (usize, usize) {
        (self.hashes.len() - mark.hashes, self.regexes.len() - mark.regexes)
    }

    /// Parses list bytes; a line may be split across calls.
    pub fn feed(&mut self, mut data: &[u8]) {
        while let Some(newline) = data.iter().position(|&b| b == b'\n') {
            let (line, rest) = data.split_at(newline);
            data = &rest[1..];
            if self.skipping_line {
                self.skipping_line = false;
            } else if self.partial.is_empty() {
                self.parse_line_bytes(line);
            } else {
                let mut full = std::mem::take(&mut self.partial);
                full.extend_from_slice(line);
                self.parse_line_bytes(&full);
                full.clear();
                self.partial = full;
            }
        }
        if !self.skipping_line {
            self.partial.extend_from_slice(data);
            if self.partial.len() > MAX_LINE_LEN {
                self.partial.clear();
                self.skipping_line = true;
            }
        }
    }

    /// Ends the current source: parses its last line if it had no trailing newline.
    pub fn end_source(&mut self) {
        if !self.partial.is_empty() && !self.skipping_line {
            let line = std::mem::take(&mut self.partial);
            self.parse_line_bytes(&line);
        }
        self.partial.clear();
        self.skipping_line = false;
    }

    /// Sorts and deduplicates the collected domains into a `ParsedList`. This takes a
    /// while for millions of entries: call it off the async workers.
    pub fn finish(mut self) -> ParsedList {
        self.end_source();
        ParsedList {
            domains: DomainSet::from_hashes(self.hashes),
            regexes: self.regexes,
        }
    }

    fn parse_line_bytes(&mut self, line: &[u8]) {
        match std::str::from_utf8(line) {
            Ok(line) => self.parse_line(line),
            Err(_) => self.parse_line(&String::from_utf8_lossy(line)),
        }
    }

    fn parse_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        // Skip comments and headers
        if line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
            return;
        }

        // Regex format: /pattern/
        if line.starts_with('/') && line.len() > 2 {
            if let Some(pattern) = line.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                match Regex::new(pattern) {
                    Ok(re) => self.regexes.push(re),
                    Err(e) => warn!("Invalid regex pattern '/{pattern}/': {e}"),
                }
                return;
            }
        }

        // Adblock Plus / ABP format: ||example.com^
        if let Some(abp_rest) = line.strip_prefix("||") {
            let domain_part = abp_rest
                .split(&['^', '$', '/', '|'][..])
                .next()
                .unwrap_or("")
                .trim();
            self.push_domain(domain_part, false);
            return;
        }

        // Hosts file or plain domain format:
        // Strip inline comments starting with '#'
        let effective_line = match line.split_once('#') {
            Some((before_hash, _)) => before_hash.trim(),
            None => line,
        };

        let mut tokens = effective_line.split_whitespace();
        let Some(first) = tokens.next() else {
            return;
        };

        // Check if first token is an IP address (Hosts format)
        if first.parse::<std::net::IpAddr>().is_ok() {
            // Tokens after the IP are domain names
            for token in tokens {
                self.push_domain(token, true);
            }
        } else {
            // Plain domain list or single domain
            self.push_domain(first, false);
        }
    }

    fn push_domain(&mut self, raw: &str, skip_local_names: bool) {
        if !normalize_into(raw, &mut self.norm) {
            return;
        }
        // Hosts files map the standard loopback hostnames too
        if skip_local_names
            && matches!(
                self.norm.as_str(),
                "localhost" | "localhost.localdomain" | "broadcasthost" | "local" | "ip6-localhost" | "ip6-loopback"
            )
        {
            return;
        }
        self.hashes.push(domain_hash(&self.norm));
    }
}

pub struct ListParser;

impl ListParser {
    /// Parse lines of text from any supported format into `ParsedList`
    pub fn parse_content(content: &str) -> ParsedList {
        let mut builder = ListBuilder::new();
        builder.feed(content.as_bytes());
        builder.finish()
    }

    /// Load list from URL, local file, or direct inline string
    pub async fn load_source(
        source: &str,
        client: &reqwest::Client,
        timeout: Duration,
        max_attempts: u32,
        cooldown: Duration,
    ) -> Result<ParsedList, String> {
        let mut builder = ListBuilder::new();
        Self::load_source_into(source, client, timeout, max_attempts, cooldown, &mut builder).await?;
        Ok(builder.finish())
    }

    /// Loads a URL, local file, or inline entry into `builder`, parsing downloads and
    /// files as they stream in rather than holding them in memory (the largest lists are
    /// over 100 MB). On error, whatever the source added is removed again.
    pub async fn load_source_into(
        source: &str,
        client: &reqwest::Client,
        timeout: Duration,
        max_attempts: u32,
        cooldown: Duration,
        builder: &mut ListBuilder,
    ) -> Result<(), String> {
        let source = source.trim();
        let mark = builder.mark();

        if source.starts_with("http://") || source.starts_with("https://") {
            let mut attempts = 0;
            let mut last_err = String::new();

            while attempts < max_attempts {
                attempts += 1;
                debug!(source = %source, attempt = attempts, "Fetching blocklist URL");

                match fetch_into(source, client, timeout, builder).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        builder.rollback(mark);
                        last_err = e;
                    }
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
                read_file_into(path, path_str, builder).await.inspect_err(|_| builder.rollback(mark))
            } else {
                // Treat as direct inline entry (domain or regex)
                builder.feed(source.as_bytes());
                builder.end_source();
                Ok(())
            }
        }
    }
}

async fn fetch_into(
    source: &str,
    client: &reqwest::Client,
    timeout: Duration,
    builder: &mut ListBuilder,
) -> Result<(), String> {
    let mut resp = match tokio::time::timeout(timeout, client.get(source).send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(format!("Request error: {e}")),
        Err(_) => return Err(format!("Timed out after {timeout:?}")),
    };
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let mut decoder = Decoder::new(source);
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => decoder.push(&chunk, builder)?,
            Ok(None) => break,
            Err(e) => return Err(format!("Failed to read response body: {e}")),
        }
    }
    decoder.finish(builder)
}

async fn read_file_into(path: &Path, path_str: &str, builder: &mut ListBuilder) -> Result<(), String> {
    let read_err = |e: std::io::Error| format!("Failed to read file '{path_str}': {e}");
    let mut file = tokio::fs::File::open(path).await.map_err(read_err)?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut decoder = Decoder::new(path_str);
    loop {
        let n = file.read(&mut buf).await.map_err(read_err)?;
        if n == 0 {
            break;
        }
        decoder.push(&buf[..n], builder)?;
    }
    decoder.finish(builder)
}

/// Streams list bytes into a `ListBuilder`, gunzipping them when the source is
/// compressed (name ending in `.gz` or gzip magic bytes).
enum Decoder {
    Detect { gz_name: bool, head: Vec<u8> },
    Plain,
    Gzip(Box<GzDecoder<Vec<u8>>>),
}

impl Decoder {
    fn new(source_hint: &str) -> Self {
        Decoder::Detect {
            gz_name: source_hint.ends_with(".gz"),
            head: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8], builder: &mut ListBuilder) -> Result<(), String> {
        if let Decoder::Detect { gz_name, head } = self {
            if !*gz_name && head.len() + data.len() < 2 {
                head.extend_from_slice(data);
                return Ok(());
            }
            let mut magic = head.iter().chain(data).take(2);
            let gzip = *gz_name || (magic.next() == Some(&0x1f) && magic.next() == Some(&0x8b));
            let head = std::mem::take(head);
            *self = if gzip {
                Decoder::Gzip(Box::new(GzDecoder::new(Vec::new())))
            } else {
                Decoder::Plain
            };
            if !head.is_empty() {
                self.push(&head, builder)?;
            }
        }

        match self {
            Decoder::Plain => builder.feed(data),
            Decoder::Gzip(decoder) => {
                decoder
                    .write_all(data)
                    .map_err(|e| format!("Gzip decompression failed: {e}"))?;
                let out = decoder.get_mut();
                builder.feed(out);
                out.clear();
            }
            Decoder::Detect { .. } => unreachable!("decoder kind decided above"),
        }
        Ok(())
    }

    fn finish(self, builder: &mut ListBuilder) -> Result<(), String> {
        match self {
            Decoder::Detect { head, .. } => builder.feed(&head),
            Decoder::Plain => {}
            Decoder::Gzip(decoder) => {
                let out = decoder
                    .finish()
                    .map_err(|e| format!("Gzip decompression failed: {e}"))?;
                builder.feed(&out);
            }
        }
        builder.end_source();
        Ok(())
    }
}

/// Normalizes `s` into `out`: lowercase, no surrounding whitespace or dots, and
/// internationalized names in punycode, the form queries carry. Returns false when `s`
/// is not a domain name.
fn normalize_into(s: &str, out: &mut String) -> bool {
    let s = s.trim().trim_start_matches('.').trim_end_matches('.');
    out.clear();
    if s.is_ascii() {
        out.push_str(s);
    } else {
        match Name::from_utf8(s) {
            Ok(name) => out.push_str(name.to_ascii().trim_end_matches('.')),
            Err(_) => return false,
        }
    }
    out.make_ascii_lowercase();
    if out.is_empty() {
        return false;
    }
    // Basic domain validation: letters, digits, dots, hyphens, underscores
    let valid = out
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_');
    valid && (out.contains('.') || out == "localhost")
}

/// Normalizes domain name: lowercase, trim whitespace and trailing/leading dots,
/// punycode for internationalized names
pub fn normalize_domain(s: &str) -> Option<String> {
    let mut out = String::new();
    normalize_into(s, &mut out).then_some(out)
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

    #[test]
    fn test_unicode_domains_are_stored_as_punycode() {
        let parsed = ListParser::parse_content("bücher.example\n");
        assert!(parsed.domains.contains("xn--bcher-kva.example"));
    }

    #[test]
    fn test_domain_set_dedup_merge_and_lookup() {
        let parsed = ListParser::parse_content("a.example.com\nb.example.com\nA.Example.com.\n");
        assert_eq!(parsed.domains.len(), 2);

        let mut set = DomainSet::new();
        assert!(set.insert("c.example.com"));
        assert!(!set.insert("c.example.com"));
        set.extend(parsed.domains);
        assert_eq!(set.len(), 3);
        for domain in ["a.example.com", "b.example.com", "c.example.com"] {
            assert!(set.contains(domain), "{domain} missing");
        }
        assert!(!set.contains("example.com"));
        assert!(!set.contains("d.example.com"));

        let mut empty = DomainSet::new();
        empty.extend(set.clone());
        assert_eq!(empty.len(), 3);
    }

    #[test]
    fn test_domain_set_large_list_has_no_false_matches() {
        let content: String = (0..200_000)
            .map(|i| format!("host{i}.blocked.test\n"))
            .collect();
        let parsed = ListParser::parse_content(&content);
        assert_eq!(parsed.domains.len(), 200_000);
        assert!(matches!(parsed.domains.repr, Repr::Bucketed { .. }));
        assert!((0..200_000)
            .step_by(997)
            .all(|i| parsed.domains.contains(&format!("host{i}.blocked.test"))));
        assert!((0..200_000).all(|i| !parsed.domains.contains(&format!("host{i}.allowed.test"))));
    }

    #[test]
    fn test_bucketed_set_keeps_every_hash() {
        // Deterministic pseudo-random hashes, with duplicates, to cover all bit offsets
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let hashes: Vec<u64> = (0..300_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            })
            .collect();
        let mut expected = hashes.clone();
        expected.sort_unstable();
        expected.dedup();

        let set = DomainSet::from_hashes(hashes.iter().chain(&hashes[..1000]).copied().collect());
        assert!(matches!(set.repr, Repr::Bucketed { .. }));
        assert_eq!(set.len(), expected.len());
        assert!(set.iter().eq(expected.iter().copied()));
        assert!(expected.iter().all(|&h| set.contains_hash(h)));
        assert!(expected.iter().all(|&h| !set.contains_hash(h ^ 1) || expected.binary_search(&(h ^ 1)).is_ok()));
        assert!(set.heap_bytes() < expected.len() * 7);

        let mut grown = set.clone();
        assert!(grown.insert("new.example.com"));
        assert!(grown.contains("new.example.com"));
        assert_eq!(grown.len(), expected.len() + 1);
    }

    #[test]
    fn test_builder_handles_split_lines_rollback_and_long_lines() {
        let mut builder = ListBuilder::new();
        builder.feed(b"0.0.0.0 a.exa");
        builder.feed(b"mple.com\r\nb.example.com");
        builder.end_source();

        let mark = builder.mark();
        builder.feed(b"failed.example.com\npartial.exam");
        builder.rollback(mark);

        builder.feed(&vec![b'x'; MAX_LINE_LEN + 10]);
        builder.feed(b".example.com\nc.example.com");
        let list = builder.finish();
        assert_eq!(list.domains.len(), 3);
        for domain in ["a.example.com", "b.example.com", "c.example.com"] {
            assert!(list.domains.contains(domain), "{domain} missing");
        }
        assert!(!list.domains.contains("failed.example.com"));
    }

    #[tokio::test]
    async fn test_load_gzip_file_streams() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt.gz");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        for i in 0..50_000 {
            writeln!(encoder, "0.0.0.0 host{i}.gz.test").unwrap();
        }
        std::fs::write(&path, encoder.finish().unwrap()).unwrap();

        let client = reqwest::Client::new();
        let list = ListParser::load_source(path.to_str().unwrap(), &client, Duration::from_secs(5), 1, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(list.domains.len(), 50_000);
        assert!(list.domains.contains("host49999.gz.test"));
    }
}
