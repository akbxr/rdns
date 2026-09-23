# rdns

A minimal DNS proxy and ad blocker written in Rust, inspired by [Blocky](https://github.com/0xERR0R/blocky). 

## Features

### Protocols

- DNS over UDP and TCP
- DNS over HTTPS (DoH)
- DNS over TLS (DoT)

### Upstreams

- Resolves through plain UDP, TCP, DoT, and DoH.
- Supports three query strategies. `parallel` queries every upstream at once and takes the first valid answer. `strict` walks the list in order until one answers. `random` shuffles upstreams before trying.
- Groups allow routing specific domains like `.lan` or reverse lookups to local routers while sending general traffic upstream.

### Blocking

- Parses hosts files, Adblock Plus rules, regular expressions, and raw domain lists.
- Decompresses `.gz` lists during download.
- Suffix matching walks domain labels from right to left without heap allocation per query. Blocking `doubleclick.net` catches `ad.doubleclick.net` automatically.
- Whitelists take precedence over blacklists.
- Client groups let you give different rules to different subnets or individual IPs.
- Blocks answer with `0.0.0.0` and `::`, NXDOMAIN, or a custom IP.
- Refreshes blocklists in the background on an interval.

### Cache

- In-memory cache using read-write locks.
- Enforces minimum and maximum TTL bounds on upstream responses.
- Caches NXDOMAIN and empty responses with a separate negative TTL.
- Optional prefetching queries upstreams before popular records expire.

### Local records and privacy logging

- Maps custom A, AAAA, and CNAME records directly from the configuration file.
- Generates reverse PTR records for local definitions automatically.
- Optional `csv-client` logging writes daily query counts per client to CSV files. It records only the date, the client IP, the total query count, and the blocked count. It never logs domain names.

## Quick start

### Build

```bash
cargo build --release
```

The output binary is at `target/release/rdns`.

To install it into your system PATH:

```bash
cargo install --path .
```

### Validate configuration

```bash
rdns check -c config.yaml
```

### Run

```bash
rdns start -c config.yaml
```

If you omit the subcommands, `rdns` defaults to `start` using `config.yaml` in the current working directory.

### Run with Docker

Build and run the container locally or on a VPS:

```bash
# Build the image
docker build -t rdns:latest .

# Run directly
docker run -d \
  --name rdns \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 4000:4000/tcp \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v $(pwd)/logs:/app/logs \
  rdns:latest
```

Or use docker compose:

```bash
docker compose up -d
```

## Example configuration

```yaml
ports:
  dns: "0.0.0.0:53"
  http: "0.0.0.0:4000"
  # dot: "0.0.0.0:853"
  # https: "0.0.0.0:443"

# Required only if dot or https ports are enabled
# tls:
#   cert: "/etc/letsencrypt/live/dns.example.com/fullchain.pem"
#   key: "/etc/letsencrypt/live/dns.example.com/privkey.pem"

upstreams:
  groups:
    default:
      - "udp:1.1.1.1:53"
      - "tcp:1.0.0.1:53"
      - "dot:cloudflare-dns.com:853"
      - "https://cloudflare-dns.com/dns-query"
      - "udp:8.8.8.8:53"
      - "dot:dns.google:853"
      - "https://dns.google/dns-query"
  strategy: parallel
  timeout: 2s

conditional:
  mapping:
    "home.lan": "udp:192.168.1.1:53"
    "168.192.in-addr.arpa": "udp:192.168.1.1:53"

blocking:
  blacklists:
    ads:
      - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      - "https://adaway.org/hosts.txt"
    malware:
      - "https://urlhaus.abuse.ch/downloads/hostfile/"
  whitelists:
    ads:
      - "analytics.google.com"
  client_groups:
    default:
      - "ads"
    kids:
      - "ads"
      - "malware"
  block_type: zeroIp
  block_ttl: 1h
  refresh_period: 4h

client_lookup:
  clients:
    "192.168.1.100": ["kids"]
    "192.168.1.0/24": ["default"]

caching:
  min_ttl: 5m
  max_ttl: 1d
  neg_ttl: 30m
  prefetching: true
  prefetch_threshold: 5
  max_items: 50000

custom_dns:
  custom_ttl: 1h
  mapping:
    "router.home.lan": ["192.168.1.1"]
    "nas.home.lan": ["192.168.1.10", "fd00::10"]
    "storage.home.lan": ["nas.home.lan"]

query_log:
  type: console
  log_level: info
  target_dir: "./logs"
  flush_interval: 30s
```

## CLI reference

Control the running server or inspect state through the binary:

```bash
# Validate config file syntax
rdns check -c config.yaml

# Check blocking status and total loaded rules
rdns blocking status

# Temporarily pause blocking for 10 minutes
rdns blocking disable --duration 10m

# Turn blocking back on
rdns blocking enable

# Download blocklists again immediately
rdns blocking refresh

# Inspect cache hit ratio
rdns cache stats

# Empty the cache
rdns cache clear

# Print Prometheus metrics to stdout
rdns metrics

# Print daily client query counts
rdns querylog

# Flush in-memory query counts to CSV files now
rdns querylog flush

# Stop the running background daemon cleanly
rdns stop

# Remove rdns binary from your system
rdns uninstall
```

If the HTTP API runs on another host or port, pass `--api http://ip:port` to any control command.

## HTTP endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/dns-query` | GET, POST | RFC 8484 DNS over HTTPS handler |
| `/health` | GET | Health probe returning status ok |
| `/api/blocking/status` | GET | Active rules count and disable timer |
| `/api/blocking/disable?duration=5m` | GET, POST | Pause blocking for a set duration |
| `/api/blocking/enable` | GET, POST | Resume blocking |
| `/api/blocking/refresh` | GET, POST | Trigger list downloads |
| `/api/cache/stats` | GET | Hit count, miss count, and ratio |
| `/api/cache/clear` | GET, POST | Flush cache entries |
| `/api/querylog/summary` | GET | Per-client daily counts |
| `/api/querylog/flush` | GET, POST | Force CSV write |
| `/api/shutdown` | GET, POST | Trigger clean process exit |
| `/metrics` | GET | Prometheus scraper endpoint |
