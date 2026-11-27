use crate::config::{QueryLogConfig, QueryLogType};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDailyStats {
    pub date: String,
    pub client: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    total: u64,
    blocked: u64,
}

#[derive(Debug, Default)]
struct DayStats {
    current: Counts,
    /// What the CSV files hold for this day and client after the last flush.
    flushed: Counts,
}

impl DayStats {
    fn is_dirty(&self) -> bool {
        self.current != self.flushed
    }
}

/// Days since the Unix epoch (UTC).
type Day = u32;

pub struct QueryLogger {
    config: QueryLogConfig,
    /// (day, client) -> counts. Days that are on disk are dropped after a flush, so the
    /// map does not grow with every client ever seen.
    aggregated: Mutex<HashMap<(Day, IpAddr), DayStats>>,
}

fn today() -> Day {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (now_secs / 86400) as Day
}

impl QueryLogger {
    pub fn new(config: QueryLogConfig) -> Self {
        Self {
            config,
            aggregated: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_csv_enabled(&self) -> bool {
        self.config.log_type == QueryLogType::CsvClient
    }

    /// Record a query count for a client.
    /// Privacy notice: only records timestamp/date and count, NEVER records domain/hostname!
    pub fn record(&self, client_ip: IpAddr, is_blocked: bool) {
        if !self.is_csv_enabled() {
            return;
        }

        let day = today();
        let mut guard = self.aggregated.lock();
        let counts = &mut guard.entry((day, client_ip)).or_default().current;
        counts.total += 1;
        if is_blocked {
            counts.blocked += 1;
        }
    }

    /// Returns in-memory summary of daily query counts per client (today and yesterday;
    /// older days are in the CSV files)
    pub fn get_summary(&self) -> Vec<ClientDailyStats> {
        let guard = self.aggregated.lock();
        let mut list: Vec<ClientDailyStats> = guard
            .iter()
            .map(|(&(day, client), stats)| to_stats(day, client, stats.current))
            .collect();
        drop(guard);
        sort_stats(&mut list);
        list
    }

    /// Flush aggregated query counts to CSV files in target_dir
    pub fn flush_to_disk(&self) -> Result<(), std::io::Error> {
        if !self.is_csv_enabled() {
            return Ok(());
        }

        let target_dir = Path::new(&self.config.target_dir);
        if !target_dir.exists() {
            create_dir_all(target_dir)?;
        }

        // Only what changed since the last flush: the files merge rows with what they hold
        let dirty: Vec<((Day, IpAddr), Counts)> = self
            .aggregated
            .lock()
            .iter()
            .filter(|(_, stats)| stats.is_dirty())
            .map(|(&key, stats)| (key, stats.current))
            .collect();
        if dirty.is_empty() {
            self.prune_flushed_days();
            return Ok(());
        }

        let mut stats: Vec<ClientDailyStats> = dirty
            .iter()
            .map(|&((day, client), counts)| to_stats(day, client, counts))
            .collect();
        sort_stats(&mut stats);

        debug!(dir = ?target_dir, count = stats.len(), "Flushing daily client query stats to CSV");

        // 1. Update master clients_daily.csv file
        let master_path = target_dir.join("clients_daily.csv");
        update_csv_file(&master_path, &stats)?;

        // 2. Update individual per-client CSV files (e.g. 192.168.1.100.csv) like Blocky
        let mut by_client: HashMap<String, Vec<ClientDailyStats>> = HashMap::new();
        for stat in stats {
            by_client.entry(stat.client.clone()).or_default().push(stat);
        }

        for (client, client_stats) in by_client {
            // Sanitize client filename (e.g. replacing colons for IPv6)
            let safe_client = client.replace(':', "_");
            let client_file_path = target_dir.join(format!("{safe_client}.csv"));
            update_csv_file(&client_file_path, &client_stats)?;
        }

        {
            let mut guard = self.aggregated.lock();
            for (key, counts) in dirty {
                if let Some(stats) = guard.get_mut(&key) {
                    stats.flushed = counts;
                }
            }
        }
        self.prune_flushed_days();

        Ok(())
    }

    /// Drops days before yesterday whose counts are all on disk.
    fn prune_flushed_days(&self) {
        let yesterday = today().saturating_sub(1);
        self.aggregated
            .lock()
            .retain(|&(day, _), stats| day >= yesterday || stats.is_dirty());
    }

    /// Start periodic flush task in background
    pub fn start_flush_task(self: Arc<Self>, interval_duration: Duration) {
        if !self.is_csv_enabled() || interval_duration.is_zero() {
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.tick().await; // first tick immediate

            loop {
                interval.tick().await;
                // File I/O: keep it off the async workers
                let logger = self.clone();
                match tokio::task::spawn_blocking(move || logger.flush_to_disk()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("Failed to flush client query log CSV to disk: {e}"),
                    Err(e) => error!("Client query log flush task failed: {e}"),
                }
            }
        });
    }
}

fn to_stats(day: Day, client: IpAddr, counts: Counts) -> ClientDailyStats {
    ClientDailyStats {
        date: epoch_to_date(u64::from(day) * 86400),
        client: client.to_string(),
        total_queries: counts.total,
        blocked_queries: counts.blocked,
    }
}

fn sort_stats(list: &mut [ClientDailyStats]) {
    list.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.client.cmp(&b.client)));
}

fn update_csv_file(path: &PathBuf, new_stats: &[ClientDailyStats]) -> Result<(), std::io::Error> {
    // Read existing entries to merge with current in-memory stats
    let mut map: HashMap<(String, String), (u64, u64)> = HashMap::new();

    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() || line.starts_with("date,") || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                let date = parts[0].trim().to_string();
                let client = parts[1].trim().to_string();
                let total: u64 = parts[2].trim().parse().unwrap_or(0);
                let blocked: u64 = parts[3].trim().parse().unwrap_or(0);
                map.insert((date, client), (total, blocked));
            }
        }
    }

    // Merge new stats
    for stat in new_stats {
        let entry = map
            .entry((stat.date.clone(), stat.client.clone()))
            .or_insert((0, 0));
        // Use the maximum of previously written and currently aggregated stats
        entry.0 = entry.0.max(stat.total_queries);
        entry.1 = entry.1.max(stat.blocked_queries);
    }

    // Write back sorted by date descending, client ascending
    let mut rows: Vec<ClientDailyStats> = map
        .into_iter()
        .map(|((date, client), (total_queries, blocked_queries))| ClientDailyStats {
            date,
            client,
            total_queries,
            blocked_queries,
        })
        .collect();
    rows.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.client.cmp(&b.client)));

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    writeln!(file, "date,client,total_queries,blocked_queries")?;
    for row in rows {
        writeln!(
            file,
            "{},{},{},{}",
            row.date, row.client, row.total_queries, row.blocked_queries
        )?;
    }
    file.flush()?;

    Ok(())
}

/// Howard Hinnant's civil calendar algorithm (epoch seconds to YYYY-MM-DD UTC)
pub fn epoch_to_date(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86400) as i64;
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_date() {
        assert_eq!(epoch_to_date(0), "1970-01-01");
        assert_eq!(epoch_to_date(86400), "1970-01-02");
        assert_eq!(epoch_to_date(1704067200), "2024-01-01"); // Jan 1, 2024
    }

    #[test]
    fn test_query_logger_aggregation_and_csv() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = QueryLogConfig::default();
        config.log_type = QueryLogType::CsvClient;
        config.target_dir = temp_dir.path().to_str().unwrap().to_string();

        let logger = QueryLogger::new(config);
        let client_a: IpAddr = "192.168.1.50".parse().unwrap();
        let client_b: IpAddr = "192.168.1.100".parse().unwrap();

        logger.record(client_a, false);
        logger.record(client_a, true);
        logger.record(client_a, false);
        logger.record(client_b, true);

        let summary = logger.get_summary();
        assert_eq!(summary.len(), 2);

        let stat_a = summary.iter().find(|s| s.client == "192.168.1.50").unwrap();
        assert_eq!(stat_a.total_queries, 3);
        assert_eq!(stat_a.blocked_queries, 1);

        let stat_b = summary.iter().find(|s| s.client == "192.168.1.100").unwrap();
        assert_eq!(stat_b.total_queries, 1);
        assert_eq!(stat_b.blocked_queries, 1);

        // Test flush to disk
        logger.flush_to_disk().unwrap();

        let master_csv = temp_dir.path().join("clients_daily.csv");
        assert!(master_csv.exists());
        let content = std::fs::read_to_string(&master_csv).unwrap();
        assert!(content.contains("date,client,total_queries,blocked_queries"));
        assert!(content.contains("192.168.1.50,3,1"));
        assert!(content.contains("192.168.1.100,1,1"));

        // Check per-client file
        let client_file = temp_dir.path().join("192.168.1.50.csv");
        assert!(client_file.exists());

        // Later flushes write only clients that changed, keeping the others' rows
        std::fs::remove_file(&client_file).unwrap();
        logger.record(client_b, false);
        logger.flush_to_disk().unwrap();
        assert!(!client_file.exists());
        let content = std::fs::read_to_string(&master_csv).unwrap();
        assert!(content.contains("192.168.1.50,3,1"));
        assert!(content.contains("192.168.1.100,2,1"));
    }

    #[test]
    fn test_flushed_old_days_are_pruned() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = QueryLogConfig::default();
        config.log_type = QueryLogType::CsvClient;
        config.target_dir = temp_dir.path().to_str().unwrap().to_string();
        let logger = QueryLogger::new(config);

        let client: IpAddr = "10.0.0.1".parse().unwrap();
        let old_day = today() - 5;
        logger.aggregated.lock().entry((old_day, client)).or_default().current = Counts { total: 7, blocked: 2 };
        logger.record(client, false);
        assert_eq!(logger.aggregated.lock().len(), 2);

        logger.flush_to_disk().unwrap();
        assert_eq!(logger.aggregated.lock().len(), 1);
        let content = std::fs::read_to_string(temp_dir.path().join("clients_daily.csv")).unwrap();
        assert!(content.contains(&format!("{},10.0.0.1,7,2", epoch_to_date(u64::from(old_day) * 86400))));
    }
}
