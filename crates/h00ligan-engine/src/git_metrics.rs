//! Git-derived churn metrics for code intelligence enrichment.
//!
//! [`GitMetricsCollector`] runs `git log` asynchronously, computes per-file
//! churn statistics (commit count, recency, author diversity over 90 days),
//! and caches results in redb keyed by the current HEAD commit hash.
//!
//! All redb I/O is wrapped in [`tokio::task::spawn_blocking`] to avoid
//! blocking the tokio runtime. Git commands use [`tokio::process::Command`].

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tracing::warn;

// ---------------------------------------------------------------------------
// redb table definition
// ---------------------------------------------------------------------------

/// Git churn metrics: `"{commit_hash}:{file_path}"` -> bincode-serialized FileChurnMetrics.
const GIT_CHURN_METRICS: TableDefinition<&str, &[u8]> = TableDefinition::new("git_churn_metrics");

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Per-file churn metrics derived from `git log --numstat`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChurnMetrics {
    /// Number of commits touching this file in the last 90 days.
    pub churn_90d: u32,
    /// Days since the file was last modified (relative to collection time).
    pub last_modified_days: u32,
    /// Number of distinct authors who modified this file in the last 90 days.
    pub unique_authors_90d: u32,
    /// The HEAD commit hash at which these metrics were computed.
    pub computed_at_commit: String,
}

impl FileChurnMetrics {
    /// Whether this file has high churn (top quartile heuristic: >15 commits in 90 days).
    pub const fn is_high_churn(&self) -> bool {
        self.churn_90d > 15
    }

    /// Whether this file has many authors (top quartile heuristic: >3 unique authors in 90 days).
    pub const fn is_many_authors(&self) -> bool {
        self.unique_authors_90d > 3
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from git metrics collection. All variants are non-fatal: callers
/// should log a warning and fall back to an empty metrics map.
#[derive(thiserror::Error, Debug)]
pub enum GitMetricsError {
    #[error("git command failed: {0}")]
    Git(String),

    #[error("redb operation failed: {0}")]
    Redb(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("task join error: {0}")]
    Join(String),
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Collects per-file git churn metrics and caches them in redb.
///
/// Follows the [`CrashJournal`](crate::journal::CrashJournal) pattern:
/// holds an `Arc<Database>` so it can be cloned into `spawn_blocking` closures.
#[derive(Debug, Clone)]
pub struct GitMetricsCollector {
    db: Arc<Database>,
    repo_root: PathBuf,
}

impl GitMetricsCollector {
    /// Create a new collector backed by the given redb database and git repo root.
    ///
    /// The redb table is created eagerly so that later reads never encounter a
    /// missing-table error.
    pub fn new(db: Arc<Database>, repo_root: PathBuf) -> Result<Self, GitMetricsError> {
        // Ensure the table exists.
        let txn = db
            .begin_write()
            .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
        {
            let _table = txn
                .open_table(GIT_CHURN_METRICS)
                .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| GitMetricsError::Redb(e.to_string()))?;

        Ok(Self { db, repo_root })
    }

    /// Collect per-file churn metrics for the current HEAD commit.
    ///
    /// 1. Reads the current HEAD via `git rev-parse HEAD`.
    /// 2. If metrics for that HEAD are already cached in redb, returns them.
    /// 3. Otherwise runs `git log --numstat --since="90 days ago"`, parses the
    ///    output, caches in redb, and returns the result.
    ///
    /// All redb I/O is wrapped in `spawn_blocking`. Git commands use
    /// `tokio::process::Command` (natively async).
    ///
    /// On any error, returns an empty map and logs a warning.
    pub async fn collect(&self) -> HashMap<String, FileChurnMetrics> {
        match self.collect_inner().await {
            Ok(map) => map,
            Err(e) => {
                warn!("git metrics collection failed (non-fatal): {e}");
                HashMap::new()
            }
        }
    }

    async fn collect_inner(&self) -> Result<HashMap<String, FileChurnMetrics>, GitMetricsError> {
        // Step 1: get current HEAD
        let head = self.git_head().await?;

        // Step 2: check redb cache
        let db = self.db.clone();
        let head_for_cache = head.clone();
        let cached = tokio::task::spawn_blocking(move || read_cached_metrics(&db, &head_for_cache))
            .await
            .map_err(|e| GitMetricsError::Join(e.to_string()))??;

        if let Some(map) = cached {
            return Ok(map);
        }

        // Step 3: cache miss -> run git log
        let raw_log = self.git_log_numstat().await?;

        // Step 4: parse
        let map = parse_git_log(&raw_log, &head);

        // Step 5: store in redb (also cleans up old HEAD entries)
        let db = self.db.clone();
        let map_for_store = map.clone();
        let head_for_store = head.clone();
        tokio::task::spawn_blocking(move || {
            write_and_cleanup(&db, &head_for_store, &map_for_store)
        })
        .await
        .map_err(|e| GitMetricsError::Join(e.to_string()))??;

        Ok(map)
    }

    /// Run `git rev-parse HEAD` and return the trimmed commit hash.
    async fn git_head(&self) -> Result<String, GitMetricsError> {
        let output = tokio::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&self.repo_root)
            .output()
            .await
            .map_err(|e| GitMetricsError::Git(format!("failed to run git rev-parse: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitMetricsError::Git(format!(
                "git rev-parse HEAD failed: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run `git log --numstat --since="90 days ago" --format="%H %ae" HEAD`.
    async fn git_log_numstat(&self) -> Result<String, GitMetricsError> {
        let output = tokio::process::Command::new("git")
            .args([
                "log",
                "--numstat",
                "--since=90 days ago",
                "--format=%H %ae",
                "HEAD",
            ])
            .current_dir(&self.repo_root)
            .output()
            .await
            .map_err(|e| GitMetricsError::Git(format!("failed to run git log: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitMetricsError::Git(format!(
                "git log --numstat failed: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

// ---------------------------------------------------------------------------
// Parse logic (pure, testable without git)
// ---------------------------------------------------------------------------

/// Parsed commit header from `--format="%H %ae"`.
struct CommitHeader {
    _hash: String,
    author: String,
}

/// Parse the output of `git log --numstat --format="%H %ae"`.
///
/// The format alternates between:
///   - A commit header line: `<hash> <author_email>`
///   - Zero or more numstat lines: `<added>\t<deleted>\t<file_path>`
///   - Blank lines between commits
///
/// Returns a map of file path to [`FileChurnMetrics`].
pub fn parse_git_log(raw: &str, head_commit: &str) -> HashMap<String, FileChurnMetrics> {
    let mut result: HashMap<String, FileChurnMetrics> = HashMap::new();
    let mut authors_per_file: HashMap<String, HashSet<String>> = HashMap::new();
    let mut current_header: Option<CommitHeader> = None;
    let mut most_recent_commit_per_file: HashMap<String, usize> = HashMap::new();

    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as a numstat line: <added>\t<deleted>\t<filepath>
        if let Some(file_path) = try_parse_numstat(trimmed) {
            let entry = result
                .entry(file_path.clone())
                .or_insert_with(|| FileChurnMetrics {
                    churn_90d: 0,
                    last_modified_days: 0,
                    unique_authors_90d: 0,
                    computed_at_commit: head_commit.to_string(),
                });
            entry.churn_90d += 1;

            // Track earliest line index where this file appears (most recent commit).
            most_recent_commit_per_file
                .entry(file_path.clone())
                .or_insert(line_idx);

            if let Some(ref header) = current_header {
                authors_per_file
                    .entry(file_path)
                    .or_default()
                    .insert(header.author.clone());
            }
        } else if let Some(header) = try_parse_commit_header(trimmed) {
            // Commit header line
            current_header = Some(header);
        }
        // else: skip unrecognized lines
    }

    // Fill in unique_authors_90d and last_modified_days.
    // NOTE: last_modified_days is approximated as 0 for all files within the 90-day
    // window. A more precise calculation would require parsing commit dates, but the
    // spec only requires a rough signal. We set it to 0 for the most recently
    // appearing file and scale linearly for others based on line order (a rough proxy
    // for recency since git log outputs newest-first).
    let total_lines = raw.lines().count().max(1);
    for (path, metrics) in &mut result {
        if let Some(authors) = authors_per_file.get(path) {
            metrics.unique_authors_90d = authors.len() as u32;
        }
        if let Some(&first_line) = most_recent_commit_per_file.get(path) {
            // Rough approximation: map line position to 0..90 days.
            // First line = most recent = 0 days, last line = ~90 days.
            metrics.last_modified_days = ((first_line as u64 * 90) / total_lines as u64) as u32;
        }
    }

    result
}

/// Try to parse a numstat line: `<added>\t<deleted>\t<filepath>`.
/// Returns the file path if successful.
fn try_parse_numstat(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.splitn(3, '\t').collect();
    if parts.len() != 3 {
        return None;
    }
    // added/deleted can be "-" for binary files
    let added_ok = parts[0] == "-" || parts[0].parse::<u64>().is_ok();
    let deleted_ok = parts[1] == "-" || parts[1].parse::<u64>().is_ok();
    if added_ok && deleted_ok && !parts[2].is_empty() {
        Some(parts[2].to_string())
    } else {
        None
    }
}

/// Try to parse a commit header line: `<40-hex-chars> <email>`.
fn try_parse_commit_header(line: &str) -> Option<CommitHeader> {
    let (hash, author) = line.split_once(' ')?;
    // SHA-1 hashes are 40 hex chars; SHA-256 are 64
    if (hash.len() == 40 || hash.len() == 64) && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(CommitHeader {
            _hash: hash.to_string(),
            author: author.to_string(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// redb cache operations (all blocking — called via spawn_blocking)
// ---------------------------------------------------------------------------

/// Read all cached metrics for the given HEAD commit.
/// Returns `None` on cache miss (no entries with this commit prefix).
fn read_cached_metrics(
    db: &Database,
    head: &str,
) -> Result<Option<HashMap<String, FileChurnMetrics>>, GitMetricsError> {
    let prefix = format!("{head}:");
    let txn = db
        .begin_read()
        .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
    let table = txn
        .open_table(GIT_CHURN_METRICS)
        .map_err(|e| GitMetricsError::Redb(e.to_string()))?;

    let mut map = HashMap::new();
    let iter = table
        .iter()
        .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
    for entry in iter {
        let entry = entry.map_err(|e| GitMetricsError::Redb(e.to_string()))?;
        let key = entry.0.value();
        if key.starts_with(&prefix) {
            let file_path = key[prefix.len()..].to_string();
            let (metrics, _): (FileChurnMetrics, _) =
                bincode::serde::decode_from_slice(entry.1.value(), bincode::config::standard())
                    .map_err(|e| GitMetricsError::Serialization(e.to_string()))?;
            map.insert(file_path, metrics);
        }
    }

    if map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(map))
    }
}

/// Write metrics for the new HEAD and delete entries from any previous HEAD.
fn write_and_cleanup(
    db: &Database,
    head: &str,
    metrics: &HashMap<String, FileChurnMetrics>,
) -> Result<(), GitMetricsError> {
    let prefix = format!("{head}:");

    let txn = db
        .begin_write()
        .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
    {
        let mut table = txn
            .open_table(GIT_CHURN_METRICS)
            .map_err(|e| GitMetricsError::Redb(e.to_string()))?;

        // Collect old keys to delete (keys not matching current HEAD prefix).
        let old_keys: Vec<String> = {
            let iter = table
                .iter()
                .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
            let mut keys = Vec::new();
            for entry in iter {
                let entry = entry.map_err(|e| GitMetricsError::Redb(e.to_string()))?;
                let key = entry.0.value().to_string();
                if !key.starts_with(&prefix) {
                    keys.push(key);
                }
            }
            keys
        };

        // Delete old entries.
        for key in &old_keys {
            table
                .remove(key.as_str())
                .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
        }

        // Write new entries.
        for (file_path, m) in metrics {
            let key = format!("{head}:{file_path}");
            let bytes = bincode::serde::encode_to_vec(m, bincode::config::standard())
                .map_err(|e| GitMetricsError::Serialization(e.to_string()))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|e| GitMetricsError::Redb(e.to_string()))?;
        }
    }
    txn.commit()
        .map_err(|e| GitMetricsError::Redb(e.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Sample git log output for parse testing.
    fn sample_git_log() -> &'static str {
        "abc123def456abc123def456abc123def456abcd user1@example.com\n\
         \n\
         10\t5\tsrc/main.rs\n\
         3\t1\tsrc/lib.rs\n\
         \n\
         def456abc123def456abc123def456abc123abcd user2@example.com\n\
         \n\
         7\t2\tsrc/main.rs\n\
         1\t0\tREADME.md\n\
         \n\
         aaa111bbb222ccc333ddd444eee555fff666abcd user1@example.com\n\
         \n\
         2\t2\tsrc/lib.rs\n"
    }

    #[test]
    fn test_parse_git_log_churn_counts() {
        let map = parse_git_log(sample_git_log(), "abc123");
        assert_eq!(map.get("src/main.rs").map(|m| m.churn_90d), Some(2));
        assert_eq!(map.get("src/lib.rs").map(|m| m.churn_90d), Some(2));
        assert_eq!(map.get("README.md").map(|m| m.churn_90d), Some(1));
    }

    #[test]
    fn test_parse_git_log_unique_authors() {
        let map = parse_git_log(sample_git_log(), "abc123");
        // src/main.rs: user1 + user2
        assert_eq!(
            map.get("src/main.rs").map(|m| m.unique_authors_90d),
            Some(2)
        );
        // src/lib.rs: user1 only (both commits are user1 and user1)
        assert_eq!(map.get("src/lib.rs").map(|m| m.unique_authors_90d), Some(1));
        // README.md: user2 only
        assert_eq!(map.get("README.md").map(|m| m.unique_authors_90d), Some(1));
    }

    #[test]
    fn test_parse_git_log_computed_at_commit() {
        let map = parse_git_log(sample_git_log(), "deadbeef");
        for metrics in map.values() {
            assert_eq!(metrics.computed_at_commit, "deadbeef");
        }
    }

    #[test]
    fn test_parse_empty_log() {
        let map = parse_git_log("", "abc123");
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_binary_numstat() {
        // Binary files show "-" for added/deleted
        let log = "abc123def456abc123def456abc123def456abcd user@test.com\n\
                    \n\
                    -\t-\timage.png\n";
        let map = parse_git_log(log, "abc123");
        assert_eq!(map.get("image.png").map(|m| m.churn_90d), Some(1));
    }

    #[test]
    fn test_try_parse_numstat_valid() {
        assert_eq!(
            try_parse_numstat("10\t5\tsrc/main.rs"),
            Some("src/main.rs".to_string())
        );
    }

    #[test]
    fn test_try_parse_numstat_invalid() {
        assert_eq!(try_parse_numstat("not a numstat line"), None);
        assert_eq!(try_parse_numstat("abc\tdef\t"), None);
    }

    #[test]
    fn test_try_parse_commit_header() {
        let header =
            try_parse_commit_header("abc123def456abc123def456abc123def456abcd user@example.com");
        assert!(header.is_some());
        let h = header.unwrap();
        assert_eq!(h.author, "user@example.com");
    }

    #[test]
    fn test_try_parse_commit_header_invalid() {
        assert!(try_parse_commit_header("short_hash user@test.com").is_none());
        assert!(try_parse_commit_header("10\t5\tsrc/main.rs").is_none());
    }

    #[test]
    fn test_redb_cache_roundtrip() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let db = Arc::new(Database::create(tmp.path()).expect("create redb"));

        // Ensure table exists.
        {
            let txn = db.begin_write().expect("begin write");
            {
                let _t = txn.open_table(GIT_CHURN_METRICS).expect("open table");
            }
            txn.commit().expect("commit");
        }

        let mut metrics = HashMap::new();
        metrics.insert(
            "src/main.rs".to_string(),
            FileChurnMetrics {
                churn_90d: 10,
                last_modified_days: 2,
                unique_authors_90d: 3,
                computed_at_commit: "abc123".to_string(),
            },
        );

        // Write
        write_and_cleanup(&db, "abc123", &metrics).expect("write metrics");

        // Read back (cache hit)
        let cached = read_cached_metrics(&db, "abc123")
            .expect("read metrics")
            .expect("should have cached data");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached["src/main.rs"].churn_90d, 10);
        assert_eq!(cached["src/main.rs"].unique_authors_90d, 3);

        // Read with different HEAD (cache miss)
        let miss = read_cached_metrics(&db, "def456").expect("read metrics");
        assert!(miss.is_none());
    }

    #[test]
    fn test_redb_cache_cleanup_on_new_head() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let db = Arc::new(Database::create(tmp.path()).expect("create redb"));

        {
            let txn = db.begin_write().expect("begin write");
            {
                let _t = txn.open_table(GIT_CHURN_METRICS).expect("open table");
            }
            txn.commit().expect("commit");
        }

        let mut metrics_v1 = HashMap::new();
        metrics_v1.insert(
            "old_file.rs".to_string(),
            FileChurnMetrics {
                churn_90d: 5,
                last_modified_days: 10,
                unique_authors_90d: 1,
                computed_at_commit: "old_head".to_string(),
            },
        );

        // Write old HEAD
        write_and_cleanup(&db, "old_head", &metrics_v1).expect("write v1");
        assert!(
            read_cached_metrics(&db, "old_head")
                .expect("read")
                .is_some()
        );

        // Write new HEAD — should delete old entries
        let mut metrics_v2 = HashMap::new();
        metrics_v2.insert(
            "new_file.rs".to_string(),
            FileChurnMetrics {
                churn_90d: 2,
                last_modified_days: 0,
                unique_authors_90d: 1,
                computed_at_commit: "new_head".to_string(),
            },
        );
        write_and_cleanup(&db, "new_head", &metrics_v2).expect("write v2");

        // Old HEAD should be gone
        assert!(
            read_cached_metrics(&db, "old_head")
                .expect("read")
                .is_none()
        );
        // New HEAD should be present
        let cached = read_cached_metrics(&db, "new_head")
            .expect("read")
            .expect("should have new data");
        assert_eq!(cached.len(), 1);
        assert!(cached.contains_key("new_file.rs"));
    }

    #[tokio::test]
    async fn test_collector_new_creates_table() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let db = Arc::new(Database::create(tmp.path()).expect("create redb"));
        let collector = GitMetricsCollector::new(db.clone(), PathBuf::from("/tmp"));
        assert!(collector.is_ok());

        // Verify table exists by reading from it.
        let txn = db.begin_read().expect("begin read");
        let table = txn.open_table(GIT_CHURN_METRICS);
        assert!(table.is_ok());
    }
}
