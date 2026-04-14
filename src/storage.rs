//! Persistent SQLite reputation store.
//!
//! ## Schema
//!
//! - `relay_reputation` — per-relay EMA score, ASN, country, flags
//! - `threat_events`    — last N ThreatEvents (pruned to 10 000)
//! - `blocked_ips`      — IP blocklist with optional TTL

use crate::event::ThreatEvent;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::{net::IpAddr, path::Path, sync::Mutex};
use tracing::{debug, info};

/// Maximum threat events kept in the database.
const MAX_STORED_EVENTS: usize = 10_000;

/// Thread-safe SQLite-backed store for relay reputation, threat events, and the IP blocklist.
pub struct ReputationStore {
    conn: Mutex<Connection>,
}

impl ReputationStore {
    /// Acquire the DB connection, recovering from a poisoned mutex rather than panicking.
    ///
    /// If a previous thread panicked while holding the lock, `PoisonError::into_inner()`
    /// returns the underlying connection — SQLite connections survive panics safely.
    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| {
            tracing::error!("DB mutex was poisoned — recovering underlying connection");
            e.into_inner()
        })
    }
}

impl ReputationStore {
    /// Open (or create) the SQLite database at `path` and run schema migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        // WAL mode: concurrent reads don't block writes
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.migrate()?;
        info!(?path, "ReputationStore opened");
        Ok(s)
    }

    /// Create an in-memory database (used in unit tests).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<()> {
        self.db().execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS relay_reputation (
                fingerprint   TEXT PRIMARY KEY,
                score         REAL    NOT NULL DEFAULT 0.0,
                seen_circuits INTEGER NOT NULL DEFAULT 0,
                last_seen     TEXT    NOT NULL,
                flags         TEXT    NOT NULL DEFAULT '',
                asn           INTEGER,
                country       TEXT
            );

            CREATE TABLE IF NOT EXISTS threat_events (
                id            TEXT PRIMARY KEY,
                timestamp     TEXT NOT NULL,
                level         TEXT NOT NULL,
                kind          TEXT NOT NULL,
                message       TEXT NOT NULL,
                anomaly_score REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts
                ON threat_events(timestamp DESC);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                reason     TEXT NOT NULL,
                expires_at TEXT
            );
        "#,
        )?;
        debug!("Schema ready");
        Ok(())
    }

    // ── Relay reputation ───────────────────────────────────────────────────────

    /// Update relay score using EMA: new = 0.3 * fresh + 0.7 * old.
    /// `asn` is stored as i64 (SQLite INTEGER) — the u32 fits safely.
    pub fn update_relay(
        &self,
        fp: &str,
        new_score: f64,
        asn: Option<u32>,
        country: Option<&str>,
    ) -> Result<()> {
        // Fingerprints must be 1–40 ASCII hex characters.
        if fp.is_empty() || fp.len() > 40 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!(
                "invalid relay fingerprint: expected up to 40 hex chars, got {:?}",
                fp
            );
        }
        let conn = self.db();
        let old: Option<f64> = conn
            .query_row(
                "SELECT score FROM relay_reputation WHERE fingerprint=?1",
                params![fp],
                |r| r.get(0),
            )
            .ok();
        let blended = match old {
            Some(o) => 0.3 * new_score + 0.7 * o,
            None => new_score,
        };
        // asn: cast u32 → i64 (SQLite has no u32 type)
        let asn_i64 = asn.map(|a| a as i64);
        conn.execute(
            r#"INSERT INTO relay_reputation(fingerprint,score,seen_circuits,last_seen,asn,country)
               VALUES(?1,?2,1,?3,?4,?5)
               ON CONFLICT(fingerprint) DO UPDATE SET
                   score         = excluded.score,
                   seen_circuits = seen_circuits + 1,
                   last_seen     = excluded.last_seen,
                   asn           = COALESCE(excluded.asn, asn),
                   country       = COALESCE(excluded.country, country)"#,
            params![fp, blended, Utc::now().to_rfc3339(), asn_i64, country],
        )?;
        Ok(())
    }

    /// Add a flag to a relay, avoiding duplicates.
    ///
    /// Returns an error if `flag` is empty, contains commas, or contains
    /// whitespace — all of which would corrupt the comma-separated flag store.
    pub fn add_flag(&self, fp: &str, flag: &str) -> Result<()> {
        if flag.is_empty() || flag.contains(',') || flag.contains(char::is_whitespace) {
            anyhow::bail!(
                "invalid flag {:?}: must be non-empty and contain no commas or whitespace",
                flag
            );
        }
        let conn = self.db();
        // Read current flags, add only if not already present
        let current: Option<String> = conn
            .query_row(
                "SELECT flags FROM relay_reputation WHERE fingerprint=?1",
                params![fp],
                |r| r.get(0),
            )
            .ok();

        if let Some(flags) = current {
            let already = flags.split(',').any(|f| f.trim() == flag);
            if !already {
                let new_flags = if flags.is_empty() {
                    flag.to_string()
                } else {
                    format!("{flags},{flag}")
                };
                conn.execute(
                    "UPDATE relay_reputation SET flags=?2 WHERE fingerprint=?1",
                    params![fp, new_flags],
                )?;
            }
        }
        Ok(())
    }

    /// Return the current EMA reputation score for a relay fingerprint, or `0.0` if unknown.
    pub fn relay_score(&self, fp: &str) -> f64 {
        self.db()
            .query_row(
                "SELECT score FROM relay_reputation WHERE fingerprint=?1",
                params![fp],
                |r| r.get(0),
            )
            .unwrap_or(0.0)
    }

    /// Multiply every relay score by `factor` (e.g. 0.9 for 10 % decay).
    /// Removes rows that fall below `prune_below` after decay.
    /// Returns the number of rows pruned.
    pub fn decay_scores(&self, factor: f64, prune_below: f64) -> Result<usize> {
        let conn = self.db();
        conn.execute(
            "UPDATE relay_reputation SET score = score * ?1",
            params![factor],
        )?;
        let pruned = conn.execute(
            "DELETE FROM relay_reputation WHERE score < ?1",
            params![prune_below],
        )?;
        Ok(pruned)
    }

    /// Return all relays whose reputation score is at or above `threshold`, ordered by score descending.
    pub fn suspicious_relays(&self, threshold: f64) -> Result<Vec<RelayRecord>> {
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT fingerprint,score,seen_circuits,last_seen,flags,asn,country \
             FROM relay_reputation WHERE score>=?1 ORDER BY score DESC",
        )?;
        // Collect before conn is dropped (fixes E0597)
        let result: Result<Vec<_>, _> = stmt
            .query_map(params![threshold], |r| {
                Ok(RelayRecord {
                    fingerprint: r.get(0)?,
                    score: r.get(1)?,
                    seen_circuits: r.get(2)?,
                    last_seen: r.get(3)?,
                    flags: r.get(4)?,
                    asn: r.get(5)?,
                    country: r.get(6)?,
                })
            })?
            .collect();
        Ok(result?)
    }

    // ── Events ─────────────────────────────────────────────────────────────────

    /// Persist a `ThreatEvent` and prune the table to at most [`MAX_STORED_EVENTS`] rows.
    pub fn store_event(&self, evt: &ThreatEvent) -> Result<()> {
        let conn = self.db();
        conn.execute(
            "INSERT OR IGNORE INTO threat_events(id,timestamp,level,kind,message,anomaly_score) \
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                evt.id.to_string(),
                evt.timestamp.to_rfc3339(),
                evt.level.to_string(),
                serde_json::to_string(&evt.kind).unwrap_or_default(),
                evt.message,
                evt.anomaly_score
            ],
        )?;
        // Prune to keep DB size bounded
        conn.execute(
            "DELETE FROM threat_events WHERE id NOT IN \
             (SELECT id FROM threat_events ORDER BY timestamp DESC LIMIT ?1)",
            params![MAX_STORED_EVENTS as i64],
        )?;
        Ok(())
    }

    /// Return up to `limit` most-recent events ordered by timestamp descending.
    pub fn recent_events(&self, limit: usize) -> Result<Vec<StoredEvent>> {
        let conn = self.db();
        let mut stmt = conn.prepare(
            "SELECT id,timestamp,level,message,anomaly_score \
             FROM threat_events ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let result: Result<Vec<_>, _> = stmt
            .query_map(params![limit as i64], |r| {
                Ok(StoredEvent {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    level: r.get(2)?,
                    message: r.get(3)?,
                    anomaly_score: r.get(4)?,
                })
            })?
            .collect();
        Ok(result?)
    }

    // ── IP blocklist ───────────────────────────────────────────────────────────

    /// Add `ip` to the blocklist with an optional expiry timestamp.
    pub fn block_ip(&self, ip: IpAddr, reason: &str, expires: Option<DateTime<Utc>>) -> Result<()> {
        self.db().execute(
            "INSERT OR REPLACE INTO blocked_ips(ip,blocked_at,reason,expires_at) \
             VALUES(?1,?2,?3,?4)",
            params![
                ip.to_string(),
                Utc::now().to_rfc3339(),
                reason,
                expires.map(|e| e.to_rfc3339())
            ],
        )?;
        info!(%ip, reason, "IP blocked");
        Ok(())
    }

    /// Remove `ip` from the blocklist. No-op if not present.
    pub fn unblock_ip(&self, ip: &str) -> Result<()> {
        let n = self
            .db()
            .execute("DELETE FROM blocked_ips WHERE ip=?1", params![ip])?;
        if n > 0 {
            info!(ip, "IP unblocked");
        }
        Ok(())
    }

    /// Return `true` if `ip` is currently blocked (ignoring expired entries).
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.db()
            .query_row(
                "SELECT COUNT(*) FROM blocked_ips WHERE ip=?1 \
                 AND (expires_at IS NULL OR expires_at > ?2)",
                params![ip.to_string(), Utc::now().to_rfc3339()],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Delete all expired blocklist entries and return the number of rows removed.
    pub fn prune_expired_blocks(&self) -> Result<usize> {
        Ok(self.db().execute(
            "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?)
    }

    /// Return the count of currently active (non-expired) blocked IPs.
    pub fn blocked_ip_count(&self) -> usize {
        self.db()
            .query_row(
                "SELECT COUNT(*) FROM blocked_ips \
                 WHERE expires_at IS NULL OR expires_at > ?1",
                params![Utc::now().to_rfc3339()],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Return `true` if a relay with fingerprint `fp` exists in the reputation table.
    pub fn relay_exists(&self, fp: &str) -> bool {
        self.db()
            .query_row(
                "SELECT 1 FROM relay_reputation WHERE fingerprint=?1",
                params![fp],
                |_| Ok(true),
            )
            .unwrap_or(false)
    }
}

// ── Record types ──────────────────────────────────────────────────────────────

/// A relay's full reputation record as stored in the database.
#[derive(Debug, Clone)]
pub struct RelayRecord {
    /// Hex-encoded RSA fingerprint of the relay.
    pub fingerprint: String,
    /// Current EMA reputation score `[0, 1]`.
    pub score: f64,
    /// Total number of circuits in which this relay has been observed.
    pub seen_circuits: i64,
    /// RFC 3339 timestamp of the most recent observation.
    pub last_seen: String,
    /// Comma-separated flag labels attached to this relay (e.g. `"sybil,guard_discovery"`).
    pub flags: String,
    /// Autonomous System Number, if resolved.
    pub asn: Option<i64>,
    /// ISO 3166-1 alpha-2 country code, if resolved.
    pub country: Option<String>,
}

/// A threat event row as returned from the `threat_events` table.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    /// UUIDv4 string identifier.
    pub id: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// Severity level string (e.g. `"HIGH"`).
    pub level: String,
    /// Human-readable description of the threat.
    pub message: String,
    /// Anomaly score `[0, 1]` at the time of detection.
    pub anomaly_score: f64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ema_blending() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("A", 0.9, None, None).unwrap();
        s.update_relay("A", 0.0, None, None).unwrap();
        let score = s.relay_score("A");
        // second call: 0.3*0.0 + 0.7*0.9 = 0.63
        assert!((score - 0.63).abs() < 0.02, "EMA={score}");
    }

    #[test]
    fn flag_deduplication() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("B", 0.5, None, None).unwrap();
        s.add_flag("B", "sybil").unwrap();
        s.add_flag("B", "sybil").unwrap(); // duplicate
        s.add_flag("B", "guard_inj").unwrap();
        let relays = s.suspicious_relays(0.0).unwrap();
        let flags = &relays[0].flags;
        // Should be "sybil,guard_inj" not "sybil,sybil,guard_inj"
        assert_eq!(flags.matches("sybil").count(), 1, "flags={flags}");
    }

    #[test]
    fn block_and_unblock() {
        let s = ReputationStore::in_memory().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        s.block_ip(ip, "test", None).unwrap(); // permanent block (no expiry)
        assert_eq!(s.blocked_ip_count(), 1);
        assert!(s.is_blocked(&ip));
        s.unblock_ip("1.2.3.4").unwrap();
        assert_eq!(s.blocked_ip_count(), 0);
        assert!(!s.is_blocked(&ip));
    }

    #[test]
    fn expired_ip_not_counted() {
        let s = ReputationStore::in_memory().unwrap();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        s.block_ip(ip, "test", Some(past)).unwrap();
        assert_eq!(s.blocked_ip_count(), 0, "expired block must not be counted");
        assert!(!s.is_blocked(&ip));
    }

    #[test]
    fn relay_exists_returns_correct() {
        let s = ReputationStore::in_memory().unwrap();
        assert!(!s.relay_exists("aabbccdd"));
        s.update_relay("aabbccdd", 0.5, None, None).unwrap();
        assert!(s.relay_exists("aabbccdd"));
    }

    #[test]
    fn suspicious_filter() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("00000001", 0.1, None, None).unwrap();
        s.update_relay("00000002", 0.9, None, None).unwrap();
        let sus = s.suspicious_relays(0.5).unwrap();
        assert_eq!(sus.len(), 1);
        assert_eq!(sus[0].fingerprint, "00000002");
    }

    #[test]
    fn asn_stored_and_retrieved() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("C", 0.5, Some(12345), Some("DE")).unwrap();
        let relays = s.suspicious_relays(0.0).unwrap();
        assert_eq!(relays[0].asn, Some(12345));
        assert_eq!(relays[0].country.as_deref(), Some("DE"));
    }

    #[test]
    fn events_pruning() {
        let s = ReputationStore::in_memory().unwrap();
        let evts = s.recent_events(100).unwrap();
        assert!(evts.is_empty());
    }
}
