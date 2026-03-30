//! Persistent SQLite reputation store.

use crate::event::ThreatEvent;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use std::{net::IpAddr, path::Path, sync::Mutex};
use tracing::{debug, info};

pub struct ReputationStore { conn: Mutex<Connection> }

impl ReputationStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let s = Self { conn: Mutex::new(conn) };
        s.migrate()?;
        info!(?path, "ReputationStore opened");
        Ok(s)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let s = Self { conn: Mutex::new(conn) };
        s.migrate()?;
        Ok(s)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.lock().unwrap().execute_batch(r#"
            CREATE TABLE IF NOT EXISTS relay_reputation (
                fingerprint TEXT PRIMARY KEY, score REAL NOT NULL DEFAULT 0.0,
                seen_circuits INTEGER NOT NULL DEFAULT 0, last_seen TEXT NOT NULL,
                flags TEXT NOT NULL DEFAULT '', asn INTEGER, country TEXT);
            CREATE TABLE IF NOT EXISTS threat_events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, level TEXT NOT NULL,
                kind TEXT NOT NULL, message TEXT NOT NULL, anomaly_score REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON threat_events(timestamp DESC);
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY, blocked_at TEXT NOT NULL,
                reason TEXT NOT NULL, expires_at TEXT);
        "#)?;
        debug!("Schema ready");
        Ok(())
    }

    pub fn update_relay(&self, fp: &str, new_score: f64, asn: Option<u32>, country: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let old: Option<f64> = conn.query_row(
            "SELECT score FROM relay_reputation WHERE fingerprint=?1", params![fp], |r| r.get(0)).ok();
        let blended = match old { Some(o) => 0.3*new_score + 0.7*o, None => new_score };
        conn.execute(
            r#"INSERT INTO relay_reputation(fingerprint,score,seen_circuits,last_seen,asn,country)
               VALUES(?1,?2,1,?3,?4,?5) ON CONFLICT(fingerprint) DO UPDATE SET
               score=excluded.score, seen_circuits=seen_circuits+1, last_seen=excluded.last_seen,
               asn=COALESCE(excluded.asn,asn), country=COALESCE(excluded.country,country)"#,
            params![fp, blended, Utc::now().to_rfc3339(), asn, country])?;
        Ok(())
    }

    pub fn add_flag(&self, fp: &str, flag: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE relay_reputation SET flags=CASE WHEN flags='' THEN ?2 ELSE flags||','||?2 END WHERE fingerprint=?1",
            params![fp, flag])?;
        Ok(())
    }

    pub fn relay_score(&self, fp: &str) -> f64 {
        self.conn.lock().unwrap()
            .query_row("SELECT score FROM relay_reputation WHERE fingerprint=?1", params![fp], |r| r.get(0))
            .unwrap_or(0.0)
    }

    pub fn suspicious_relays(&self, threshold: f64) -> Result<Vec<RelayRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT fingerprint,score,seen_circuits,last_seen,flags,asn,country \
             FROM relay_reputation WHERE score>=?1 ORDER BY score DESC")?;
        // collect() before conn is dropped — fixes E0597
        let result: Result<Vec<_>, _> = stmt.query_map(params![threshold], |r| Ok(RelayRecord {
            fingerprint: r.get(0)?, score: r.get(1)?, seen_circuits: r.get(2)?,
            last_seen: r.get(3)?, flags: r.get(4)?, asn: r.get(5)?, country: r.get(6)?,
        }))?.collect();
        Ok(result?.into_iter().collect())
    }

    pub fn store_event(&self, evt: &ThreatEvent) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO threat_events(id,timestamp,level,kind,message,anomaly_score) VALUES(?1,?2,?3,?4,?5,?6)",
            params![evt.id.to_string(), evt.timestamp.to_rfc3339(), evt.level.to_string(),
                    serde_json::to_string(&evt.kind).unwrap_or_default(), evt.message, evt.anomaly_score])?;
        Ok(())
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<StoredEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,timestamp,level,message,anomaly_score \
             FROM threat_events ORDER BY timestamp DESC LIMIT ?1")?;
        // collect() before conn is dropped — fixes E0597
        let result: Result<Vec<_>, _> = stmt.query_map(params![limit as i64], |r| Ok(StoredEvent {
            id: r.get(0)?, timestamp: r.get(1)?, level: r.get(2)?,
            message: r.get(3)?, anomaly_score: r.get(4)?,
        }))?.collect();
        Ok(result?.into_iter().collect())
    }

    pub fn block_ip(&self, ip: IpAddr, reason: &str, expires: Option<DateTime<Utc>>) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO blocked_ips(ip,blocked_at,reason,expires_at) VALUES(?1,?2,?3,?4)",
            params![ip.to_string(), Utc::now().to_rfc3339(), reason, expires.map(|e| e.to_rfc3339())])?;
        info!(%ip, reason, "IP blocked");
        Ok(())
    }

    pub fn prune_expired_blocks(&self) -> Result<usize> {
        Ok(self.conn.lock().unwrap().execute(
            "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at<?1",
            params![Utc::now().to_rfc3339()])?)
    }

    pub fn blocked_ip_count(&self) -> usize {
        self.conn.lock().unwrap()
            .query_row("SELECT COUNT(*) FROM blocked_ips", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct RelayRecord {
    pub fingerprint: String, pub score: f64, pub seen_circuits: i64,
    pub last_seen: String, pub flags: String, pub asn: Option<i64>, pub country: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: String, pub timestamp: String, pub level: String,
    pub message: String, pub anomaly_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ema() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("A", 0.9, None, None).unwrap();
        s.update_relay("A", 0.0, None, None).unwrap();
        let score = s.relay_score("A");
        assert!((score - 0.63).abs() < 0.02, "EMA={score}");
    }
    #[test]
    fn block_count() {
        let s = ReputationStore::in_memory().unwrap();
        s.block_ip("1.2.3.4".parse().unwrap(), "t", None).unwrap();
        assert_eq!(s.blocked_ip_count(), 1);
    }
    #[test]
    fn suspicious_filter() {
        let s = ReputationStore::in_memory().unwrap();
        s.update_relay("GOOD", 0.1, None, None).unwrap();
        s.update_relay("BAD",  0.9, None, None).unwrap();
        let sus = s.suspicious_relays(0.5).unwrap();
        assert_eq!(sus.len(), 1);
        assert_eq!(sus[0].fingerprint, "BAD");
    }
}
