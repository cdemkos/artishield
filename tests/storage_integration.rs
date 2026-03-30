//! Integration tests for the SQLite reputation store.

use artishield::{
    event::{ThreatEvent, ThreatKind, ThreatLevel},
    storage::ReputationStore,
};
use chrono::Utc;

fn store() -> ReputationStore {
    ReputationStore::in_memory().expect("in-memory SQLite failed")
}

// ── Relay reputation ──────────────────────────────────────────────────────────

#[test]
fn insert_and_read_relay_score() {
    let s = store();
    s.update_relay("AABBCC", 0.7, None, None).unwrap();
    let score = s.relay_score("AABBCC");
    assert!((score - 0.7).abs() < 0.01, "score={score}");
}

#[test]
fn ema_blending_converges() {
    let s = store();
    s.update_relay("FP01", 1.0, None, None).unwrap(); // start at 1.0
    s.update_relay("FP01", 0.0, None, None).unwrap(); // EMA: 0.3*0 + 0.7*1 = 0.7
    s.update_relay("FP01", 0.0, None, None).unwrap(); // EMA: 0.3*0 + 0.7*0.7 = 0.49
    s.update_relay("FP01", 0.0, None, None).unwrap(); // EMA: ~0.343

    let score = s.relay_score("FP01");
    assert!(score < 0.5, "EMA should have decayed below 0.5, got {score}");
    assert!(score > 0.2, "EMA should not have decayed below 0.2, got {score}");
}

#[test]
fn unknown_relay_returns_zero() {
    let s     = store();
    let score = s.relay_score("NONEXISTENT");
    assert_eq!(score, 0.0);
}

#[test]
fn flag_relay() {
    let s = store();
    s.update_relay("FP02", 0.8, None, None).unwrap();
    s.add_flag("FP02", "sybil").unwrap();
    s.add_flag("FP02", "dos_source").unwrap();

    let records = s.suspicious_relays(0.5).unwrap();
    let rec     = records.iter().find(|r| r.fingerprint == "FP02").unwrap();
    assert!(rec.flags.contains("sybil"));
    assert!(rec.flags.contains("dos_source"));
}

#[test]
fn suspicious_filter_threshold() {
    let s = store();
    s.update_relay("CLEAN",   0.1, None, None).unwrap();
    s.update_relay("MEDIUM",  0.6, None, None).unwrap();
    s.update_relay("DANGER",  0.95, None, None).unwrap();

    let above_05 = s.suspicious_relays(0.5).unwrap();
    let fps: Vec<&str> = above_05.iter().map(|r| r.fingerprint.as_str()).collect();
    assert!(!fps.contains(&"CLEAN"),  "CLEAN should be below threshold");
    assert!(fps.contains(&"MEDIUM"),  "MEDIUM should be above threshold");
    assert!(fps.contains(&"DANGER"),  "DANGER should be above threshold");
}

#[test]
fn suspicious_ordered_by_score_desc() {
    let s = store();
    s.update_relay("R1", 0.6, None, None).unwrap();
    s.update_relay("R2", 0.9, None, None).unwrap();
    s.update_relay("R3", 0.7, None, None).unwrap();

    let result = s.suspicious_relays(0.5).unwrap();
    // Highest score should be first
    assert!(result[0].score >= result[1].score);
    assert!(result[1].score >= result[2].score);
}

#[test]
fn relay_with_asn_and_country() {
    let s = store();
    s.update_relay("FP_GEO", 0.5, Some(13335), Some("DE")).unwrap();

    let records = s.suspicious_relays(0.4).unwrap();
    let rec     = records.iter().find(|r| r.fingerprint == "FP_GEO").unwrap();
    assert_eq!(rec.asn,     Some(13335));
    assert_eq!(rec.country, Some("DE".into()));
}

// ── Threat events ─────────────────────────────────────────────────────────────

fn sample_event(score: f64) -> ThreatEvent {
    ThreatEvent::new(
        ThreatLevel::High,
        ThreatKind::SybilCluster {
            shared_asn:    None,
            shared_prefix: Some("198.51.100.0".into()),
            affected_fps:  vec!["AABB".into(), "CCDD".into()],
        },
        format!("test event score={score}"),
        score,
        vec!["auto_circuit_rotate".into()],
    )
}

#[test]
fn store_and_retrieve_event() {
    let s   = store();
    let evt = sample_event(0.85);
    let id  = evt.id.to_string();
    s.store_event(&evt).unwrap();

    let recent = s.recent_events(10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, id);
    assert!((recent[0].anomaly_score - 0.85).abs() < 0.001);
}

#[test]
fn events_ordered_newest_first() {
    let s = store();
    for i in 0..5u32 {
        s.store_event(&sample_event(i as f64 / 10.0)).unwrap();
    }
    let recent = s.recent_events(10).unwrap();
    // Timestamps should be non-increasing (newest first)
    for w in recent.windows(2) {
        assert!(w[0].timestamp >= w[1].timestamp, "Events not newest-first");
    }
}

#[test]
fn duplicate_event_ignored() {
    let s   = store();
    let evt = sample_event(0.7);
    s.store_event(&evt).unwrap();
    s.store_event(&evt).unwrap(); // duplicate — same UUID
    assert_eq!(s.recent_events(10).unwrap().len(), 1);
}

#[test]
fn recent_events_limit_respected() {
    let s = store();
    for _ in 0..20 {
        s.store_event(&sample_event(0.5)).unwrap();
    }
    let recent = s.recent_events(5).unwrap();
    assert_eq!(recent.len(), 5);
}

// ── Blocked IPs ───────────────────────────────────────────────────────────────

#[test]
fn block_and_count() {
    let s = store();
    s.block_ip("1.2.3.4".parse().unwrap(), "sybil", None).unwrap();
    s.block_ip("5.6.7.8".parse().unwrap(), "timing", None).unwrap();
    assert_eq!(s.blocked_ip_count(), 2);
}

#[test]
fn block_idempotent() {
    let s  = store();
    let ip = "1.2.3.4".parse().unwrap();
    s.block_ip(ip, "reason_a", None).unwrap();
    s.block_ip(ip, "reason_b", None).unwrap(); // REPLACE — last reason wins
    assert_eq!(s.blocked_ip_count(), 1);
}

#[test]
fn prune_expired_blocks() {
    use chrono::Duration;
    let s = store();
    // One block that expired in the past
    let past = Utc::now() - Duration::hours(1);
    s.block_ip("1.2.3.4".parse().unwrap(), "expired", Some(past)).unwrap();
    // One block that expires in the future
    let future = Utc::now() + Duration::hours(1);
    s.block_ip("5.6.7.8".parse().unwrap(), "active", Some(future)).unwrap();
    // One permanent block
    s.block_ip("9.10.11.12".parse().unwrap(), "permanent", None).unwrap();

    let pruned = s.prune_expired_blocks().unwrap();
    assert_eq!(pruned, 1, "Only one block should have been pruned");
    assert_eq!(s.blocked_ip_count(), 2);
}
