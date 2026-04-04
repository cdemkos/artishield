//! Integration tests for ReputationStore.

use artishield::storage::ReputationStore;
use chrono::{Duration, Utc};
use std::net::IpAddr;

// ── EMA ───────────────────────────────────────────────────────────────────────

#[test]
fn ema_blends_correctly() {
    let s = ReputationStore::in_memory().unwrap();
    s.update_relay("A", 0.9, None, None).unwrap();
    s.update_relay("A", 0.0, None, None).unwrap();
    let score = s.relay_score("A");
    assert!((score - 0.63).abs() < 0.02, "EMA={score}");
}

#[test]
fn first_update_no_blend() {
    let s = ReputationStore::in_memory().unwrap();
    s.update_relay("NEW", 0.5, None, None).unwrap();
    assert!((s.relay_score("NEW") - 0.5).abs() < 0.001);
}

// ── Flags ─────────────────────────────────────────────────────────────────────

#[test]
fn flag_added() {
    let s = ReputationStore::in_memory().unwrap();
    s.update_relay("B", 0.9, None, None).unwrap();
    s.add_flag("B", "sybil").unwrap();
    let relays = s.suspicious_relays(0.0).unwrap();
    assert!(relays[0].flags.contains("sybil"));
}

#[test]
fn flag_no_duplicate() {
    let s = ReputationStore::in_memory().unwrap();
    s.update_relay("C", 0.9, None, None).unwrap();
    s.add_flag("C", "sybil").unwrap();
    s.add_flag("C", "sybil").unwrap();
    s.add_flag("C", "guard_inj").unwrap();
    let relays = s.suspicious_relays(0.0).unwrap();
    let flags  = &relays[0].flags;
    assert_eq!(flags.matches("sybil").count(), 1, "duplicate sybil flag: {flags}");
    assert!(flags.contains("guard_inj"));
}

// ── Suspicious filter ─────────────────────────────────────────────────────────

#[test]
fn suspicious_threshold() {
    let s = ReputationStore::in_memory().unwrap();
    s.update_relay("GOOD", 0.1, None, None).unwrap();
    s.update_relay("BAD",  0.9, None, None).unwrap();
    let sus = s.suspicious_relays(0.5).unwrap();
    assert_eq!(sus.len(), 1);
    assert_eq!(sus[0].fingerprint, "BAD");
}

// ── ASN storage ───────────────────────────────────────────────────────────────

#[test]
fn asn_stored_as_i64() {
    let s = ReputationStore::in_memory().unwrap();
    // u32::MAX fits in i64
    s.update_relay("D", 0.5, Some(4_294_967_295u32), Some("DE")).unwrap();
    let relays = s.suspicious_relays(0.0).unwrap();
    assert_eq!(relays[0].asn, Some(4_294_967_295i64));
    assert_eq!(relays[0].country.as_deref(), Some("DE"));
}

// ── IP blocklist ──────────────────────────────────────────────────────────────

#[test]
fn block_and_count() {
    let s = ReputationStore::in_memory().unwrap();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    s.block_ip(ip, "test", None).unwrap();
    assert_eq!(s.blocked_ip_count(), 1);
    assert!(s.is_blocked(&ip));
}

#[test]
fn unblock_works() {
    let s  = ReputationStore::in_memory().unwrap();
    let ip: IpAddr = "5.6.7.8".parse().unwrap();
    s.block_ip(ip, "test", None).unwrap();
    s.unblock_ip("5.6.7.8").unwrap();
    assert_eq!(s.blocked_ip_count(), 0);
    assert!(!s.is_blocked(&ip));
}

#[test]
fn unblocked_ip_not_blocked() {
    let s = ReputationStore::in_memory().unwrap();
    let ip: IpAddr = "9.10.11.12".parse().unwrap();
    assert!(!s.is_blocked(&ip));
}

#[test]
fn expired_block_pruned() {
    let s  = ReputationStore::in_memory().unwrap();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    // expires in the past
    let past = Utc::now() - Duration::hours(1);
    s.block_ip(ip, "expired", Some(past)).unwrap();
    // blocked_ip_count must NOT include expired entries — they are not actually blocking
    assert_eq!(s.blocked_ip_count(), 0, "expired IP must not appear in blocked count");
    assert!(!s.is_blocked(&ip), "is_blocked must be false for expired entry");
    let pruned = s.prune_expired_blocks().unwrap();
    assert_eq!(pruned, 1);
    assert_eq!(s.blocked_ip_count(), 0);
}

#[test]
fn active_block_not_pruned() {
    let s   = ReputationStore::in_memory().unwrap();
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
    let future = Utc::now() + Duration::hours(1);
    s.block_ip(ip, "active", Some(future)).unwrap();
    let pruned = s.prune_expired_blocks().unwrap();
    assert_eq!(pruned, 0);
    assert_eq!(s.blocked_ip_count(), 1);
}

// ── Events ────────────────────────────────────────────────────────────────────

#[test]
fn recent_events_empty_initially() {
    let s = ReputationStore::in_memory().unwrap();
    assert!(s.recent_events(10).unwrap().is_empty());
}

#[test]
fn recent_events_limit() {
    use artishield::event::{ThreatEvent, ThreatKind, ThreatLevel};
    let s = ReputationStore::in_memory().unwrap();
    for _ in 0..5 {
        let evt = ThreatEvent::new(
            ThreatLevel::Low,
            ThreatKind::AnomalySpike {
                score: 0.1,
                contributing_detectors: vec![],
            },
            "test",
            0.1,
            vec![],
        );
        s.store_event(&evt).unwrap();
    }
    assert_eq!(s.recent_events(3).unwrap().len(), 3);
    assert_eq!(s.recent_events(100).unwrap().len(), 5);
}
