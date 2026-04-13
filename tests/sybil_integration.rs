//! Integration tests for SybilDetector — no arti crate dependency needed.

use artishield::{
    detectors::sybil::{CircuitHop, SybilDetector},
    event::ThreatKind,
    ShieldConfig,
};
use std::net::SocketAddr;
use tokio::sync::broadcast;

fn det() -> SybilDetector {
    let (tx, _) = broadcast::channel(64);
    SybilDetector::new(ShieldConfig::default(), tx)
}

fn hop(ip: &str, fp: &str, guard: bool, exit: bool) -> CircuitHop {
    CircuitHop {
        fingerprint: fp.into(),
        addrs: vec![format!("{ip}:443").parse::<SocketAddr>().unwrap()],
        is_guard: guard,
        is_exit: exit,
    }
}

#[test]
fn clean_circuit_no_event() {
    assert!(det()
        .check_hops(&[
            hop("91.108.4.1", "GUARD", true, false),
            hop("185.220.101.5", "MIDDLE", false, false),
            hop("46.23.73.200", "EXIT", false, true),
        ])
        .is_none());
}

#[test]
fn guard_exit_same_slash24_fires_high() {
    let d = det();
    let evt = d
        .check_hops(&[
            hop("198.51.100.10", "GUARD", true, false),
            hop("185.220.101.5", "MIDDLE", false, false),
            hop("198.51.100.200", "EXIT", false, true),
        ])
        .expect("Expected Sybil event");

    assert!(matches!(&evt.kind,
        ThreatKind::SybilCluster { shared_prefix: Some(p), .. } if p == "198.51.100.0"));
    assert!(evt.anomaly_score >= 0.8);
}

#[test]
fn guard_middle_same_slash24_fires() {
    assert!(det()
        .check_hops(&[
            hop("10.20.30.5", "G", true, false),
            hop("10.20.30.50", "M", false, false),
            hop("5.6.7.8", "E", false, true),
        ])
        .is_some());
}

#[test]
fn different_slash24_same_slash16_is_clean() {
    assert!(det()
        .check_hops(&[
            hop("203.0.113.10", "G", true, false),
            hop("203.0.114.10", "M", false, false),
            hop("198.51.100.1", "E", false, true),
        ])
        .is_none());
}

#[test]
fn ipv6_no_panic() {
    let hops = vec![
        CircuitHop {
            fingerprint: "G".into(),
            addrs: vec!["[2001:db8::1]:443".parse().unwrap()],
            is_guard: true,
            is_exit: false,
        },
        CircuitHop {
            fingerprint: "M".into(),
            addrs: vec!["[2001:db8::2]:443".parse().unwrap()],
            is_guard: false,
            is_exit: false,
        },
        CircuitHop {
            fingerprint: "E".into(),
            addrs: vec!["[2001:db8::3]:443".parse().unwrap()],
            is_guard: false,
            is_exit: true,
        },
    ];
    let _ = det().check_hops(&hops);
}

#[test]
fn single_hop_ignored() {
    assert!(det()
        .check_hops(&[hop("1.2.3.4", "G", true, false)])
        .is_none());
}

#[test]
fn sybil_event_suggests_circuit_rotate() {
    let evt = det()
        .check_hops(&[
            hop("198.51.100.1", "G", true, false),
            hop("5.6.7.8", "M", false, false),
            hop("198.51.100.200", "E", false, true),
        ])
        .unwrap();
    assert!(evt
        .suggested_mitigations
        .iter()
        .any(|m| m.contains("circuit_rotate")));
}
