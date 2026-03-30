//! Integration tests for GuardDiscoveryDetector.

use artishield::{ShieldConfig, event::ThreatKind};
use artishield::detectors::guard_discovery::{GuardDiscoveryDetector, GuardSnapshot};
use std::collections::HashMap;
use tokio::sync::broadcast;

fn det() -> GuardDiscoveryDetector {
    let (tx, _) = broadcast::channel(64);
    GuardDiscoveryDetector::new(ShieldConfig::default(), tx)
}
fn snap(fps: &[(&str, Option<&str>)]) -> GuardSnapshot {
    GuardSnapshot {
        fps: fps.iter()
            .map(|(fp, ip)| (fp.to_string(), ip.map(|s| s.parse().unwrap())))
            .collect(),
    }
}

#[test]
fn no_churn_is_silent() {
    let mut d  = det();
    let s      = snap(&[("AA", Some("1.2.3.4")), ("BB", Some("5.6.7.8"))]);
    assert!(d.analyse_transition(&s.clone(), &s).is_empty());
}

#[test]
fn full_churn_fires_event() {
    let mut d = det();
    let prev_raw: Vec<(String, Option<&str>)> = (0..10).map(|i|(format!("P{i:02}"), Some("1.1.1.1"))).collect();
    let curr_raw: Vec<(String, Option<&str>)> = (10..20).map(|i|(format!("C{i:02}"), Some("2.2.2.2"))).collect();
    let prev = snap(&prev_raw.iter().map(|(a,b)|(a.as_str(),*b)).collect::<Vec<_>>());
    let curr = snap(&curr_raw.iter().map(|(a,b)|(a.as_str(),*b)).collect::<Vec<_>>());
    assert!(!d.analyse_transition(&prev, &curr).is_empty());
}

#[test]
fn new_guard_subnet_cluster_fires() {
    let mut d = det();
    let prev  = snap(&[("OLD", Some("1.2.3.4"))]);
    let curr  = snap(&[
        ("OLD", Some("1.2.3.4")),
        ("N1",  Some("198.51.100.1")),
        ("N2",  Some("198.51.100.2")),
        ("N3",  Some("198.51.100.3")),
    ]);
    let evts = d.analyse_transition(&prev, &curr);
    assert!(evts.iter().any(|e| matches!(&e.kind, ThreatKind::GuardDiscovery{..})));
}

#[test]
fn config_defaults() {
    let cfg = ShieldConfig::default();
    assert_eq!(cfg.detectors.guard_rotation_max, 5);
    assert!((cfg.detectors.alert_threshold - 0.70).abs() < 0.01);
    assert!(cfg.mitigations.guard_pin);
}

#[test]
fn config_toml_roundtrip() {
    let src = r#"
        socks_addr = "127.0.0.1:9150"
        api_addr   = "127.0.0.1:7878"
        db_path    = "test.db"
        [detectors]
        guard_rotation_max = 3
        alert_threshold    = 0.80
        [mitigations]
        auto_circuit_rotate = true
    "#;
    let cfg: ShieldConfig = toml::from_str(src).unwrap();
    assert_eq!(cfg.detectors.guard_rotation_max, 3);
    assert!(cfg.mitigations.auto_circuit_rotate);
}
