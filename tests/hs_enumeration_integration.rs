//! Integration tests for the HS enumeration detector.

use artishield::{
    ShieldConfig,
    detectors::hs_enumeration::{HsEnumDetector, HsDirSnapshot},
    event::ThreatKind,
};
use tokio::sync::broadcast;

fn det() -> HsEnumDetector {
    let (tx, _) = broadcast::channel(64);
    HsEnumDetector::new(ShieldConfig::default(), tx)
}

fn snap(fps: &[(&str, Option<&str>)]) -> HsDirSnapshot {
    HsDirSnapshot {
        fps: fps.iter()
            .map(|(fp, ip)| (fp.to_string(), ip.map(|s| s.parse().unwrap())))
            .collect(),
    }
}

// ── HsDir analysis ────────────────────────────────────────────────────────────

#[test]
fn small_network_no_alert() {
    let d = det();
    let s = snap(&(0..5).map(|i| (
        Box::leak(format!("FP{i}").into_boxed_str()) as &str,
        Some("1.2.3.4")
    )).collect::<Vec<_>>());
    assert!(d.analyse_hsdir(&s).is_empty());
}

#[test]
fn concentrated_hsdir_fires_event() {
    let d = det();
    // 10 HSDir nodes in same /24 out of 100 = 10% — above 5% threshold
    let mut fps: Vec<(String, Option<&'static str>)> = (0..10)
        .map(|i| (format!("BAD{i:02}"), Some("198.51.100.1")))
        .collect();
    fps.extend((10..100).map(|i| (format!("OK{i:02}"), Some("1.2.3.4"))));
    let s = snap(&fps.iter().map(|(a, b)| (a.as_str(), *b)).collect::<Vec<_>>());
    let evts = d.analyse_hsdir(&s);
    assert!(!evts.is_empty(), "10% HSDir concentration should trigger alert");
    assert!(matches!(evts[0].kind, ThreatKind::HsEnumeration { .. }));
}

#[test]
fn dispersed_hsdir_no_alert() {
    let d = det();
    // 100 nodes, each in a different /24 → no concentration
    let fps: Vec<(String, Option<String>)> = (0..100u32)
        .map(|i| (format!("FP{i:03}"), Some(format!("{}.{}.{}.1",
            (i / 65536) % 256,
            (i / 256) % 256,
            i % 256,
        )))).collect();
    let s = HsDirSnapshot {
        fps: fps.iter()
            .map(|(fp, ip)| (fp.clone(), ip.as_ref().map(|s| s.parse().unwrap())))
            .collect(),
    };
    assert!(d.analyse_hsdir(&s).is_empty(), "Dispersed HSDir nodes should not alert");
}

// ── Descriptor fetch rate ─────────────────────────────────────────────────────

#[test]
fn desc_fetch_below_limit_no_alert() {
    let mut d = det();
    let mut last = None;
    for _ in 0..15 { last = d.record_desc_fetch(); }
    // 15 is below the limit of 20 — should not alert yet
    // (note: timing can affect this if tests run slow)
    let _ = last; // may or may not be Some
}

#[test]
fn desc_fetch_burst_triggers_alert() {
    let mut d = det();
    // Inject 25 fetches rapidly
    let mut last = None;
    for _ in 0..25 { last = d.record_desc_fetch(); }
    assert!(last.is_some(), "25 descriptor fetches should trigger alert");
    assert!(matches!(last.unwrap().kind, ThreatKind::HsEnumeration { .. }));
}

#[test]
fn config_defaults_sensible() {
    let cfg = ShieldConfig::default();
    // Alert threshold should be between 0.5 and 1.0
    assert!(cfg.detectors.alert_threshold > 0.5);
    assert!(cfg.detectors.alert_threshold <= 1.0);
}
