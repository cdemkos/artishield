//! Integration tests for the DoS detector.

use artishield::{
    ShieldConfig,
    detectors::dos::DosDetector,
};
use tokio::sync::broadcast;

fn det() -> DosDetector {
    let (tx, _) = broadcast::channel(64);
    DosDetector::new(
        ShieldConfig::default(),
        tx,
        "127.0.0.1:9150".parse().unwrap(),
    )
}

// We test the analysis logic by calling internal analyse() via unit tests.
// The probe() method needs a live SOCKS5 — tested in integration only.

#[test]
fn default_config_baseline_multiplier() {
    // Verify our constant matches reasonable expectations
    assert!(artishield::detectors::dos::BASELINE_MULTIPLIER >= 2.0,
        "Baseline multiplier should be ≥ 2× for meaningful detection");
    assert!(artishield::detectors::dos::BASELINE_MULTIPLIER <= 5.0,
        "Baseline multiplier should be ≤ 5× to avoid too many false negatives");
}

#[test]
fn detector_constructs_without_panic() {
    let _ = det();
}

// The core statistical tests are in the unit tests inside dos.rs itself.
// Here we verify the public API surface:

#[test]
fn config_socks_addr_default() {
    let cfg = ShieldConfig::default();
    assert_eq!(cfg.socks_addr.port(), 9150);
}
