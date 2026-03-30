//! # Prometheus Metrics
//!
//! Exposes a `/metrics` endpoint in the Prometheus text format.
//! No external library needed — we hand-write the exposition format.
//!
//! ## Available metrics
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `artishield_anomaly_score` | gauge | Rolling anomaly score [0, 1] |
//! | `artishield_events_total` | counter | Total threat events by level |
//! | `artishield_blocked_ips` | gauge | Currently blocked IPs |
//! | `artishield_events_last_minute` | gauge | Events in the last 60 s |
//! | `artishield_detector_events_total` | counter | Events per detector kind |

use crate::{
    event::{ThreatKind, ThreatLevel},
    storage::ReputationStore,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use super::SharedState;

/// Render the current state as a Prometheus text exposition.
pub async fn render(
    shared: &Arc<RwLock<SharedState>>,
    store:  &Arc<ReputationStore>,
) -> String {
    let state = shared.read().await;
    let mut out = String::with_capacity(2048);

    // ── artishield_anomaly_score ──────────────────────────────────────────────
    out.push_str("# HELP artishield_anomaly_score Rolling threat anomaly score [0,1]\n");
    out.push_str("# TYPE artishield_anomaly_score gauge\n");
    out.push_str(&format!("artishield_anomaly_score {:.6}\n", state.anomaly_score));

    // ── artishield_blocked_ips ────────────────────────────────────────────────
    out.push_str("# HELP artishield_blocked_ips Number of currently blocked IPs\n");
    out.push_str("# TYPE artishield_blocked_ips gauge\n");
    out.push_str(&format!("artishield_blocked_ips {}\n", store.blocked_ip_count()));

    // ── artishield_events_last_minute ─────────────────────────────────────────
    out.push_str("# HELP artishield_events_last_minute Threat events in last 60 s\n");
    out.push_str("# TYPE artishield_events_last_minute gauge\n");
    out.push_str(&format!(
        "artishield_events_last_minute {}\n",
        state.metrics.events_last_minute,
    ));

    // ── artishield_events_total (by level) ────────────────────────────────────
    out.push_str("# HELP artishield_events_total Total threat events since start, by level\n");
    out.push_str("# TYPE artishield_events_total counter\n");
    let levels = [
        ThreatLevel::Info,
        ThreatLevel::Low,
        ThreatLevel::Medium,
        ThreatLevel::High,
        ThreatLevel::Critical,
    ];
    for level in &levels {
        let count = state.recent_events.iter()
            .filter(|e| e.level == *level)
            .count();
        out.push_str(&format!(
            "artishield_events_total{{level=\"{level}\"}} {count}\n"
        ));
    }

    // ── artishield_detector_events_total (by kind) ────────────────────────────
    out.push_str("# HELP artishield_detector_events_total Events per detector\n");
    out.push_str("# TYPE artishield_detector_events_total counter\n");
    let kinds = ["sybil_cluster", "timing_correlation", "denial_of_service",
                 "guard_discovery", "hs_enumeration", "anomaly_spike"];
    for kind in &kinds {
        let count = state.recent_events.iter()
            .filter(|e| kind_label(&e.kind) == *kind)
            .count();
        out.push_str(&format!(
            "artishield_detector_events_total{{detector=\"{kind}\"}} {count}\n"
        ));
    }

    // ── artishield_build_info ─────────────────────────────────────────────────
    out.push_str("# HELP artishield_build_info Build information\n");
    out.push_str("# TYPE artishield_build_info gauge\n");
    out.push_str(&format!(
        "artishield_build_info{{version=\"{}\",features=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"),
        feature_string(),
    ));

    out
}

fn kind_label(kind: &ThreatKind) -> &'static str {
    match kind {
        ThreatKind::SybilCluster { .. }       => "sybil_cluster",
        ThreatKind::TimingCorrelation { .. }  => "timing_correlation",
        ThreatKind::DenialOfService { .. }    => "denial_of_service",
        ThreatKind::GuardDiscovery { .. }     => "guard_discovery",
        ThreatKind::HsEnumeration { .. }      => "hs_enumeration",
        ThreatKind::AnomalySpike { .. }       => "anomaly_spike",
    }
}

fn feature_string() -> &'static str {
    #[cfg(all(feature = "arti-hooks", feature = "geoip"))]
    return "arti-hooks,geoip";
    #[cfg(all(feature = "arti-hooks", not(feature = "geoip")))]
    return "arti-hooks";
    #[cfg(all(not(feature = "arti-hooks"), feature = "geoip"))]
    return "geoip";
    #[cfg(all(not(feature = "arti-hooks"), not(feature = "geoip")))]
    return "none";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn renders_valid_prometheus_format() {
        let shared = Arc::new(RwLock::new(SharedState::default()));
        let store  = Arc::new(crate::storage::ReputationStore::in_memory().unwrap());

        let output = render(&shared, &store).await;

        // Every metric must have a HELP and TYPE line
        assert!(output.contains("# HELP artishield_anomaly_score"));
        assert!(output.contains("# TYPE artishield_anomaly_score gauge"));
        assert!(output.contains("artishield_anomaly_score 0.000000"));

        // Must not have trailing whitespace on metric lines
        for line in output.lines() {
            if line.starts_with("artishield_") && !line.starts_with('#') {
                assert!(
                    !line.ends_with(' '),
                    "Metric line has trailing space: {line:?}"
                );
            }
        }

        // Build info must be present
        assert!(output.contains("artishield_build_info{"));
    }

    #[tokio::test]
    async fn level_labels_correct() {
        let shared = Arc::new(RwLock::new(SharedState::default()));
        let store  = Arc::new(crate::storage::ReputationStore::in_memory().unwrap());
        let output = render(&shared, &store).await;

        assert!(output.contains("level=\"CRITICAL\""));
        assert!(output.contains("level=\"HIGH\""));
        assert!(output.contains("level=\"MEDIUM\""));
        assert!(output.contains("level=\"LOW\""));
        assert!(output.contains("level=\"INFO\""));
    }
}
