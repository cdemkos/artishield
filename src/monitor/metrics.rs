//! Prometheus text exposition — `/metrics` endpoint.
//!
//! No external library. We hand-write the Prometheus text format.
//! Format spec: https://prometheus.io/docs/instrumenting/exposition_formats/

use crate::{
    event::{ThreatKind, ThreatLevel},
    storage::ReputationStore,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::SharedState;

/// Render the current state as a Prometheus text exposition.
pub async fn render(shared: &Arc<RwLock<SharedState>>, store: &Arc<ReputationStore>) -> String {
    let state = shared.read().await;
    let mut out = String::with_capacity(2048);

    // ── artishield_anomaly_score ──────────────────────────────────────────────
    metric(
        &mut out,
        "artishield_anomaly_score",
        "gauge",
        "Rolling threat anomaly score [0,1]",
        &[("", state.anomaly_score)],
    );

    // ── artishield_blocked_ips ────────────────────────────────────────────────
    metric(
        &mut out,
        "artishield_blocked_ips",
        "gauge",
        "Number of currently blocked IPs",
        &[("", store.blocked_ip_count() as f64)],
    );

    // ── artishield_events_last_minute ─────────────────────────────────────────
    metric(
        &mut out,
        "artishield_events_last_minute",
        "gauge",
        "Threat events in the last 60 s",
        &[("", state.metrics.events_last_minute as f64)],
    );

    // ── artishield_events_recent (by level) ──────────────────────────────────
    // Gauge, not counter: values come from a 200-event rolling buffer and can
    // decrease as old entries roll off. A Prometheus counter must never decrease.
    out.push_str("# HELP artishield_events_recent Threat events in recent buffer, by level\n");
    out.push_str("# TYPE artishield_events_recent gauge\n");
    for level in [
        ThreatLevel::Info,
        ThreatLevel::Low,
        ThreatLevel::Medium,
        ThreatLevel::High,
        ThreatLevel::Critical,
    ] {
        let count = state
            .recent_events
            .iter()
            .filter(|e| e.level == level)
            .count();
        out.push_str(&format!(
            "artishield_events_recent{{level=\"{level}\"}} {count}\n"
        ));
    }

    // ── artishield_detector_events_recent (by kind) ───────────────────────────
    // Same reasoning: gauge because this is a sliding window, not a true total.
    out.push_str("# HELP artishield_detector_events_recent Events per detector in recent buffer\n");
    out.push_str("# TYPE artishield_detector_events_recent gauge\n");
    for kind in [
        "sybil_cluster",
        "timing_correlation",
        "denial_of_service",
        "guard_discovery",
        "hs_enumeration",
        "anomaly_spike",
        "canary_failure",
    ] {
        let count = state
            .recent_events
            .iter()
            .filter(|e| kind_label(&e.kind) == kind)
            .count();
        out.push_str(&format!(
            "artishield_detector_events_recent{{detector=\"{kind}\"}} {count}\n"
        ));
    }

    // ── artishield_build_info ─────────────────────────────────────────────────
    out.push_str("# HELP artishield_build_info Build metadata\n");
    out.push_str("# TYPE artishield_build_info gauge\n");
    out.push_str(&format!(
        "artishield_build_info{{version=\"{}\",features=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"),
        active_features(),
    ));

    out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn metric(out: &mut String, name: &str, typ: &str, help: &str, values: &[(&str, f64)]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} {typ}\n"));
    for (labels, value) in values {
        if labels.is_empty() {
            out.push_str(&format!("{name} {value:.6}\n"));
        } else {
            out.push_str(&format!("{name}{{{labels}}} {value:.6}\n"));
        }
    }
}

/// Map a ThreatKind to the Prometheus label string.
/// Must be exhaustive — new variants will cause a compile error here, which is intentional.
fn kind_label(kind: &ThreatKind) -> &'static str {
    match kind {
        ThreatKind::SybilCluster { .. } => "sybil_cluster",
        ThreatKind::TimingCorrelation { .. } => "timing_correlation",
        ThreatKind::DenialOfService { .. } => "denial_of_service",
        ThreatKind::GuardDiscovery { .. } => "guard_discovery",
        ThreatKind::HsEnumeration { .. } => "hs_enumeration",
        ThreatKind::AnomalySpike { .. } => "anomaly_spike",
        ThreatKind::CanaryFailure { .. } => "canary_failure",
    }
}

fn active_features() -> &'static str {
    #[cfg(all(feature = "arti-hooks", feature = "geoip"))]
    return "arti-hooks,geoip";
    #[cfg(all(feature = "arti-hooks", not(feature = "geoip")))]
    return "arti-hooks";
    #[cfg(all(not(feature = "arti-hooks"), feature = "geoip"))]
    return "geoip";
    #[cfg(all(not(feature = "arti-hooks"), not(feature = "geoip")))]
    return "none";
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn valid_prometheus_format() {
        let shared = Arc::new(RwLock::new(SharedState::default()));
        let store = Arc::new(crate::storage::ReputationStore::in_memory().unwrap());
        let output = render(&shared, &store).await;

        assert!(output.contains("# HELP artishield_anomaly_score"));
        assert!(output.contains("# TYPE artishield_anomaly_score gauge"));
        assert!(output.contains("artishield_anomaly_score 0.000000"));
        assert!(output.contains("artishield_build_info{"));

        // No trailing whitespace on metric lines
        for line in output.lines() {
            if !line.starts_with('#') && !line.is_empty() {
                assert!(!line.ends_with(' '), "trailing space: {line:?}");
            }
        }
    }

    #[tokio::test]
    async fn all_levels_present() {
        let shared = Arc::new(RwLock::new(SharedState::default()));
        let store = Arc::new(crate::storage::ReputationStore::in_memory().unwrap());
        let output = render(&shared, &store).await;

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
            assert!(
                output.contains(&format!("level=\"{level}\"")),
                "missing level {level}"
            );
        }
        // Verify correct Prometheus type: gauge (not counter) since buffer can shrink
        assert!(
            output.contains("# TYPE artishield_events_recent gauge"),
            "events_recent must be gauge, not counter"
        );
        assert!(
            output.contains("# TYPE artishield_detector_events_recent gauge"),
            "detector_events_recent must be gauge, not counter"
        );
    }
}
