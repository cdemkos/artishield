//! Threat event types shared across all detectors and the HTTP API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Severity of a detected threat, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatLevel {
    /// Informational — no immediate action required.
    Info,
    /// Low-severity anomaly — monitor but no mitigation needed.
    Low,
    /// Moderate anomaly — consider circuit rotation.
    Medium,
    /// Significant threat — mitigation recommended.
    High,
    /// Severe threat — immediate mitigation required.
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        })
    }
}

/// The specific threat category detected, with supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatKind {
    /// A group of relays sharing a /24 subnet or ASN — Sybil attack indicator.
    SybilCluster {
        /// Shared Autonomous System Number, if identified.
        shared_asn: Option<u32>,
        /// Shared /24 IPv4 prefix, if identified.
        shared_prefix: Option<String>,
        /// Fingerprints of relays in the suspected cluster.
        affected_fps: Vec<String>,
    },
    /// Statistical timing correlation between probe RTTs and a burst signal.
    TimingCorrelation {
        /// Pearson correlation coefficient `[-1, 1]`.
        pearson_r: f64,
        /// Number of probe samples used.
        sample_count: usize,
        /// Estimated probability of successful de-anonymisation.
        deanon_probability: f64,
    },
    /// Denial-of-service indicators: latency spikes or bursty SENDME delivery.
    DenialOfService {
        /// Estimated SENDME cell rate (cells per second).
        sendme_rate: u32,
        /// Number of samples in the latency queue.
        queue_depth: usize,
        /// Fingerprint of the suspected source relay, if known.
        source_relay: Option<String>,
    },
    /// Unexpected guard-flag churn in a consensus — guard-discovery attack indicator.
    GuardDiscovery {
        /// Number of guard relays added or removed.
        rotation_count: u32,
        /// Observation window in seconds.
        window_secs: u64,
        /// Fingerprints of newly added or suspicious guard relays.
        suspicious_fingerprints: Vec<String>,
    },
    /// Abnormal HSDir concentration or descriptor-fetch rate — enumeration indicator.
    HsEnumeration {
        /// Descriptor-fetch rate (fetches per `window_secs`).
        intro_rate: u32,
        /// Observation window in seconds.
        window_secs: u64,
        /// IP address of the suspected scanner, if identified.
        suspected_scanner: Option<IpAddr>,
    },
    /// Composite anomaly score spike from multiple detectors firing simultaneously.
    AnomalySpike {
        /// Blended anomaly score `[0, 1]`.
        score: f64,
        /// Names of the detectors that contributed to this spike.
        contributing_detectors: Vec<String>,
    },
    /// Canary circuit probe failed — circuit integrity may be compromised.
    CanaryFailure {
        /// The endpoint URL that was probed.
        endpoint: String,
        /// Short reason string: `"timeout"` | `"bad_response"` | `"connect_failed"`.
        reason: String,
    },
}

/// A single detected threat event emitted by a detector onto the event bus.
// uuid with feature "serde" implements Serialize/Deserialize natively
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Unique identifier for this event (UUIDv4).
    pub id: Uuid,
    /// UTC timestamp of detection.
    pub timestamp: DateTime<Utc>,
    /// Severity level.
    pub level: ThreatLevel,
    /// Detailed threat category and supporting evidence.
    pub kind: ThreatKind,
    /// Human-readable description of the threat.
    pub message: String,
    /// Mitigation action keys (e.g. `"auto_circuit_rotate"`) suggested for this event.
    pub suggested_mitigations: Vec<String>,
    /// Blended anomaly score `[0, 1]` at the time of detection.
    pub anomaly_score: f64,
}

impl ThreatEvent {
    /// Construct a new `ThreatEvent` with a fresh UUIDv4 and the current UTC timestamp.
    ///
    /// `score` is clamped to `[0.0, 1.0]`.
    pub fn new(
        level: ThreatLevel,
        kind: ThreatKind,
        message: impl Into<String>,
        score: f64,
        mitigations: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level,
            kind,
            message: message.into(),
            suggested_mitigations: mitigations,
            anomaly_score: score.clamp(0.0, 1.0),
        }
    }
}

/// Point-in-time metrics snapshot exposed by the `/api/metrics` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    /// UTC timestamp of this snapshot.
    pub timestamp: Option<DateTime<Utc>>,
    /// Number of active Tor circuits (0 when arti-hooks is disabled).
    pub active_circuits: u32,
    /// Exponentially smoothed anomaly score `[0, 1]`.
    pub anomaly_score: f64,
    /// Number of currently active (non-expired) blocked IPs.
    pub blocked_ips: u32,
    /// Estimated bandwidth in kilobits per second (0 when arti-hooks is disabled).
    pub bandwidth_kbps: f64,
    /// Number of threat events detected in the last 60 seconds.
    pub events_last_minute: u32,
    /// Fingerprint of the current guard relay, if available.
    pub guard_fingerprint: Option<String>,
    /// Severity level of the most recent event, if any.
    pub threat_level: Option<ThreatLevel>,
}
