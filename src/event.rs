use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatLevel { Info, Low, Medium, High, Critical }

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Info => "INFO", Self::Low => "LOW", Self::Medium => "MEDIUM",
            Self::High => "HIGH", Self::Critical => "CRITICAL",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatKind {
    SybilCluster {
        shared_asn:    Option<u32>,
        shared_prefix: Option<String>,
        affected_fps:  Vec<String>,
    },
    TimingCorrelation {
        pearson_r:          f64,
        sample_count:       usize,
        deanon_probability: f64,
    },
    DenialOfService {
        sendme_rate:  u32,
        queue_depth:  usize,
        source_relay: Option<String>,
    },
    GuardDiscovery {
        rotation_count:          u32,
        window_secs:             u64,
        suspicious_fingerprints: Vec<String>,
    },
    HsEnumeration {
        intro_rate:        u32,
        window_secs:       u64,
        suspected_scanner: Option<IpAddr>,
    },
    AnomalySpike {
        score:                  f64,
        contributing_detectors: Vec<String>,
    },
}

// uuid with feature "serde" implements Serialize/Deserialize natively
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id:                    Uuid,
    pub timestamp:             DateTime<Utc>,
    pub level:                 ThreatLevel,
    pub kind:                  ThreatKind,
    pub message:               String,
    pub suggested_mitigations: Vec<String>,
    pub anomaly_score:         f64,
}

impl ThreatEvent {
    pub fn new(
        level:       ThreatLevel,
        kind:        ThreatKind,
        message:     impl Into<String>,
        score:       f64,
        mitigations: Vec<String>,
    ) -> Self {
        Self {
            id:                    Uuid::new_v4(),
            timestamp:             Utc::now(),
            level,
            kind,
            message:               message.into(),
            suggested_mitigations: mitigations,
            anomaly_score:         score.clamp(0.0, 1.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    pub timestamp:          Option<DateTime<Utc>>,
    pub active_circuits:    u32,
    pub anomaly_score:      f64,
    pub blocked_ips:        u32,
    pub bandwidth_kbps:     f64,
    pub events_last_minute: u32,
    pub guard_fingerprint:  Option<String>,
    pub threat_level:       Option<ThreatLevel>,
}
