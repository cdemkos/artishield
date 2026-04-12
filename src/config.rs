//! Configuration types and TOML loader for ArtiShield.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

/// Top-level ArtiShield configuration, loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    /// Address of arti's SOCKS5 proxy (default: `127.0.0.1:9150`).
    #[serde(default = "default_socks")] pub socks_addr: SocketAddr,
    /// Address the HTTP dashboard and API will bind to (default: `0.0.0.0:7878`).
    #[serde(default = "default_api")]   pub api_addr:   SocketAddr,
    /// Path to the SQLite reputation database (default: `artishield.db`).
    #[serde(default = "default_db")]    pub db_path:    PathBuf,
    /// Optional path to a MaxMind GeoLite2-ASN `.mmdb` file for ASN lookups.
    pub geoip_db: Option<PathBuf>,
    /// Log level in `RUST_LOG` syntax (default: `artishield=info,warn`).
    #[serde(default = "default_log")]   pub log_level:  String,
    /// Optional Bearer token for write API endpoints (POST / DELETE).
    /// If unset, write endpoints are restricted to loopback (127.0.0.1 / ::1).
    /// Set a strong random value in production: `openssl rand -hex 32`
    pub api_token: Option<String>,
    /// Detector thresholds and tuning parameters.
    #[serde(default)]                   pub detectors:  DetectorConfig,
    /// Mitigation actions to take on detected threats.
    #[serde(default)]                   pub mitigations: MitigationConfig,
}
impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            socks_addr:  default_socks(),
            api_addr:    default_api(),
            db_path:     default_db(),
            geoip_db:    None,
            log_level:   default_log(),
            api_token:   None,
            detectors:   DetectorConfig::default(),
            mitigations: MitigationConfig::default(),
        }
    }
}
impl ShieldConfig {
    /// Load configuration from a TOML file.
    ///
    /// Falls back to [`ShieldConfig::default`] if the file does not exist.
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) }
        else { tracing::warn!(?path, "config not found"); Ok(Self::default()) }
    }
}
fn default_socks() -> SocketAddr { "127.0.0.1:9150".parse().unwrap() }
fn default_api()   -> SocketAddr { "0.0.0.0:7878".parse().unwrap() }
fn default_db()    -> PathBuf    { PathBuf::from("artishield.db") }
fn default_log()   -> String     { "artishield=info,warn".into() }

/// Tuning knobs for all threat detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Enable /24-subnet collision check in the Sybil detector (default: `true`).
    #[serde(default = "yes")]  pub sybil_subnet_check:           bool,
    /// Maximum circuit hops from the same ASN before a Sybil alert fires (default: `1`).
    #[serde(default = "d1")]   pub sybil_asn_max_hops:           usize,
    /// Pearson |r| threshold for timing-correlation alerts (default: `0.6`).
    #[serde(default = "d06")]  pub timing_correlation_threshold: f64,
    /// Minimum probe window in seconds before computing correlation (default: `30`).
    #[serde(default = "d30")]  pub timing_window_secs:           u64,
    /// Maximum guard-flag changes per consensus before a guard-discovery alert fires (default: `5`).
    #[serde(default = "d5")]   pub guard_rotation_max:           u32,
    /// Anomaly score threshold `[0, 1]` that triggers configured mitigations (default: `0.70`).
    #[serde(default = "d07")]  pub alert_threshold:              f64,
}
impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            sybil_subnet_check:           yes(),
            sybil_asn_max_hops:           d1(),
            timing_correlation_threshold: d06(),
            timing_window_secs:           d30(),
            guard_rotation_max:           d5(),
            alert_threshold:              d07(),
        }
    }
}
fn yes()  -> bool  { true }
fn d1()   -> usize { 1    }
fn d06()  -> f64   { 0.6  }
fn d30()  -> u64   { 30   }
fn d5()   -> u32   { 5    }
fn d07()  -> f64   { 0.70 }

/// Actions the mitigation engine may take when a threat is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationConfig {
    /// Log an alert when an unexpected guard rotation is detected (default: `true`).
    #[serde(default = "yes")] pub guard_pin:            bool,
    /// Automatically rotate the circuit via `TorClient::isolated_client()` when
    /// the anomaly score exceeds `alert_threshold` (default: `false`).
    #[serde(default = "no")]  pub auto_circuit_rotate:  bool,
    /// Add suspected Sybil and scanner IPs to the persistent IP blocklist (default: `false`).
    #[serde(default = "no")]  pub entry_ip_filter:      bool,
}
impl Default for MitigationConfig {
    fn default() -> Self {
        Self {
            guard_pin:           yes(),
            auto_circuit_rotate: no(),
            entry_ip_filter:     no(),
        }
    }
}
fn no() -> bool { false }
