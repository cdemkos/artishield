//! Configuration types and TOML loader for ArtiShield.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

/// Top-level ArtiShield configuration, loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    /// Address of arti's SOCKS5 proxy (default: `127.0.0.1:9150`).
    #[serde(default = "default_socks")] pub socks_addr: SocketAddr,
    /// Address the HTTP dashboard and API will bind to (default: `127.0.0.1:7878`).
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
    /// Distributed blocklist feed (export + import).
    #[serde(default)]                   pub feed:        FeedConfig,
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
            feed:        FeedConfig::default(),
        }
    }
}
impl ShieldConfig {
    /// Load configuration from a TOML file.
    ///
    /// Falls back to [`ShieldConfig::default`] if the file does not exist.
    /// Returns an error if the file exists but cannot be parsed.
    ///
    /// Secrets can be supplied via environment variables, which always override
    /// values from the TOML file:
    ///
    /// | Variable                    | Config field                    |
    /// |-----------------------------|---------------------------------|
    /// | `ARTISHIELD_API_TOKEN`      | `api_token`                     |
    /// | `ARTISHIELD_ABUSEIPDB_KEY`  | `mitigations.abuseipdb_key`     |
    /// | `ARTISHIELD_HMAC_KEY`       | `feed.hmac_key`                 |
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let mut cfg = if path.exists() {
            toml::from_str::<Self>(&std::fs::read_to_string(path)?)?
        } else {
            tracing::warn!(?path, "config not found, using defaults");
            Self::default()
        };
        // Environment variable overrides — never log the secret values
        if let Ok(v) = std::env::var("ARTISHIELD_API_TOKEN")     { cfg.api_token                     = Some(v); }
        if let Ok(v) = std::env::var("ARTISHIELD_ABUSEIPDB_KEY") { cfg.mitigations.abuseipdb_key     = Some(v); }
        if let Ok(v) = std::env::var("ARTISHIELD_HMAC_KEY")      { cfg.feed.hmac_key                 = Some(v); }
        Ok(cfg)
    }

    /// Return a list of production warnings.
    ///
    /// Call this on startup and log each entry with `tracing::warn!`.
    pub fn validate(&self) -> Vec<String> {
        let mut w: Vec<String> = Vec::new();

        if self.api_token.is_none() {
            w.push(
                "api_token not set — write endpoints are restricted to loopback only; \
                 set ARTISHIELD_API_TOKEN for remote access"
                    .into(),
            );
        }
        if self.mitigations.abuse_reporting && self.mitigations.abuseipdb_key.is_none() {
            w.push(
                "abuse_reporting=true but abuseipdb_key is not configured \
                 (set ARTISHIELD_ABUSEIPDB_KEY) — reporting disabled"
                    .into(),
            );
        }
        if self.feed.export && self.feed.hmac_key.is_none() {
            w.push(
                "feed.export=true but hmac_key is not configured \
                 (set ARTISHIELD_HMAC_KEY) — exported feed will be unsigned"
                    .into(),
            );
        }
        if self.mitigations.canary_circuits {
            let ep = &self.mitigations.canary_endpoint;
            if ep.contains("example.com") {
                w.push(format!(
                    "canary_endpoint is still the placeholder {ep:?}; \
                     set a real .onion or Tor-reachable URL"
                ));
            } else if ep.contains("localhost")
                || ep.contains("127.0.0.1")
                || ep.contains("::1")
            {
                w.push(format!(
                    "canary_endpoint {ep:?} points to loopback — \
                     this will not test Tor connectivity"
                ));
            }
        }
        #[cfg(feature = "geoip")]
        if self.geoip_db.is_none() {
            w.push(
                "geoip feature enabled but geoip_db path not configured — \
                 ASN-based Sybil detection disabled"
                    .into(),
            );
        }
        w
    }
}
fn default_socks() -> SocketAddr { "127.0.0.1:9150".parse().unwrap() }
fn default_api()   -> SocketAddr { "127.0.0.1:7878".parse().unwrap() }
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

    // ── Active countermeasures ────────────────────────────────────────────────

    /// Inject random jitter into SOCKS probes when a timing-correlation attack is
    /// detected, corrupting the attacker's RTT samples (default: `false`).
    #[serde(default = "no")]   pub timing_noise:         bool,
    /// Minimum jitter added per probe in milliseconds (default: `5`).
    #[serde(default = "d5ms")] pub timing_noise_min_ms:  u64,
    /// Maximum jitter added per probe in milliseconds (default: `50`).
    #[serde(default = "d50")]  pub timing_noise_max_ms:  u64,

    /// Delay API responses from IPs identified as scanners/HS-enumerators (default: `false`).
    #[serde(default = "no")]     pub tarpit_scanners: bool,
    /// Artificial delay in milliseconds applied to tarpitted IPs (default: `8000`).
    #[serde(default = "d8000")]  pub tarpit_delay_ms: u64,

    /// Periodically probe circuit integrity via a canary request through SOCKS (default: `false`).
    #[serde(default = "no")]      pub canary_circuits:      bool,
    /// Interval between canary probes in seconds (default: `300`).
    #[serde(default = "d300")]    pub canary_interval_secs: u64,
    /// URL probed for canary checks — must be reachable through the Tor SOCKS proxy.
    #[serde(default = "default_canary")] pub canary_endpoint: String,

    /// Report scanner and Sybil IPs to AbuseIPDB automatically (default: `false`).
    #[serde(default = "no")]   pub abuse_reporting: bool,
    /// AbuseIPDB v2 API key (required when `abuse_reporting = true`).
    pub abuseipdb_key: Option<String>,
}
impl Default for MitigationConfig {
    fn default() -> Self {
        Self {
            guard_pin:            yes(),
            auto_circuit_rotate:  no(),
            entry_ip_filter:      no(),
            timing_noise:         no(),
            timing_noise_min_ms:  d5ms(),
            timing_noise_max_ms:  d50(),
            tarpit_scanners:      no(),
            tarpit_delay_ms:      d8000(),
            canary_circuits:      no(),
            canary_interval_secs: d300(),
            canary_endpoint:      default_canary(),
            abuse_reporting:      no(),
            abuseipdb_key:        None,
        }
    }
}
fn no()             -> bool   { false }
fn d5ms()           -> u64    { 5 }
fn d50()            -> u64    { 50 }
fn d8000()          -> u64    { 8_000 }
fn d300()           -> u64    { 300 }
fn default_canary() -> String { "http://example.com/".into() }

/// Settings for the distributed bad-relay blocklist feed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedConfig {
    /// Serve a signed JSON bad-relay feed at `GET /api/export/bad-relays` (default: `false`).
    #[serde(default = "no")] pub export: bool,
    /// HMAC-SHA256 key (hex-encoded) used to sign the exported feed.
    /// Generate with: `openssl rand -hex 32`
    pub hmac_key: Option<String>,
    /// List of upstream feed URLs to import periodically.
    #[serde(default)]         pub import_urls: Vec<String>,
    /// Import interval in seconds (default: `3600`).
    #[serde(default = "default_feed_interval")] pub import_interval_secs: u64,
}
fn default_feed_interval() -> u64 { 3_600 }
