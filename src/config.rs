use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    #[serde(default = "default_socks")] pub socks_addr: SocketAddr,
    #[serde(default = "default_api")]   pub api_addr:   SocketAddr,
    #[serde(default = "default_db")]    pub db_path:    PathBuf,
    pub geoip_db: Option<PathBuf>,
    #[serde(default = "default_log")]   pub log_level:  String,
    #[serde(default)]                   pub detectors:  DetectorConfig,
    #[serde(default)]                   pub mitigations:MitigationConfig,
}
impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            socks_addr:  default_socks(),
            api_addr:    default_api(),
            db_path:     default_db(),
            geoip_db:    None,
            log_level:   default_log(),
            detectors:   DetectorConfig::default(),
            mitigations: MitigationConfig::default(),
        }
    }
}
impl ShieldConfig {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) }
        else { tracing::warn!(?path, "config not found"); Ok(Self::default()) }
    }
}
fn default_socks() -> SocketAddr { "127.0.0.1:9150".parse().unwrap() }
fn default_api()   -> SocketAddr { "0.0.0.0:7878".parse().unwrap() }
fn default_db()    -> PathBuf    { PathBuf::from("artishield.db") }
fn default_log()   -> String     { "artishield=info,warn".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    #[serde(default = "yes")]  pub sybil_subnet_check:           bool,
    #[serde(default = "d1")]   pub sybil_asn_max_hops:           usize,
    #[serde(default = "d06")]  pub timing_correlation_threshold: f64,
    #[serde(default = "d30")]  pub timing_window_secs:           u64,
    #[serde(default = "d5")]   pub guard_rotation_max:           u32,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationConfig {
    #[serde(default = "yes")] pub guard_pin:            bool,
    #[serde(default = "no")]  pub auto_circuit_rotate:  bool,
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
