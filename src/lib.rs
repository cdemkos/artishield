//! ArtiShield — threat monitoring & mitigation for arti (Tor Rust client).
//!
//! # Feature flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `arti-hooks` | yes | Real arti integration via `experimental-api` |
//! | `geoip` | yes | MaxMind GeoLite2-ASN for ASN-based Sybil detection |
//!
//! Build without arti for unit-testing the core logic:
//! ```bash
//! cargo test --no-default-features
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, missing_docs, rust_2018_idioms)]

pub mod config;
pub mod detectors;
pub mod event;
pub mod mitigations;
pub mod monitor;
pub mod storage;

pub use config::ShieldConfig;
pub use event::{ThreatEvent, ThreatKind, ThreatLevel};
pub use monitor::ArtiShield;
