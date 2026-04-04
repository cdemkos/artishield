//! Detector subsystem.
//!
//! | Detector           | Hook                                                   |
//! |--------------------|--------------------------------------------------------|
//! | `SybilDetector`    | `dirmgr().events()` → `NetDir::relays()`               |
//! | `GuardDiscovery`   | `dirmgr().events()` → Guard-flag diff                  |
//! | `HsEnumDetector`   | `dirmgr().events()` → HSDir-flag concentration         |
//! | `TimingDetector`   | SOCKS5 RTT probe via `tokio-socks`                     |
//! | `DosDetector`      | SOCKS5 connect-latency spike detection                 |

pub mod dos;
pub mod guard_discovery;
pub mod hs_enumeration;
pub mod sybil;
pub mod timing;

use crate::event::ThreatEvent;
use tokio::sync::broadcast;

/// Sender — detectors clone this to emit events.
pub type EventTx = broadcast::Sender<ThreatEvent>;
