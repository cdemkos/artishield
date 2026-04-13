//! Mitigation Engine — reacts to ThreatEvents on the event bus.
//!
//! Compiled in two modes:
//!
//! **With `arti-hooks`** (default): holds a real `TorClient<R>` and calls
//! `isolated_client()` to force circuit rotation when anomaly score is high.
//!
//! **Without `arti-hooks`**: updates reputation scores only.

use crate::{
    config::ShieldConfig,
    event::{ThreatEvent, ThreatKind},
    storage::ReputationStore,
};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════════
// WITHOUT arti-hooks  —  reputation-only engine
// ═══════════════════════════════════════════════════════════════════

/// Reacts to `ThreatEvent`s by updating relay reputation scores (no-arti-hooks mode).
#[cfg(not(feature = "arti-hooks"))]
pub struct MitigationEngine {
    #[allow(dead_code)]
    config: ShieldConfig,
    rx:     broadcast::Receiver<ThreatEvent>,
    store:  Arc<ReputationStore>,
}

#[cfg(not(feature = "arti-hooks"))]
impl MitigationEngine {
    /// Create a new `MitigationEngine` subscribed to `rx`.
    pub fn new(
        config: ShieldConfig,
        rx:     broadcast::Receiver<ThreatEvent>,
        store:  Arc<ReputationStore>,
    ) -> Self {
        Self { config, rx, store }
    }

    /// Start the mitigation loop; runs until the event bus is closed.
    pub async fn run(mut self) {
        info!("MitigationEngine started (no-arti-hooks mode)");
        loop {
            match self.rx.recv().await {
                Ok(evt)  => self.update_reputation(&evt),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(n, "MitigationEngine lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }

    fn update_reputation(&self, evt: &ThreatEvent) {
        match &evt.kind {
            ThreatKind::SybilCluster { affected_fps, shared_asn, .. } => {
                for fp in affected_fps {
                    if let Err(e) = self.store.update_relay(fp, evt.anomaly_score, *shared_asn, None) {
                        warn!(fp, "Failed to update relay reputation: {e}");
                    }
                    if let Err(e) = self.store.add_flag(fp, "sybil") {
                        warn!(fp, "Failed to add sybil flag: {e}");
                    }
                }
            }
            ThreatKind::GuardDiscovery { suspicious_fingerprints, .. } => {
                for fp in suspicious_fingerprints {
                    if let Err(e) = self.store.update_relay(fp, evt.anomaly_score * 0.5, None, None) {
                        warn!(fp, "Failed to update relay reputation: {e}");
                    }
                    if let Err(e) = self.store.add_flag(fp, "guard_discovery") {
                        warn!(fp, "Failed to add guard_discovery flag: {e}");
                    }
                }
            }
            _ => {}
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// WITH arti-hooks  —  full TorClient integration
// ═══════════════════════════════════════════════════════════════════

// All arti/tor-* types are confined to this cfg block.
// The `use` statements are at the *top of the impl* (inside the cfg block),
// which is valid Rust — a `use` at the start of a block is scoped to that block.
#[cfg(feature = "arti-hooks")]
mod arti_engine {
    use super::*;
    use arti_client::TorClient;
    use tor_rtcompat::Runtime;

    /// Mitigation engine with full arti/Tor-client integration.
    pub struct MitigationEngine<R: Runtime> {
        config:     ShieldConfig,
        rx:         broadcast::Receiver<ThreatEvent>,
        store:      Arc<ReputationStore>,
        tor_client: TorClient<R>,
    }

    impl<R: Runtime> MitigationEngine<R> {
        /// Create a new `MitigationEngine` subscribed to `rx`, holding `tor_client` for circuit rotation.
        pub fn new(
            config:     ShieldConfig,
            rx:         broadcast::Receiver<ThreatEvent>,
            store:      Arc<ReputationStore>,
            tor_client: TorClient<R>,
        ) -> Self {
            Self { config, rx, store, tor_client }
        }

        /// Start the mitigation loop; runs until the event bus is closed.
        pub async fn run(mut self) {
            info!("MitigationEngine started (arti-hooks mode)");
            loop {
                match self.rx.recv().await {
                    Ok(evt)  => self.handle(evt).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(n, "MitigationEngine lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }

        async fn handle(&mut self, evt: ThreatEvent) {
            let cfg = &self.config.mitigations;

            // ── Circuit rotation ──────────────────────────────────────────────
            // TorClient::isolated_client() is the stable public API.
            // It returns a new TorClient with a fresh IsolationToken — arti
            // will never share circuits between the original and the clone.
            if cfg.auto_circuit_rotate
                && evt.anomaly_score >= self.config.detectors.alert_threshold
            {
                info!("Mitigation: circuit rotation via isolated_client()");
                self.tor_client = self.tor_client.isolated_client();
            }

            // ── Guard-pin alert ───────────────────────────────────────────────
            // arti's guard manager already pins guards for weeks by default.
            // We log an alert; pinning a specific fingerprint via reconfigure()
            // would require writing a new TorClientConfig with [guard] settings.
            if cfg.guard_pin {
                if matches!(evt.kind,
                    ThreatKind::SybilCluster { .. }
                    | ThreatKind::GuardDiscovery { .. })
                {
                    warn!(
                        score = evt.anomaly_score,
                        "Mitigation: guard-pin alert — verify guard fp in arti logs"
                    );
                }
            }

            // ── Reputation updates ────────────────────────────────────────────
            match &evt.kind {
                ThreatKind::SybilCluster { affected_fps, shared_asn, .. } => {
                    for fp in affected_fps {
                        if let Err(e) = self.store.update_relay(fp, evt.anomaly_score, *shared_asn, None) {
                            warn!(fp, "Failed to update relay reputation: {e}");
                        }
                        if let Err(e) = self.store.add_flag(fp, "sybil") {
                            warn!(fp, "Failed to add sybil flag: {e}");
                        }
                    }
                }
                ThreatKind::GuardDiscovery { suspicious_fingerprints, .. } => {
                    for fp in suspicious_fingerprints {
                        if let Err(e) = self.store.update_relay(fp, evt.anomaly_score * 0.5, None, None) {
                            warn!(fp, "Failed to update relay reputation: {e}");
                        }
                        if let Err(e) = self.store.add_flag(fp, "guard_discovery") {
                            warn!(fp, "Failed to add guard_discovery flag: {e}");
                        }
                    }
                }
                _ => {}
            }
        }

        /// Expose the (possibly rotated) client handle.
        pub fn tor_client(&self) -> &TorClient<R> {
            &self.tor_client
        }
    }
}

// Re-export so `crate::mitigations::MitigationEngine` works in both modes.
#[cfg(feature = "arti-hooks")]
pub use arti_engine::MitigationEngine;
