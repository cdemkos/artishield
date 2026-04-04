//! ArtiShield orchestrator.
//!
//! API starts immediately. arti bootstrapping runs in a background task
//! so the dashboard is reachable from the first second.
pub mod api;
pub mod metrics;

use crate::{
    config::ShieldConfig,
    detectors::{
        dos::DosDetector,
        timing::TimingDetector,
        EventTx,
    },
    event::{MetricsSnapshot, ThreatEvent, ThreatKind},
    storage::ReputationStore,
};
#[cfg(feature = "arti-hooks")]
use crate::detectors::{
    guard_discovery::GuardDiscoveryDetector,
    hs_enumeration::HsEnumDetector,
    sybil::SybilDetector,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;
#[cfg(feature = "arti-hooks")]
use tracing::warn;

// ── Shared state ──────────────────────────────────────────────────────────────

/// State shared between the monitor tasks and the HTTP API.
#[derive(Default)]
pub struct SharedState {
    pub recent_events: Vec<ThreatEvent>,
    pub metrics:       MetricsSnapshot,
    pub anomaly_score: f64,
    /// Human-readable arti connection status shown in the dashboard.
    /// Values: "booting" | "connecting" | "online" | "no-arti" | "error: …"
    pub arti_status:   String,
}

// ── Main struct ───────────────────────────────────────────────────────────────

pub struct ArtiShield {
    pub config: ShieldConfig,
}

impl ArtiShield {
    pub fn new(config: ShieldConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn run(self) -> Result<()> {
        // ── Storage ───────────────────────────────────────────────────────────
        let store = Arc::new(ReputationStore::open(&self.config.db_path)?);
        info!(blocked = store.blocked_ip_count(), "ReputationStore loaded");

        // ── Event bus ─────────────────────────────────────────────────────────
        let (tx, _): (EventTx, _) = broadcast::channel(256);

        // ── Shared API state ──────────────────────────────────────────────────
        let shared = Arc::new(RwLock::new(SharedState {
            arti_status: "booting".into(),
            ..Default::default()
        }));

        // ── SOCKS-based detectors — start immediately, no arti crate needed ──
        tokio::spawn(
            TimingDetector::new(self.config.clone(), tx.clone(), self.config.socks_addr).run(),
        );
        tokio::spawn(
            DosDetector::new(self.config.clone(), tx.clone(), self.config.socks_addr).run(),
        );

        // ── arti-hooks block — runs in background ─────────────────────────────
        #[cfg(feature = "arti-hooks")]
        {
            let config2 = self.config.clone();
            let tx2     = tx.clone();
            let store2  = store.clone();
            let shared2 = shared.clone();

            tokio::spawn(async move {
                use arti_client::{TorClient, TorClientConfig};
                use crate::mitigations::MitigationEngine;
                use tor_rtcompat::PreferredRuntime;

                {
                    let mut s = shared2.write().await;
                    s.arti_status = "connecting".into();
                }
                info!("ArtiShield: bootstrapping arti in background…");

                match TorClient::<PreferredRuntime>::create_bootstrapped(
                    TorClientConfig::default(),
                )
                .await
                {
                    Ok(tor_client) => {
                        info!("ArtiShield: arti online");
                        shared2.write().await.arti_status = "online".into();

                        let dirmgr = tor_client.dirmgr().clone();

                        tokio::spawn(
                            SybilDetector::new(config2.clone(), tx2.clone())
                                .run(dirmgr.clone()),
                        );
                        tokio::spawn(
                            GuardDiscoveryDetector::new(config2.clone(), tx2.clone())
                                .run(dirmgr.clone()),
                        );
                        tokio::spawn(
                            HsEnumDetector::new(config2.clone(), tx2.clone())
                                .run(dirmgr.clone()),
                        );
                        tokio::spawn(
                            MitigationEngine::new(
                                config2,
                                tx2.subscribe(),
                                store2,
                                tor_client,
                            )
                            .run(),
                        );
                    }
                    Err(e) => {
                        warn!("arti bootstrap failed: {e}");
                        warn!("Running without arti — SOCKS-based detectors still active");
                        shared2.write().await.arti_status = format!("error: {e}");
                    }
                }
            });
        }

        // ── No-arti-hooks mitigation engine ───────────────────────────────────
        #[cfg(not(feature = "arti-hooks"))]
        {
            use crate::mitigations::MitigationEngine;
            tokio::spawn(
                MitigationEngine::new(self.config.clone(), tx.subscribe(), store.clone()).run(),
            );
            shared.write().await.arti_status = "no-arti".into();
        }

        // ── Storage + state writer ────────────────────────────────────────────
        {
            let store3  = store.clone();
            let shared3 = shared.clone();
            let mut rx  = tx.subscribe();

            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(evt) => {
                            if let Err(e) = store3.store_event(&evt) {
                                tracing::warn!("Failed to persist event: {e}");
                            }
                            update_reputation(&store3, &evt);

                            let mut s = shared3.write().await;
                            s.anomaly_score = s.anomaly_score * 0.95 + evt.anomaly_score * 0.05;
                            s.recent_events.insert(0, evt);
                            s.recent_events.truncate(200);

                            let now    = chrono::Utc::now();
                            let ev_1m = s.recent_events.iter().filter(|e| {
                                now.signed_duration_since(e.timestamp).num_seconds() < 60
                            }).count() as u32;

                            s.metrics = MetricsSnapshot {
                                timestamp:          Some(now),
                                active_circuits:    0,
                                anomaly_score:      s.anomaly_score,
                                blocked_ips:        store3.blocked_ip_count() as u32,
                                bandwidth_kbps:     0.0,
                                events_last_minute: ev_1m,
                                guard_fingerprint:  None,
                                threat_level:       s.recent_events.first().map(|e| e.level),
                            };
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(n, "state writer lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        // ── Block-expiry pruner (every 5 min) ─────────────────────────────────
        {
            let s = store.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    t.tick().await;
                    if let Ok(n) = s.prune_expired_blocks() {
                        if n > 0 { info!(n, "pruned expired IP blocks"); }
                    }
                }
            });
        }

        // ── HTTP + WebSocket + Prometheus API ─────────────────────────────────
        // This is the last thing we do — it blocks until the process exits.
        let addr = self.config.api_addr;
        info!(%addr, "Dashboard listening — http://{addr}/");
        api::serve(api::ApiState { shared, store, event_tx: tx }, addr).await?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn update_reputation(store: &ReputationStore, evt: &ThreatEvent) {
    match &evt.kind {
        ThreatKind::SybilCluster { affected_fps, shared_asn, .. } => {
            for fp in affected_fps {
                if let Err(e) = store.update_relay(fp, evt.anomaly_score, *shared_asn, None) {
                    tracing::warn!(fp, "Failed to update relay reputation: {e}");
                }
                if let Err(e) = store.add_flag(fp, "sybil") {
                    tracing::warn!(fp, "Failed to add sybil flag: {e}");
                }
            }
        }
        ThreatKind::GuardDiscovery { suspicious_fingerprints, .. } => {
            for fp in suspicious_fingerprints {
                if let Err(e) = store.update_relay(fp, evt.anomaly_score * 0.5, None, None) {
                    tracing::warn!(fp, "Failed to update relay reputation: {e}");
                }
                if let Err(e) = store.add_flag(fp, "guard_discovery") {
                    tracing::warn!(fp, "Failed to add guard_discovery flag: {e}");
                }
            }
        }
        _ => {}
    }
}
