//! # DoS Detector
//!
//! Monitors two attack classes via SOCKS5 probes through arti:
//!
//! ## 1. Circuit-stuffing
//! When p95 connect latency exceeds `BASELINE_MULTIPLIER × baseline`.
//!
//! ## 2. SENDME-burst (bursty delivery)
//! High coefficient of variation in TTFB samples.

use crate::{
    config::ShieldConfig,
    detectors::EventTx,
    event::{ThreatEvent, ThreatKind, ThreatLevel},
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// p95 connect latency must exceed `BASELINE_MULTIPLIER × baseline` to trigger an alert.
pub const BASELINE_MULTIPLIER: f64 = 3.0;
/// Minimum number of probe samples before establishing a baseline or emitting alerts.
pub const MIN_SAMPLES:         usize = 10;

const LAT_WINDOW:     usize    = 30;
const PROBE_HOST:     &str     = "example.com:80";
const PROBE_REQ:      &[u8]    = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
const PROBE_TIMEOUT:  Duration = Duration::from_secs(25);
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct LatSample {
    connect_ms: f64,
    ttfb_ms:    f64,
}

// ── Detector ─────────────────────────────────────────────────────────────────

/// Detects circuit-stuffing and SENDME-burst DoS attacks via SOCKS5 latency probes.
pub struct DosDetector {
    #[allow(dead_code)]
    config:     ShieldConfig,
    tx:         EventTx,
    socks_addr: SocketAddr,
    samples:    VecDeque<LatSample>,
    baseline:   Option<f64>,
}

impl DosDetector {
    /// Create a new `DosDetector` that probes through the SOCKS5 proxy at `socks_addr`.
    pub fn new(config: ShieldConfig, tx: EventTx, socks_addr: SocketAddr) -> Self {
        Self {
            config,
            tx,
            socks_addr,
            samples:  VecDeque::with_capacity(LAT_WINDOW + 1),
            baseline: None,
        }
    }

    // ── Probe ─────────────────────────────────────────────────────────────────

    async fn probe(&self) -> Option<LatSample> {
        let t0 = Instant::now();
        let result = time::timeout(PROBE_TIMEOUT, async {
            let mut s = Socks5Stream::connect(self.socks_addr, PROBE_HOST)
                .await
                .map_err(|e| debug!("DoS probe SOCKS: {e}"))?;
            let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
            s.write_all(PROBE_REQ).await.map_err(|_| ())?;
            s.flush().await.ok();
            let mut buf = [0u8; 1];
            s.read_exact(&mut buf).await.map_err(|_| ())?;
            let ttfb_ms = t0.elapsed().as_secs_f64() * 1000.0;
            Ok::<_, ()>(LatSample { connect_ms, ttfb_ms })
        })
        .await;
        match result {
            Ok(Ok(s)) => Some(s),
            _ => None,
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    fn median(vals: &mut Vec<f64>) -> f64 {
        vals.retain(|v| v.is_finite());
        if vals.is_empty() { return 0.0; }
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        vals[vals.len() / 2]
    }

    fn p95(vals: &mut Vec<f64>) -> f64 {
        vals.retain(|v| v.is_finite());
        if vals.is_empty() { return 0.0; }
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((vals.len() as f64 * 0.95) as usize).min(vals.len() - 1);
        vals[idx]
    }

    fn cov(xs: &[f64]) -> f64 {
        let n = xs.len() as f64;
        if n < 2.0 { return 0.0; }
        let mean = xs.iter().sum::<f64>() / n;
        if mean < 1e-9 { return 0.0; }
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        var.sqrt() / mean
    }

    // ── Analysis ─────────────────────────────────────────────────────────────

    fn analyse(&mut self) -> Vec<ThreatEvent> {
        let n = self.samples.len();
        if n < MIN_SAMPLES { return vec![]; }

        let mut connect_vals: Vec<f64> = self.samples.iter().map(|s| s.connect_ms).collect();
        let median_ms = Self::median(&mut connect_vals.clone());

        // Establish baseline from first MIN_SAMPLES, then keep it stable
        if self.baseline.is_none() {
            self.baseline = Some(median_ms);
            info!(baseline_ms = format!("{median_ms:.0}"), "DoS: baseline established");
            return vec![];
        }

        let baseline = self.baseline.unwrap();
        let mut events = Vec::new();

        // ── Circuit-stuffing: p95 > BASELINE_MULTIPLIER × baseline ───────────
        let p95_ms = Self::p95(&mut connect_vals);
        let ratio  = p95_ms / baseline.max(1.0);

        if ratio >= BASELINE_MULTIPLIER {
            let score = ((ratio - BASELINE_MULTIPLIER) / BASELINE_MULTIPLIER).min(1.0);
            let level = if ratio >= 6.0 { ThreatLevel::Critical }
                        else if ratio >= 4.0 { ThreatLevel::High }
                        else { ThreatLevel::Medium };
            warn!(
                p95_ms    = format!("{p95_ms:.0}"),
                baseline  = format!("{baseline:.0}"),
                ratio     = format!("{ratio:.1}x"),
                "DoS: circuit-build latency spike"
            );
            events.push(ThreatEvent::new(
                level,
                ThreatKind::DenialOfService {
                    sendme_rate:  0,
                    queue_depth:  n,
                    source_relay: None,
                },
                format!(
                    "DoS: p95={p95_ms:.0}ms ({ratio:.1}× baseline={baseline:.0}ms) \
                     — circuit stuffing suspected"
                ),
                score,
                vec!["auto_circuit_rotate".into()],
            ));
        }

        // ── SENDME-burst: high TTFB coefficient of variation ─────────────────
        let ttfbs: Vec<f64> = self.samples.iter().map(|s| s.ttfb_ms).collect();
        let cov_val = Self::cov(&ttfbs);
        if cov_val > 1.5 {
            debug!(cov = format!("{cov_val:.2}"), "DoS: high TTFB CoV — possible SENDME burst");
            events.push(ThreatEvent::new(
                ThreatLevel::Low,
                ThreatKind::DenialOfService {
                    sendme_rate:  0,
                    queue_depth:  0,
                    source_relay: None,
                },
                format!("DoS: TTFB CoV={cov_val:.2} — bursty delivery"),
                (cov_val / 3.0).min(0.5),
                vec![],
            ));
        }

        events
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    /// Start the DoS detector loop; runs indefinitely, emitting events onto `tx`.
    pub async fn run(mut self) {
        info!(socks = %self.socks_addr, "DosDetector started");
        let mut ticker = time::interval(PROBE_INTERVAL);

        loop {
            ticker.tick().await;
            if let Some(sample) = self.probe().await {
                debug!(
                    connect_ms = format!("{:.0}", sample.connect_ms),
                    ttfb_ms    = format!("{:.0}", sample.ttfb_ms),
                    "DoS probe ok"
                );
                if self.samples.len() >= LAT_WINDOW {
                    self.samples.pop_front();
                }
                self.samples.push_back(sample);
                for evt in self.analyse() {
                    let _ = self.tx.send(evt);
                }
            } else {
                debug!("DoS probe failed (Tor may be bootstrapping)");
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn det() -> DosDetector {
        let (tx, _) = broadcast::channel(64);
        DosDetector::new(ShieldConfig::default(), tx, "127.0.0.1:9150".parse().unwrap())
    }

    fn push(d: &mut DosDetector, ms: &[f64]) {
        for &m in ms {
            d.samples.push_back(LatSample { connect_ms: m, ttfb_ms: m * 1.5 });
        }
    }

    #[test]
    fn no_alert_stable() {
        let mut d = det();
        push(&mut d, &[100.0; 15]);
        d.baseline = Some(100.0);
        assert!(d.analyse().is_empty());
    }

    #[test]
    fn alert_on_spike() {
        let mut d = det();
        push(&mut d, &[100.0; 10]);
        d.baseline = Some(100.0);
        push(&mut d, &[500.0; 20]);
        let evts = d.analyse();
        assert!(!evts.is_empty());
        assert!(matches!(evts[0].kind, ThreatKind::DenialOfService { .. }));
    }

    #[test]
    fn baseline_set_after_min_samples() {
        let mut d = det();
        push(&mut d, &[100.0; MIN_SAMPLES]);
        // First analyse call sets baseline and returns empty
        assert!(d.analyse().is_empty());
        assert!(d.baseline.is_some());
    }

    #[test]
    fn no_alert_below_min_samples() {
        let mut d = det();
        push(&mut d, &[100.0; MIN_SAMPLES - 1]);
        assert!(d.analyse().is_empty());
        assert!(d.baseline.is_none());
    }

    #[test]
    fn cov_stable_low() {
        let xs = vec![100.0f64; 10];
        assert!(DosDetector::cov(&xs) < 0.01);
    }

    #[test]
    fn cov_variable_high() {
        let xs = vec![10.0, 500.0, 20.0, 800.0, 5.0, 300.0, 50.0, 600.0, 15.0, 400.0];
        assert!(DosDetector::cov(&xs) > 1.0);
    }
}
