//! # DoS Detector
//!
//! Monitors two attack classes:
//!
//! ## 1. Circuit-stuffing (client-observable)
//!
//! An adversary floods the network with circuits to exhaust relay resources.
//! We observe this *indirectly*: if our own connection attempts via arti's
//! SOCKS port start timing out much faster than usual, the local arti process
//! is under resource pressure.
//!
//! Hook: we track SOCKS connect latency over a sliding window and alert when
//! the 95th-percentile RTT spikes beyond a configurable multiplier of baseline.
//!
//! ## 2. SENDME-flood (protocol-level)
//!
//! An exit relay sends unsolicited SENDME cells to inflate flow-control windows.
//! This is not directly observable from outside arti's circuit reactor.
//!
//! What we *can* observe: if our probe connections through arti are receiving
//! data in abnormally large bursts (very low latency to first byte followed by
//! stalls), that pattern is consistent with a SENDME-inflated window.
//!
//! We detect this via inter-arrival time (IAT) coefficient of variation: a
//! high CoV in byte arrival times indicates bursty delivery.

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

/// Number of recent connection latency samples to keep.
const LAT_WINDOW: usize = 30;
/// A connection taking longer than BASELINE_MULTIPLIER × median is a signal.
pub const BASELINE_MULTIPLIER: f64 = 3.0;
/// Minimum samples before we compute a baseline.
const MIN_SAMPLES: usize = 10;
/// Probe destination (low-latency HTTP endpoint reachable via Tor).
const PROBE_HOST: &str = "example.com:80";
const PROBE_REQ:  &[u8] = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct LatSample {
    connect_ms: f64,   // time to SOCKS CONNECT completion
    ttfb_ms:    f64,   // time-to-first-byte of HTTP response
    #[allow(dead_code)]
    recv_ms:    f64,   // time to receive 512 bytes (burst indicator)
}

// ── Detector ─────────────────────────────────────────────────────────────────

pub struct DosDetector {
    config:     ShieldConfig,
    tx:         EventTx,
    socks_addr: SocketAddr,
    samples:    VecDeque<LatSample>,
    /// Baseline median connect_ms (set once MIN_SAMPLES collected).
    baseline:   Option<f64>,
}

impl DosDetector {
    pub fn new(config: ShieldConfig, tx: EventTx, socks_addr: SocketAddr) -> Self {
        Self {
            config,
            tx,
            socks_addr,
            samples:  VecDeque::with_capacity(LAT_WINDOW + 1),
            baseline: None,
        }
    }

    // ── Single probe ─────────────────────────────────────────────────────────

    async fn probe(&self) -> Option<LatSample> {
        let t0 = Instant::now();

        let result = time::timeout(PROBE_TIMEOUT, async {
            // SOCKS5 connect — measures circuit-build overhead
            let mut stream = Socks5Stream::connect(self.socks_addr, PROBE_HOST)
                .await
                .map_err(|e| debug!("DoS probe SOCKS error: {e}"))?;

            let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // Send HTTP request
            stream.write_all(PROBE_REQ).await.map_err(|_| ())?;
            stream.flush().await.ok();

            // Measure TTFB
            let mut buf = [0u8; 1];
            stream.read_exact(&mut buf).await.map_err(|_| ())?;
            let ttfb_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // Read next 512 bytes to detect burst behaviour
            let mut big_buf = [0u8; 512];
            let _ = stream.read(&mut big_buf).await;
            let recv_ms = t0.elapsed().as_secs_f64() * 1000.0;

            Ok::<_, ()>(LatSample { connect_ms, ttfb_ms, recv_ms })
        })
        .await;

        match result {
            Ok(Ok(s)) => Some(s),
            _ => None,
        }
    }

    // ── Baseline ─────────────────────────────────────────────────────────────

    fn median_connect_ms(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(|s| s.connect_ms).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }

    fn p95_connect_ms(&self) -> f64 {
        let mut v: Vec<f64> = self.samples.iter().map(|s| s.connect_ms).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[(v.len() as f64 * 0.95) as usize]
    }

    // ── Analysis ─────────────────────────────────────────────────────────────

    fn analyse(&mut self) -> Vec<ThreatEvent> {
        let n = self.samples.len();
        if n < MIN_SAMPLES { return vec![]; }

        let mut events = Vec::new();
        let median = self.median_connect_ms();

        // Establish or update baseline from first MIN_SAMPLES readings
        if self.baseline.is_none() && n >= MIN_SAMPLES {
            self.baseline = Some(median);
            info!(baseline_ms = format!("{median:.0}"), "DoS: baseline established");
            return vec![];
        }

        let baseline = match self.baseline {
            Some(b) => b,
            None    => return vec![],
        };

        // ── Circuit-stuffing detection ───────────────────────────────────────
        // Recent p95 latency > BASELINE_MULTIPLIER × baseline
        let p95 = self.p95_connect_ms();
        let ratio = p95 / baseline.max(1.0);

        if ratio >= BASELINE_MULTIPLIER {
            let score = ((ratio - BASELINE_MULTIPLIER) / BASELINE_MULTIPLIER).min(1.0);
            let level = if ratio >= 6.0 { ThreatLevel::Critical }
                        else if ratio >= 4.0 { ThreatLevel::High }
                        else { ThreatLevel::Medium };

            warn!(
                p95_ms = format!("{p95:.0}"),
                baseline_ms = format!("{baseline:.0}"),
                ratio = format!("{ratio:.1}x"),
                "DoS: circuit-build latency spike — possible circuit stuffing"
            );

            events.push(ThreatEvent::new(
                level,
                ThreatKind::DenialOfService {
                    sendme_rate:  0,
                    queue_depth:  n,
                    source_relay: None,
                },
                format!(
                    "DoS: p95 connect={p95:.0}ms ({ratio:.1}× baseline={baseline:.0}ms) \
                     — circuit stuffing suspected",
                ),
                score,
                vec!["auto_circuit_rotate".into()],
            ));
        }

        // ── SENDME-burst detection ───────────────────────────────────────────
        // Coefficient of variation of TTFB: high CoV = bursty delivery
        let ttfbs: Vec<f64> = self.samples.iter().map(|s| s.ttfb_ms).collect();
        let mean_ttfb = ttfbs.iter().sum::<f64>() / ttfbs.len() as f64;
        if mean_ttfb > 0.0 {
            let variance = ttfbs.iter().map(|x| (x - mean_ttfb).powi(2)).sum::<f64>()
                / ttfbs.len() as f64;
            let cov = variance.sqrt() / mean_ttfb;

            if cov > 1.5 {
                debug!(cov = format!("{cov:.2}"), "DoS: high TTFB CoV — possible SENDME burst");
                events.push(ThreatEvent::new(
                    ThreatLevel::Low,
                    ThreatKind::DenialOfService {
                        sendme_rate:  0,
                        queue_depth:  0,
                        source_relay: None,
                    },
                    format!(
                        "DoS: TTFB CoV={cov:.2} (>1.5) — bursty delivery, \
                         possible SENDME window manipulation",
                    ),
                    (cov / 3.0).min(0.5),
                    vec![],
                ));
            }
        }

        events
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    pub async fn run(mut self) {
        info!(socks = %self.socks_addr, "DosDetector: probing via arti SOCKS5");
        let mut ticker = time::interval(PROBE_INTERVAL);

        loop {
            ticker.tick().await;

            if let Some(sample) = self.probe().await {
                debug!(
                    connect_ms = format!("{:.0}", sample.connect_ms),
                    ttfb_ms    = format!("{:.0}", sample.ttfb_ms),
                    "DoS probe"
                );
                if self.samples.len() >= LAT_WINDOW {
                    self.samples.pop_front();
                }
                self.samples.push_back(sample);

                for evt in self.analyse() {
                    let _ = self.tx.send(evt);
                }
            } else {
                debug!("DoS probe failed (Tor may be busy — normal)");
            }
        }
    }
}

// ── Stats helpers ─────────────────────────────────────────────────────────────

/// Coefficient of variation of a slice (std / mean).
#[allow(dead_code)]
fn cov(xs: &[f64]) -> f64 {
    let n = xs.len() as f64;
    if n < 2.0 { return 0.0; }
    let mean = xs.iter().sum::<f64>() / n;
    if mean < 1e-9 { return 0.0; }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    var.sqrt() / mean
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn det() -> DosDetector {
        let (tx, _) = broadcast::channel(64);
        DosDetector::new(
            ShieldConfig::default(),
            tx,
            "127.0.0.1:9150".parse().unwrap(),
        )
    }

    fn push_samples(d: &mut DosDetector, ms: &[f64]) {
        for &m in ms {
            d.samples.push_back(LatSample {
                connect_ms: m,
                ttfb_ms:    m * 1.5,
                recv_ms:    m * 2.0,
            });
        }
    }

    #[test]
    fn no_alert_below_threshold() {
        let mut d = det();
        // Stable 100ms connect times
        push_samples(&mut d, &[100.0; 15]);
        d.baseline = Some(100.0);
        let evts = d.analyse();
        assert!(evts.is_empty(), "Stable latency should produce no events");
    }

    #[test]
    fn alert_on_latency_spike() {
        let mut d = det();
        // Baseline at 100ms
        push_samples(&mut d, &[100.0; 10]);
        d.baseline = Some(100.0);
        // Then spike to 500ms (5× baseline > 3× threshold)
        push_samples(&mut d, &[500.0; 20]);
        let evts = d.analyse();
        assert!(!evts.is_empty(), "5× latency spike should trigger alert");
        assert!(matches!(evts[0].kind, ThreatKind::DenialOfService { .. }));
    }

    #[test]
    fn cov_computation() {
        let stable   = vec![100.0f64; 10];
        let variable = vec![10.0, 500.0, 20.0, 800.0, 5.0, 300.0, 50.0, 600.0, 15.0, 400.0];
        assert!(cov(&stable)   < 0.01, "Stable series should have low CoV");
        assert!(cov(&variable) > 1.0,  "Variable series should have high CoV");
    }

    #[test]
    fn no_baseline_no_alert() {
        let mut d = det();
        // 5 samples — below MIN_SAMPLES (10)
        push_samples(&mut d, &[100.0; 5]);
        assert!(d.analyse().is_empty());
    }

    #[test]
    fn median_correct() {
        let mut d = det();
        push_samples(&mut d, &[10.0, 20.0, 30.0, 40.0, 50.0]);
        assert_eq!(d.median_connect_ms(), 30.0);
    }
}
