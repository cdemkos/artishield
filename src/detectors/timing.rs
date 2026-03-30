//! # Timing Correlation Detector
//!
//! Probes through arti's SOCKS5 port using `tokio-socks`.
//! No arti crate dependency needed — pure external SOCKS5 protocol.

use crate::{
    config::ShieldConfig,
    detectors::EventTx,
    event::{ThreatEvent, ThreatKind, ThreatLevel},
};
use std::{collections::VecDeque, net::SocketAddr, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time};
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info, warn};

const PROBE_HOST:    &str  = "example.com:80";
const PROBE_REQ:     &[u8] = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const WINDOW:        usize = 60;

#[derive(Clone, Copy)]
struct Sample { rtt_ms: f64, burst: f64 }

fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 { return 0.0; }
    let mx = xs.iter().sum::<f64>() / n as f64;
    let my = ys.iter().sum::<f64>() / n as f64;
    let num: f64 = xs.iter().zip(ys).map(|(x, y)| (x-mx)*(y-my)).sum();
    let dx: f64  = xs.iter().map(|x| (x-mx).powi(2)).sum::<f64>().sqrt();
    let dy: f64  = ys.iter().map(|y| (y-my).powi(2)).sum::<f64>().sqrt();
    if dx < 1e-9 || dy < 1e-9 { return 0.0; }
    (num / (dx * dy)).clamp(-1.0, 1.0)
}

fn deanon_prob(r_abs: f64) -> f64 {
    1.0 / (1.0 + (-12.0 * (r_abs - 0.5)).exp())
}

pub struct TimingDetector {
    config:     ShieldConfig,
    tx:         EventTx,
    socks_addr: SocketAddr,
    window:     VecDeque<Sample>,
}

impl TimingDetector {
    pub fn new(config: ShieldConfig, tx: EventTx, socks_addr: SocketAddr) -> Self {
        Self { config, tx, socks_addr, window: VecDeque::with_capacity(WINDOW + 1) }
    }

    async fn probe(&self, burst: f64) -> Option<Sample> {
        let start = Instant::now();
        let result = time::timeout(PROBE_TIMEOUT, async {
            let mut s = Socks5Stream::connect(self.socks_addr, PROBE_HOST)
                .await.map_err(|e| debug!("SOCKS: {e}"))?;
            s.write_all(PROBE_REQ).await.map_err(|_| ())?;
            s.flush().await.ok();
            let mut buf = [0u8; 1];
            s.read_exact(&mut buf).await.map_err(|_| ())?;
            Ok::<_, ()>(())
        }).await;
        match result {
            Ok(Ok(())) => Some(Sample { rtt_ms: start.elapsed().as_secs_f64()*1000.0, burst }),
            _ => None,
        }
    }

    fn analyse(&self) -> Option<ThreatEvent> {
        let min = (self.config.detectors.timing_window_secs * 2).min(WINDOW as u64/2) as usize;
        if self.window.len() < min { return None; }

        let rtts:   Vec<f64> = self.window.iter().map(|s| s.rtt_ms).collect();
        let bursts: Vec<f64> = self.window.iter().map(|s| s.burst).collect();
        let r     = pearson(&rtts, &bursts);
        let prob  = deanon_prob(r.abs());
        let thresh = self.config.detectors.timing_correlation_threshold;

        if r.abs() >= thresh {
            let level = if prob >= 0.85 { ThreatLevel::Critical }
                        else if prob >= 0.65 { ThreatLevel::High }
                        else { ThreatLevel::Medium };
            warn!(pearson_r = format!("{r:.3}"), deanon_p = format!("{prob:.2}"),
                  "Timing correlation detected");
            Some(ThreatEvent::new(
                level,
                ThreatKind::TimingCorrelation {
                    pearson_r: r, sample_count: self.window.len(), deanon_probability: prob,
                },
                format!("Timing: r={r:.3} over {} probes — de-anon p={:.0}%",
                        self.window.len(), prob*100.0),
                prob,
                vec!["auto_circuit_rotate".into()],
            ))
        } else {
            debug!(pearson_r = format!("{r:.3}"), "Timing: within normal range");
            None
        }
    }

    fn burst_signal(tick: u64, period: u64) -> f64 {
        if tick % period < period / 4 { 1.0 } else { 0.0 }
    }

    pub async fn run(mut self) {
        info!(socks = %self.socks_addr, "TimingDetector: probing via arti SOCKS5");
        let mut ticker = time::interval(Duration::from_secs(5));
        let burst_period: u64 = 12;
        let mut tick: u64 = 0;

        loop {
            ticker.tick().await;
            tick += 1;
            let burst = Self::burst_signal(tick, burst_period);
            if let Some(sample) = self.probe(burst).await {
                debug!(rtt_ms = sample.rtt_ms, burst, "Probe ok");
                if self.window.len() >= WINDOW { self.window.pop_front(); }
                self.window.push_back(sample);
            }
            if tick % 10 == 0 {
                if let Some(evt) = self.analyse() { let _ = self.tx.send(evt); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pearson_perfect() {
        let xs: Vec<f64> = (0..20).map(|i| i as f64).collect();
        assert!((pearson(&xs, &xs) - 1.0).abs() < 1e-9);
    }
    #[test]
    fn deanon_midpoint() {
        assert!((deanon_prob(0.5) - 0.5).abs() < 0.01);
    }
    #[test]
    fn burst_shape() {
        assert_eq!(TimingDetector::burst_signal(0, 12), 1.0);
        assert_eq!(TimingDetector::burst_signal(3, 12), 0.0);
    }
}
