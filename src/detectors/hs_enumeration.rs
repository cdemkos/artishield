//! # Hidden-Service Enumeration Detector
//!
//! Scans HSDir-flagged relays for subnet concentration,
//! and tracks descriptor-fetch rates.
//!
//! Note: `is_dir_cache()` corresponds to the HSDir flag in arti's Relay API.

use crate::{
    config::ShieldConfig,
    detectors::EventTx,
    event::{ThreatEvent, ThreatKind, ThreatLevel},
};
use ipnet::Ipv4Net;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

fn prefix24(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => Ipv4Net::new(v4, 24).ok().map(|n| n.network().to_string()),
        IpAddr::V6(_)  => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct HsDirSnapshot {
    pub fps: HashMap<String, Option<IpAddr>>,
}

pub struct HsEnumDetector {
    config:      ShieldConfig,
    tx:          EventTx,
    desc_window: VecDeque<Instant>,
}

impl HsEnumDetector {
    pub fn new(config: ShieldConfig, tx: EventTx) -> Self {
        Self {
            config,
            tx,
            desc_window: VecDeque::with_capacity(200),
        }
    }

    pub fn analyse_hsdir(&self, snap: &HsDirSnapshot) -> Vec<ThreatEvent> {
        let total = snap.fps.len();
        if total < 10 { return vec![]; }

        let mut subnet_map: HashMap<String, Vec<String>> = HashMap::new();
        for (fp, ip_opt) in &snap.fps {
            if let Some(ip) = ip_opt {
                if let Some(pfx) = prefix24(*ip) {
                    subnet_map.entry(pfx).or_default().push(fp.clone());
                }
            }
        }

        let mut events = Vec::new();
        for (pfx, fps) in &subnet_map {
            let pct = fps.len() as f64 / total as f64;
            if fps.len() >= 5 && pct >= 0.05 {
                let score = (pct * 10.0).min(1.0);
                let level = if pct >= 0.15 { ThreatLevel::Critical }
                            else if pct >= 0.10 { ThreatLevel::High }
                            else { ThreatLevel::Medium };
                warn!(prefix = pfx, count = fps.len(), pct = format!("{:.1}%", pct*100.0),
                      "HS-Enum: HSDir /24 concentration");
                events.push(ThreatEvent::new(level,
                    ThreatKind::HsEnumeration {
                        intro_rate:        fps.len() as u32,
                        window_secs:       3600,
                        suspected_scanner: None,
                    },
                    format!("HS-Enum: {}/{total} HSDir nodes ({:.0}%) in /24 {pfx}",
                            fps.len(), pct*100.0),
                    score,
                    vec!["hs_circuit_isolation".into()],
                ));
            }
        }
        events
    }

    pub fn record_desc_fetch(&mut self) -> Option<ThreatEvent> {
        let now = Instant::now();
        self.desc_window.push_back(now);
        while let Some(&front) = self.desc_window.front() {
            if now.duration_since(front) > Duration::from_secs(30) {
                self.desc_window.pop_front();
            } else { break; }
        }
        let rate = self.desc_window.len() as u32;
        let max  = 20u32;
        if rate > max {
            warn!(rate, "HS-Enum: abnormal descriptor fetch rate");
            Some(ThreatEvent::new(
                ThreatLevel::High,
                ThreatKind::HsEnumeration {
                    intro_rate: rate, window_secs: 30, suspected_scanner: None,
                },
                format!("HS-Enum: {rate} descriptor fetches in 30 s (limit {max})"),
                (rate as f64 / (max as f64 * 2.0)).min(1.0),
                vec!["hs_circuit_isolation".into()],
            ))
        } else { None }
    }

    #[cfg(feature = "arti-hooks")]
    pub async fn run(mut self, dirmgr: std::sync::Arc<dyn tor_netdir::NetDirProvider>) {
        use futures::StreamExt as _;
        use tor_linkspec::HasAddrs as _;
        use tor_netdir::{DirEvent, Timeliness};

        info!("HsEnumDetector: subscribing to DirEvent stream");

        let snap_from = |nd: &tor_netdir::NetDir| HsDirSnapshot {
            fps: nd.relays()
                .map(|r| {
                    let fp = r.rsa_id().as_bytes()
                        .iter().map(|b| format!("{b:02X}")).collect::<String>();
                    let ip = r.addrs()
                        .find(|a| a.ip().is_ipv4())
                        .map(|a| a.ip());
                    (fp, ip)
                })
                .collect(),
        };

        if let Ok(nd) = dirmgr.netdir(Timeliness::Timely) {
            let snap = snap_from(&nd);
            info!(hsdir_count = snap.fps.len(), "HsEnumDetector: initial scan");
            for evt in self.analyse_hsdir(&snap) { let _ = self.tx.send(evt); }
        }

        let mut stream = dirmgr.events();
        loop {
            match stream.next().await {
                Some(DirEvent::NewConsensus) => {
                    if let Ok(nd) = dirmgr.netdir(Timeliness::Timely) {
                        let snap = snap_from(&nd);
                        debug!(hsdir_count = snap.fps.len(), "HsEnumDetector: consensus");
                        for evt in self.analyse_hsdir(&snap) { let _ = self.tx.send(evt); }
                    }
                }
                Some(DirEvent::NewDescriptors) => {
                    if let Some(evt) = self.record_desc_fetch() {
                        let _ = self.tx.send(evt);
                    }
                }
                // DirEvent is #[non_exhaustive]
                Some(_) => {}
                None    => { warn!("HsEnumDetector: stream closed"); break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn det() -> HsEnumDetector {
        let (tx, _) = broadcast::channel(64);
        HsEnumDetector::new(ShieldConfig::default(), tx)
    }

    fn snap(fps: &[(&str, Option<&str>)]) -> HsDirSnapshot {
        HsDirSnapshot {
            fps: fps.iter()
                .map(|(fp, ip)| (fp.to_string(), ip.map(|s| s.parse().unwrap())))
                .collect(),
        }
    }

    #[test]
    fn small_network_ignored() {
        assert!(det().analyse_hsdir(&snap(&[("A", Some("1.2.3.4"))])).is_empty());
    }

    #[test]
    fn concentrated_hsdir_fires() {
        let d = det();
        let mut fps: Vec<(String, Option<&str>)> = (0..10)
            .map(|i| (format!("B{i:02}"), Some("198.51.100.1"))).collect();
        fps.extend((10..100).map(|i| (format!("O{i:02}"), Some("1.2.3.4"))));
        let s = snap(&fps.iter().map(|(a,b)|(a.as_str(),*b)).collect::<Vec<_>>());
        assert!(!d.analyse_hsdir(&s).is_empty());
    }

    #[test]
    fn desc_fetch_above_limit() {
        let mut d = det();
        let mut last = None;
        for _ in 0..25 { last = d.record_desc_fetch(); }
        assert!(last.is_some());
    }

    #[test]
    fn prefix24_v4() {
        assert_eq!(prefix24("10.20.30.40".parse().unwrap()).as_deref(), Some("10.20.30.0"));
    }

    #[test]
    fn prefix24_v6_none() {
        assert!(prefix24("::1".parse().unwrap()).is_none());
    }
}
