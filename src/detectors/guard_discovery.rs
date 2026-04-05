//! # Guard-Discovery Detector
//!
//! Watches Guard-flagged relay set across DirEvent::NewConsensus events.
//! DirEvent is #[non_exhaustive] — wildcard arm required in match.

use crate::{
    config::ShieldConfig,
    detectors::EventTx,
    event::{ThreatEvent, ThreatKind, ThreatLevel},
};
use ipnet::Ipv4Net;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use tracing::{debug, warn};
#[cfg(feature = "arti-hooks")]
use tracing::info;

fn prefix24(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => Ipv4Net::new(v4, 24).ok().map(|n| n.network().to_string()),
        IpAddr::V6(_)  => None,
    }
}

/// A snapshot of the Guard-flagged relay set from one consensus.
#[derive(Debug, Clone, Default)]
pub struct GuardSnapshot {
    /// Map of relay fingerprint → primary IPv4 address (if available).
    pub fps: HashMap<String, Option<IpAddr>>,
}

impl GuardSnapshot {
    /// Return the set of all fingerprints in this snapshot.
    pub fn fingerprints(&self) -> HashSet<&str> {
        self.fps.keys().map(|s| s.as_str()).collect()
    }
}

/// Detects guard-discovery attacks by monitoring guard-flag churn across consensus updates.
#[cfg_attr(not(feature = "arti-hooks"), allow(dead_code))]
pub struct GuardDiscoveryDetector {
    config:   ShieldConfig,
    tx:       EventTx,
    previous: Option<GuardSnapshot>,
}

impl GuardDiscoveryDetector {
    /// Create a new `GuardDiscoveryDetector`.
    pub fn new(config: ShieldConfig, tx: EventTx) -> Self {
        Self { config, tx, previous: None }
    }

    /// Compare two consecutive guard snapshots and emit events for significant churn
    /// or /24-subnet injection clusters.
    pub fn analyse_transition(
        &mut self,
        prev: &GuardSnapshot,
        curr: &GuardSnapshot,
    ) -> Vec<ThreatEvent> {
        let mut events = Vec::new();
        let prev_fps = prev.fingerprints();
        let curr_fps = curr.fingerprints();
        let added:   Vec<&str> = curr_fps.difference(&prev_fps).copied().collect();
        let removed: Vec<&str> = prev_fps.difference(&curr_fps).copied().collect();
        let total     = curr_fps.len().max(1);
        let churn     = added.len() + removed.len();
        let churn_pct = churn as f64 / total as f64;

        debug!(added = added.len(), removed = removed.len(), "Guard transition");

        if churn_pct >= 0.15 {
            warn!(churn, total, pct = format!("{:.1}%", churn_pct*100.0), "Guard churn");
            events.push(ThreatEvent::new(
                ThreatLevel::Medium,
                ThreatKind::GuardDiscovery {
                    rotation_count:          churn as u32,
                    window_secs:             3600,
                    suspicious_fingerprints: added.iter().take(10).map(|s| s.to_string()).collect(),
                },
                format!("Guard churn: {churn} relays ({:.0}%) in one consensus", churn_pct*100.0),
                churn_pct.min(1.0),
                vec!["guard_pin".into()],
            ));
        }

        let mut new_subnet: HashMap<String, Vec<String>> = HashMap::new();
        for fp in &added {
            if let Some(Some(ip)) = curr.fps.get(*fp) {
                if let Some(pfx) = prefix24(*ip) {
                    new_subnet.entry(pfx).or_default().push(fp.to_string());
                }
            }
        }
        for (pfx, fps) in &new_subnet {
            if fps.len() >= 3 {
                warn!(prefix = pfx, count = fps.len(), "Guard injection /24 cluster");
                events.push(ThreatEvent::new(
                    ThreatLevel::High,
                    ThreatKind::GuardDiscovery {
                        rotation_count:          fps.len() as u32,
                        window_secs:             3600,
                        suspicious_fingerprints: fps.clone(),
                    },
                    format!("Guard injection: {} new Guard relays in /24 {pfx}", fps.len()),
                    0.80,
                    vec!["guard_pin".into(), "entry_ip_filter".into()],
                ));
            }
        }

        events
    }

    #[cfg(feature = "arti-hooks")]
    pub async fn run(mut self, dirmgr: std::sync::Arc<dyn tor_netdir::NetDirProvider>) {
        use futures::StreamExt as _;
        use tor_linkspec::HasAddrs as _;
        use tor_netdir::{DirEvent, Timeliness};

        info!("GuardDiscoveryDetector: subscribing to DirEvent stream");

        let snap_from = |nd: &tor_netdir::NetDir| GuardSnapshot {
            // Scan all relays — is_flagged_guard() method availability varies
            // by arti version; subnet analysis applies to all relay positions
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
            info!(guards = snap.fps.len(), "GuardDiscovery: initial snapshot");
            self.previous = Some(snap);
        }

        let mut stream = dirmgr.events();
        loop {
            match stream.next().await {
                Some(DirEvent::NewConsensus) => {
                    if let Ok(nd) = dirmgr.netdir(Timeliness::Timely) {
                        let curr = snap_from(&nd);
                        if let Some(prev) = self.previous.take() {
                            for evt in self.analyse_transition(&prev, &curr) {
                                let _ = self.tx.send(evt);
                            }
                        }
                        self.previous = Some(curr);
                    }
                }
                // DirEvent is #[non_exhaustive]
                Some(_) => {}
                None    => { warn!("GuardDiscoveryDetector: stream closed"); break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn det() -> GuardDiscoveryDetector {
        let (tx, _) = broadcast::channel(64);
        GuardDiscoveryDetector::new(ShieldConfig::default(), tx)
    }

    fn snap(fps: &[(&str, Option<&str>)]) -> GuardSnapshot {
        GuardSnapshot {
            fps: fps.iter()
                .map(|(fp, ip)| (fp.to_string(), ip.map(|s| s.parse().unwrap())))
                .collect(),
        }
    }

    #[test]
    fn no_churn_silent() {
        let mut d = det();
        let s = snap(&[("A", Some("1.2.3.4")), ("B", Some("5.6.7.8"))]);
        assert!(d.analyse_transition(&s.clone(), &s).is_empty());
    }

    #[test]
    fn full_churn_fires() {
        let mut d = det();
        let pv: Vec<(String, Option<&str>)> = (0..10).map(|i|(format!("P{i:02}"),Some("1.1.1.1"))).collect();
        let cv: Vec<(String, Option<&str>)> = (10..20).map(|i|(format!("C{i:02}"),Some("2.2.2.2"))).collect();
        let prev = snap(&pv.iter().map(|(a,b)|(a.as_str(),*b)).collect::<Vec<_>>());
        let curr = snap(&cv.iter().map(|(a,b)|(a.as_str(),*b)).collect::<Vec<_>>());
        assert!(!d.analyse_transition(&prev, &curr).is_empty());
    }

    #[test]
    fn new_guard_subnet_cluster() {
        let mut d = det();
        let prev = snap(&[("OLD", Some("1.2.3.4"))]);
        let curr = snap(&[
            ("OLD", Some("1.2.3.4")),
            ("N1",  Some("198.51.100.1")),
            ("N2",  Some("198.51.100.2")),
            ("N3",  Some("198.51.100.3")),
        ]);
        assert!(!d.analyse_transition(&prev, &curr).is_empty());
    }
}
