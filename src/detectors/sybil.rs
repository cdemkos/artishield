//! # Sybil Detector
//!
//! ## Real arti API (feature = "arti-hooks")
//!
//! ```text
//! TorClient::dirmgr() → Arc<dyn NetDirProvider>
//!   .events()          → BoxStream<'static, DirEvent>   (NOT impl Stream)
//!   .netdir(Timeliness)→ Result<Arc<NetDir>>
//!
//! Relay  (direct methods — no trait import needed)
//!   .rsa_id()             → &RsaIdentity
//!   .is_flagged_guard()   → bool
//!
//! HasAddrs trait  (must be imported)
//!   .addrs()              → impl Iterator<Item = &SocketAddr>
//!
//! DirEvent is #[non_exhaustive] — match arms need wildcard
//! ```

use crate::{
    config::ShieldConfig,
    detectors::EventTx,
    event::{ThreatEvent, ThreatKind, ThreatLevel},
};
use ipnet::Ipv4Net;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}};
use tracing::{debug, warn};

// ── Public types ─────────────────────────────────────────────────────────────

/// A single circuit hop for Sybil analysis.
#[derive(Debug, Clone)]
pub struct CircuitHop {
    /// Hex-encoded RSA fingerprint of this relay.
    pub fingerprint: String,
    /// Known socket addresses of this relay.
    pub addrs:       Vec<SocketAddr>,
    /// `true` if this relay has the Guard flag.
    pub is_guard:    bool,
    /// `true` if this relay has the Exit flag.
    pub is_exit:     bool,
}

// ── Detector ─────────────────────────────────────────────────────────────────

/// Detects Sybil attacks by identifying /24-subnet and ASN collisions in circuits and the network directory.
#[cfg_attr(not(feature = "arti-hooks"), allow(dead_code))]
pub struct SybilDetector {
    config: ShieldConfig,
    tx:     EventTx,
    #[cfg(feature = "geoip")]
    mmdb:   Option<maxminddb::Reader<Vec<u8>>>,
}

impl SybilDetector {
    /// Create a new `SybilDetector`, optionally loading a MaxMind GeoLite2-ASN database.
    pub fn new(config: ShieldConfig, tx: EventTx) -> Self {
        #[cfg(feature = "geoip")]
        let mmdb = config.geoip_db.as_ref().and_then(|p| {
            maxminddb::Reader::open_readfile(p)
                .map_err(|e| warn!("MaxMind open failed: {e}"))
                .ok()
        });
        Self {
            config, tx,
            #[cfg(feature = "geoip")]
            mmdb,
        }
    }

    fn prefix24(ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => Ipv4Net::new(v4, 24).ok().map(|n| n.network().to_string()),
            IpAddr::V6(_)  => None,
        }
    }

    #[cfg(feature = "geoip")]
    fn asn_of(&self, ip: IpAddr) -> Option<u32> {
        self.mmdb.as_ref()
            .and_then(|db| db.lookup::<maxminddb::geoip2::Asn<'_>>(ip).ok())
            .and_then(|r| r.autonomous_system_number)
    }

    #[cfg(not(feature = "geoip"))]
    fn asn_of(&self, _ip: IpAddr) -> Option<u32> { None }

    /// Build subnet→fps and asn→fps maps from an iterator of (fingerprint, ips).
    fn build_maps(
        &self,
        iter: impl Iterator<Item = (String, Vec<IpAddr>)>,
    ) -> (HashMap<String, Vec<String>>, HashMap<u32, Vec<String>>) {
        let mut subnet_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut asn_map:    HashMap<u32,    Vec<String>> = HashMap::new();
        for (fp, ips) in iter {
            for ip in ips {
                if let Some(pfx) = Self::prefix24(ip) {
                    subnet_map.entry(pfx).or_default().push(fp.clone());
                }
                if let Some(asn) = self.asn_of(ip) {
                    asn_map.entry(asn).or_default().push(fp.clone());
                }
            }
        }
        (subnet_map, asn_map)
    }

    // ── Per-circuit hop check ─────────────────────────────────────────────────

    /// Check a slice of circuit hops for /24-subnet or ASN collisions.
    ///
    /// Returns a `ThreatEvent` on the first collision found, or `None` if the circuit looks clean.
    pub fn check_hops(&self, hops: &[CircuitHop]) -> Option<ThreatEvent> {
        if hops.len() < 2 { return None; }

        let iter = hops.iter().map(|h| {
            (h.fingerprint.clone(), h.addrs.iter().map(|a| a.ip()).collect())
        });
        let (subnet_map, asn_map) = self.build_maps(iter);

        for (pfx, fps) in &subnet_map {
            if fps.len() >= 2 {
                warn!(%pfx, ?fps, "Circuit /24 collision — Sybil");
                return Some(ThreatEvent::new(
                    ThreatLevel::High,
                    ThreatKind::SybilCluster {
                        shared_asn:    None,
                        shared_prefix: Some(pfx.clone()),
                        affected_fps:  fps.clone(),
                    },
                    format!("Circuit: {} hops share /24 {pfx}", fps.len()),
                    0.85,
                    vec!["auto_circuit_rotate".into(), "entry_ip_filter".into()],
                ));
            }
        }

        for (&asn, fps) in &asn_map {
            if fps.len() > self.config.detectors.sybil_asn_max_hops {
                warn!(%asn, "Circuit ASN collision");
                return Some(ThreatEvent::new(
                    ThreatLevel::High,
                    ThreatKind::SybilCluster {
                        shared_asn:    Some(asn),
                        shared_prefix: None,
                        affected_fps:  fps.clone(),
                    },
                    format!("Circuit: {} hops from AS{asn}", fps.len()),
                    0.75,
                    vec!["auto_circuit_rotate".into()],
                ));
            }
        }

        debug!("check_hops: clean");
        None
    }

    // ── NetDir scan ───────────────────────────────────────────────────────────

    /// Scan a full network directory for /24-subnet and ASN concentration events.
    #[cfg(feature = "arti-hooks")]
    pub fn analyse_netdir(&self, netdir: &tor_netdir::NetDir) -> Vec<ThreatEvent> {
        use tor_linkspec::HasAddrs as _;

        let iter = netdir.relays().map(|relay| {
            let fp  = relay.rsa_id().as_bytes()
                .iter().map(|b| format!("{b:02X}")).collect::<String>();
            let ips = relay.addrs().map(|a| a.ip()).collect::<Vec<_>>();
            (fp, ips)
        });
        let (subnet_map, asn_map) = self.build_maps(iter);
        let total = netdir.relays().count();
        let mut out = Vec::new();

        for (pfx, fps) in &subnet_map {
            if fps.len() >= 3 {
                let score = (fps.len() as f64 / 10.0).min(1.0);
                let level = if fps.len() >= 8 { ThreatLevel::Critical }
                            else if fps.len() >= 5 { ThreatLevel::High }
                            else                   { ThreatLevel::Medium };
                warn!(prefix = pfx, count = fps.len(), "Sybil/NetDir: /24 cluster");
                out.push(ThreatEvent::new(level,
                    ThreatKind::SybilCluster {
                        shared_asn: None,
                        shared_prefix: Some(pfx.clone()),
                        affected_fps: fps.clone(),
                    },
                    format!("Sybil: {} relays share /24 {pfx}", fps.len()),
                    score,
                    vec!["entry_ip_filter".into()],
                ));
            }
        }

        let asn_threshold = (total / 50).max(20);
        for (&asn, fps) in &asn_map {
            if fps.len() >= asn_threshold {
                let pct = fps.len() as f64 / total as f64;
                warn!(asn, count = fps.len(), "Sybil/NetDir: ASN concentration");
                out.push(ThreatEvent::new(ThreatLevel::Medium,
                    ThreatKind::SybilCluster {
                        shared_asn: Some(asn),
                        shared_prefix: None,
                        affected_fps: fps.iter().take(20).cloned().collect(),
                    },
                    format!("Sybil: {} relays ({:.1}%) from AS{asn}", fps.len(), pct*100.0),
                    (pct * 5.0).min(0.9),
                    vec!["entry_ip_filter".into()],
                ));
            }
        }

        out
    }

    // ── Main task ─────────────────────────────────────────────────────────────

    /// Subscribe to consensus updates and emit Sybil-cluster events until the stream closes.
    #[cfg(feature = "arti-hooks")]
    pub async fn run(self, dirmgr: std::sync::Arc<dyn tor_netdir::NetDirProvider>) {
        use futures::StreamExt as _;
        // events() returns BoxStream — call directly on dirmgr, no trait import needed
        // DirEvent is #[non_exhaustive] — wildcard arm required
        use tor_netdir::{DirEvent, Timeliness};
        use tracing::info;

        info!("SybilDetector: subscribing to DirEvent stream");

        if let Ok(nd) = dirmgr.netdir(Timeliness::Timely) {
            info!("SybilDetector: initial scan {} relays", nd.relays().count());
            for evt in self.analyse_netdir(&nd) { let _ = self.tx.send(evt); }
        }

        let mut stream = dirmgr.events();
        loop {
            match stream.next().await {
                Some(DirEvent::NewConsensus) => {
                    if let Ok(nd) = dirmgr.netdir(Timeliness::Timely) {
                        for evt in self.analyse_netdir(&nd) { let _ = self.tx.send(evt); }
                    }
                }
                // DirEvent is #[non_exhaustive] — must have wildcard arm
                Some(_) => {}
                None    => { warn!("SybilDetector: stream closed"); break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn det() -> SybilDetector {
        let (tx, _) = broadcast::channel(64);
        SybilDetector::new(ShieldConfig::default(), tx)
    }

    fn hop(ip: &str, fp: &str, guard: bool, exit: bool) -> CircuitHop {
        CircuitHop {
            fingerprint: fp.into(),
            addrs: vec![format!("{ip}:443").parse().unwrap()],
            is_guard: guard, is_exit: exit,
        }
    }

    #[test]
    fn clean_circuit() {
        assert!(det().check_hops(&[
            hop("1.2.3.4",    "AA", true,  false),
            hop("5.6.7.8",    "BB", false, false),
            hop("9.10.11.12", "CC", false, true),
        ]).is_none());
    }

    #[test]
    fn subnet_collision() {
        let evt = det().check_hops(&[
            hop("198.51.100.1",   "AA", true,  false),
            hop("5.6.7.8",        "BB", false, false),
            hop("198.51.100.200", "CC", false, true),
        ]);
        assert!(evt.is_some());
        assert!(matches!(evt.unwrap().kind,
            ThreatKind::SybilCluster { shared_prefix: Some(_), .. }));
    }

    #[test]
    fn ipv6_no_panic() {
        let _ = SybilDetector::prefix24("2001:db8::1".parse().unwrap());
    }

    #[test]
    fn single_hop_clean() {
        assert!(det().check_hops(&[hop("1.2.3.4", "AA", true, false)]).is_none());
    }

    #[test]
    fn mitigation_suggested() {
        let evt = det().check_hops(&[
            hop("198.51.100.1",   "A", true,  false),
            hop("5.6.7.8",        "B", false, false),
            hop("198.51.100.200", "C", false, true),
        ]).unwrap();
        assert!(evt.suggested_mitigations.iter().any(|m| m.contains("circuit_rotate")));
    }

    #[test]
    fn different_slash24_same_slash16_clean() {
        assert!(det().check_hops(&[
            hop("203.0.113.10", "A", true,  false),
            hop("203.0.114.10", "B", false, false),
            hop("198.51.100.1", "C", false, true),
        ]).is_none());
    }
}
