//! Tor relay OSINT via Onionoo (Tor Project) and RDAP/ARIN.
//!
//! All relay IPs and fingerprints are **public** — they appear in every Tor
//! consensus document.  This module enriches a known fingerprint with:
//!
//! * Onionoo relay details (flags, bandwidth, uptime, family, contact, …)
//! * ip-api.com geolocation for the relay's first OR-address
//! * RDAP / ARIN lookup for ASN abuse contact info

use serde::Deserialize;
use std::net::IpAddr;
use tracing::{debug, warn};

// ── Onionoo ───────────────────────────────────────────────────────────────────

/// Full relay profile returned by the Onionoo API.
#[derive(Debug, Clone, Default)]
pub struct RelayProfile {
    /// Hex fingerprint (40 chars).
    pub fingerprint: String,
    /// Operator-chosen nickname.
    pub nickname: String,
    /// Primary OR-address (host:port).
    pub or_address: String,
    /// Parsed IP from `or_address`.
    pub ip: Option<IpAddr>,
    /// Two-letter country code (Onionoo `country` field).
    pub country: String,
    /// ASN string, e.g. `"AS1234"`.
    pub asn: String,
    /// ASN organisation name.
    pub as_name: String,
    /// Consensus flags, e.g. `["Guard", "Fast", "Running"]`.
    pub flags: Vec<String>,
    /// Advertised bandwidth rate in bytes/s.
    pub bandwidth_rate: u64,
    /// Fraction of time the relay was up in the last 30 days (`0..=1`).
    pub uptime: f64,
    /// ISO timestamp of first appearance in a consensus.
    pub first_seen: String,
    /// ISO timestamp of last appearance.
    pub last_seen: String,
    /// Self-reported platform string.
    pub platform: String,
    /// Operator contact string (raw, may be encrypted).
    pub contact: String,
    /// Probability this relay is selected as guard (`0..=1`).
    pub guard_probability: f64,
    /// Probability this relay is selected as exit (`0..=1`).
    pub exit_probability: f64,
    /// Fingerprints of relays in the same declared family.
    pub family_fingerprints: Vec<String>,
    /// ip-api.com country for the relay's IP.
    pub geo_country: String,
    /// ip-api.com city.
    pub geo_city: String,
    /// ip-api.com ISP.
    pub geo_isp: String,
    /// Latitude of relay's IP.
    pub geo_lat: f64,
    /// Longitude of relay's IP.
    pub geo_lon: f64,
    /// Abuse contact email from RDAP, if found.
    pub abuse_contact: Option<String>,
}

// ── Onionoo JSON types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OnionooResponse {
    relays: Vec<OnionooRelay>,
}

#[derive(Deserialize)]
struct OnionooRelay {
    fingerprint: Option<String>,
    nickname: Option<String>,
    or_addresses: Option<Vec<String>>,
    country: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    as_name: Option<String>,
    flags: Option<Vec<String>>,
    bandwidth_rate: Option<u64>,
    uptime: Option<f64>,
    first_seen: Option<String>,
    last_seen: Option<String>,
    platform: Option<String>,
    contact: Option<String>,
    guard_probability: Option<f64>,
    exit_probability: Option<f64>,
    family_fingerprints: Option<Vec<String>>,
}

// ── ip-api.com ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IpApiResponse {
    country: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
}

// ── RDAP ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RdapResponse {
    entities: Option<Vec<RdapEntity>>,
}

#[derive(Deserialize)]
struct RdapEntity {
    roles: Option<Vec<String>>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
}

fn extract_rdap_abuse_email(resp: &RdapResponse) -> Option<String> {
    let entities = resp.entities.as_ref()?;
    for entity in entities {
        let roles = entity.roles.as_ref()?;
        if !roles.iter().any(|r| r == "abuse") {
            continue;
        }
        if let Some(vcard) = &entity.vcard_array {
            // vcardArray = ["vcard", [[type, {}, kind, value], ...]]
            if let Some(entries) = vcard.get(1).and_then(|v| v.as_array()) {
                for entry in entries {
                    if let Some(arr) = entry.as_array() {
                        if arr.first().and_then(|v| v.as_str()) == Some("email") {
                            if let Some(email) = arr.get(3).and_then(|v| v.as_str()) {
                                return Some(email.to_owned());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ── Main lookup ───────────────────────────────────────────────────────────────

/// Look up a relay by fingerprint.  All data sources are queried in parallel.
pub async fn lookup_relay(fingerprint: &str) -> anyhow::Result<RelayProfile> {
    let client = reqwest::Client::builder()
        .user_agent("ArtiShield/0.2 (security research)")
        .build()?;

    // Step 1: Onionoo
    let url = format!(
        "https://onionoo.torproject.org/details?lookup={fingerprint}&fields=fingerprint,nickname,or_addresses,country,as,as_name,flags,bandwidth_rate,uptime,first_seen,last_seen,platform,contact,guard_probability,exit_probability,family_fingerprints"
    );
    debug!(fingerprint, "Onionoo relay lookup");
    let onion: OnionooResponse = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(12))
        .send()
        .await?
        .json()
        .await?;

    let relay = onion.relays.into_iter().next().unwrap_or(OnionooRelay {
        fingerprint: Some(fingerprint.to_owned()),
        ..Default::default()
    });

    let or_address = relay
        .or_addresses
        .as_ref()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    // Parse IP from "host:port"
    let ip: Option<IpAddr> = or_address
        .rsplit_once(':')
        .and_then(|(host, _)| host.trim_matches(|c| c == '[' || c == ']').parse().ok());

    // Step 2: ip-api + RDAP in parallel (best-effort)
    let (geo, rdap_email) = tokio::join!(
        async {
            let Some(ip) = ip else { return None };
            let geo_url = format!("https://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon");
            client
                .get(&geo_url)
                .timeout(std::time::Duration::from_secs(6))
                .send()
                .await
                .ok()?
                .json::<IpApiResponse>()
                .await
                .ok()
        },
        async {
            let Some(ip) = ip else { return None };
            let rdap_url = format!("https://rdap.arin.net/registry/ip/{ip}");
            let resp = client
                .get(&rdap_url)
                .timeout(std::time::Duration::from_secs(8))
                .send()
                .await
                .ok()?
                .json::<RdapResponse>()
                .await;
            match resp {
                Ok(r) => extract_rdap_abuse_email(&r),
                Err(e) => {
                    warn!("RDAP parse error: {e}");
                    None
                }
            }
        }
    );

    Ok(RelayProfile {
        fingerprint: relay.fingerprint.unwrap_or_else(|| fingerprint.to_owned()),
        nickname: relay.nickname.unwrap_or_default(),
        or_address: or_address.clone(),
        ip,
        country: relay.country.unwrap_or_default(),
        asn: relay.asn.unwrap_or_default(),
        as_name: relay.as_name.unwrap_or_default(),
        flags: relay.flags.unwrap_or_default(),
        bandwidth_rate: relay.bandwidth_rate.unwrap_or_default(),
        uptime: relay.uptime.unwrap_or_default(),
        first_seen: relay.first_seen.unwrap_or_default(),
        last_seen: relay.last_seen.unwrap_or_default(),
        platform: relay.platform.unwrap_or_default(),
        contact: relay.contact.unwrap_or_default(),
        guard_probability: relay.guard_probability.unwrap_or_default(),
        exit_probability: relay.exit_probability.unwrap_or_default(),
        family_fingerprints: relay.family_fingerprints.unwrap_or_default(),
        geo_country: geo
            .as_ref()
            .and_then(|g| g.country.clone())
            .unwrap_or_default(),
        geo_city: geo
            .as_ref()
            .and_then(|g| g.city.clone())
            .unwrap_or_default(),
        geo_isp: geo.as_ref().and_then(|g| g.isp.clone()).unwrap_or_default(),
        geo_lat: geo.as_ref().and_then(|g| g.lat).unwrap_or_default(),
        geo_lon: geo.as_ref().and_then(|g| g.lon).unwrap_or_default(),
        abuse_contact: rdap_email,
    })
}

// ── Helper: default for OnionooRelay ─────────────────────────────────────────

impl Default for OnionooRelay {
    fn default() -> Self {
        Self {
            fingerprint: None,
            nickname: None,
            or_addresses: None,
            country: None,
            asn: None,
            as_name: None,
            flags: None,
            bandwidth_rate: None,
            uptime: None,
            first_seen: None,
            last_seen: None,
            platform: None,
            contact: None,
            guard_probability: None,
            exit_probability: None,
            family_fingerprints: None,
        }
    }
}
