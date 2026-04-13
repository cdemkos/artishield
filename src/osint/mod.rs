//! OSINT engine: Tor relay enrichment (Onionoo + RDAP), IP geolocation,
//! Overpass building lookup, OSM tile fetching.
//!
//! All network I/O runs in a dedicated background thread so Bevy's main loop
//! is never blocked.  Results are returned via an [`mpsc`] channel that the
//! egui UI drains each frame.
//!
//! # Key insight
//!
//! In the Tor network, **attacker IPs are hidden by design**.  The information
//! available to ArtiShield is limited to:
//!
//! * **Relay fingerprints** and **relay IPs** — both public (in every consensus)
//! * Circuit paths through those relays
//! * Statistical anomalies derived from timing / directory data
//!
//! Therefore OSINT targets are always relay nodes, never end-user IPs.

pub mod relay;

use std::{
    net::IpAddr,
    sync::{mpsc, Mutex},
};

use serde::Deserialize;
use tracing::{debug, warn};

// ── Public result types ───────────────────────────────────────────────────────

/// Everything we know about one IP after a full OSINT pass.
#[derive(Debug, Clone)]
pub struct IpOsintResult {
    /// The queried IP address.
    pub ip: IpAddr,
    /// Two-letter ISO country code (e.g. `"DE"`).
    pub country_code: String,
    /// Human-readable country name.
    pub country: String,
    /// Region / state name.
    pub region: String,
    /// City name.
    pub city: String,
    /// Latitude (WGS-84 degrees).
    pub lat: f64,
    /// Longitude (WGS-84 degrees).
    pub lon: f64,
    /// ISP / organisation name.
    pub isp: String,
    /// AS number + org string (e.g. `"AS1234 Some Hosting"`).
    pub asn: String,
    /// Postal code, if available.
    pub postal: String,
    /// IANA timezone string.
    pub timezone: String,
    /// Closest buildings / addresses from Overpass API.
    pub buildings: Vec<BuildingInfo>,
    /// Raw PNG bytes of the OSM tile centred on the IP's location (zoom 17).
    pub tile_png: Option<Vec<u8>>,
    /// Display URL of the tile (for attribution).
    pub tile_url: String,
}

/// A building or address node returned by the Overpass API.
#[derive(Debug, Clone)]
pub struct BuildingInfo {
    /// OSM `name` tag, if present.
    pub name: Option<String>,
    /// Street + house number from addr:* tags.
    pub address: String,
    /// `building` tag value (e.g. `"residential"`, `"office"`, `"yes"`).
    pub building_type: String,
    /// Centre latitude.
    pub lat: f64,
    /// Centre longitude.
    pub lon: f64,
}

// ── Cross-thread channel ──────────────────────────────────────────────────────

/// Request sent from Bevy to the OSINT worker thread.
pub enum OsintRequest {
    /// Geolocate a known IP (fallback for non-Tor events).
    Ip(IpAddr),
    /// Full relay OSINT: Onionoo + ip-api + RDAP.
    Relay {
        /// 40-char hex fingerprint.
        fingerprint: String,
    },
}

/// All possible OSINT results.
#[derive(Debug, Clone)]
pub enum OsintResult {
    /// Result of an IP-level lookup (fallback path).
    Ip(IpOsintResult),
    /// Result of a relay fingerprint lookup.
    Relay(relay::RelayProfile),
}

/// Bevy resource wrapping the OSINT result receiver.
#[derive(bevy::prelude::Resource)]
pub struct OsintResultReceiver(pub Mutex<mpsc::Receiver<OsintResult>>);

/// Bevy resource wrapping the OSINT request sender.
#[derive(bevy::prelude::Resource, Clone)]
pub struct OsintRequestSender(pub mpsc::SyncSender<OsintRequest>);

// ── Worker thread ─────────────────────────────────────────────────────────────

/// Spawn the OSINT worker thread.
///
/// Returns `(sender, receiver)` Bevy resources that should be inserted into the app.
pub fn spawn_worker() -> (OsintRequestSender, OsintResultReceiver) {
    let (req_tx, req_rx) = mpsc::sync_channel::<OsintRequest>(32);
    let (res_tx, res_rx) = mpsc::channel::<OsintResult>();

    if let Err(e) = std::thread::Builder::new()
        .name("osint-worker".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("OSINT worker: failed to create Tokio runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                while let Ok(req) = req_rx.recv() {
                    match req {
                        OsintRequest::Ip(ip) => match run_ip_lookup(ip).await {
                            Ok(r) => {
                                let _ = res_tx.send(OsintResult::Ip(r));
                            }
                            Err(e) => warn!("OSINT IP lookup failed for {ip}: {e}"),
                        },
                        OsintRequest::Relay { fingerprint } => {
                            match relay::lookup_relay(&fingerprint).await {
                                Ok(r) => {
                                    let _ = res_tx.send(OsintResult::Relay(r));
                                }
                                Err(e) => warn!("OSINT relay lookup failed for {fingerprint}: {e}"),
                            }
                        }
                    }
                }
            });
        })
    {
        tracing::error!("OSINT worker: failed to spawn thread: {e}");
    }

    (
        OsintRequestSender(req_tx),
        OsintResultReceiver(Mutex::new(res_rx)),
    )
}

// ── ip-api.com response ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    isp: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    zip: Option<String>,
    timezone: Option<String>,
}

async fn lookup_ip_api(client: &reqwest::Client, ip: IpAddr) -> anyhow::Result<IpApiResponse> {
    let url = format!(
        "https://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,as,zip,timezone",
        ip
    );
    debug!(%ip, "OSINT: ip-api.com lookup");
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await?
        .json::<IpApiResponse>()
        .await?;
    Ok(resp)
}

// ── Overpass API ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OverpassResult {
    elements: Vec<OverpassElement>,
}

#[derive(Deserialize)]
struct OverpassElement {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    elem_type: String,
    center: Option<OverpassCenter>,
    lat: Option<f64>,
    lon: Option<f64>,
    tags: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
struct OverpassCenter {
    lat: f64,
    lon: f64,
}

/// Query buildings within `radius_m` metres of (`lat`, `lon`).
async fn query_buildings(
    client: &reqwest::Client,
    lat: f64,
    lon: f64,
    radius_m: u32,
) -> anyhow::Result<Vec<BuildingInfo>> {
    // Validate inputs before embedding them in the Overpass query body.
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        anyhow::bail!("invalid coordinates: lat={lat}, lon={lon}");
    }
    if radius_m > 1_000 {
        anyhow::bail!("radius {radius_m} m exceeds maximum of 1 000 m");
    }
    let query = format!(
        r#"[out:json][timeout:10];
(
  way["building"](around:{radius},{lat},{lon});
  node["addr:housenumber"](around:{radius},{lat},{lon});
);
out center tags;"#,
        radius = radius_m,
        lat = lat,
        lon = lon,
    );

    debug!(lat, lon, radius_m, "OSINT: Overpass buildings query");
    let resp = client
        .post("https://overpass-api.de/api/interpreter")
        .body(query)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?
        .json::<OverpassResult>()
        .await?;

    let buildings = resp
        .elements
        .into_iter()
        .filter_map(|e| {
            let tags = e.tags.unwrap_or_default();
            // Skip elements with neither building tag nor address
            if !tags.contains_key("building") && !tags.contains_key("addr:housenumber") {
                return None;
            }
            let (lat, lon) = if let Some(c) = e.center {
                (c.lat, c.lon)
            } else if let (Some(la), Some(lo)) = (e.lat, e.lon) {
                (la, lo)
            } else {
                return None;
            };

            let street = tags.get("addr:street").cloned().unwrap_or_default();
            let number = tags.get("addr:housenumber").cloned().unwrap_or_default();
            let city = tags.get("addr:city").cloned().unwrap_or_default();
            let address = format!(
                "{street} {number}{}",
                if city.is_empty() {
                    String::new()
                } else {
                    format!(", {city}")
                }
            )
            .trim()
            .to_string();

            Some(BuildingInfo {
                name: tags.get("name").cloned(),
                address,
                building_type: tags
                    .get("building")
                    .cloned()
                    .unwrap_or_else(|| "address".into()),
                lat,
                lon,
            })
        })
        .take(10)
        .collect();

    Ok(buildings)
}

// ── OSM tile fetch ────────────────────────────────────────────────────────────

/// Convert WGS-84 coordinates to OSM slippy-map tile indices at `zoom`.
pub fn lat_lon_to_tile(lat: f64, lon: f64, zoom: u8) -> (u32, u32) {
    let n = (1u32 << zoom) as f64;
    let x = ((lon + 180.0) / 360.0 * n) as u32;
    let lat_r = lat.to_radians();
    let y =
        ((1.0 - (lat_r.tan() + 1.0 / lat_r.cos()).ln() / std::f64::consts::PI) / 2.0 * n) as u32;
    (x, y)
}

/// Fetch the PNG bytes of one OSM standard tile.
async fn fetch_tile(
    client: &reqwest::Client,
    lat: f64,
    lon: f64,
    zoom: u8,
) -> anyhow::Result<(Vec<u8>, String)> {
    let (x, y) = lat_lon_to_tile(lat, lon, zoom);
    let url = format!("https://tile.openstreetmap.org/{zoom}/{x}/{y}.png");
    debug!(%url, "OSINT: fetching OSM tile");
    let bytes = client
        .get(&url)
        .header(
            "User-Agent",
            "ArtiShield/0.2 (security research; contact: artishield)",
        )
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .bytes()
        .await?
        .to_vec();
    Ok((bytes, url))
}

// ── Full IP lookup pipeline ───────────────────────────────────────────────────

async fn run_ip_lookup(ip: IpAddr) -> anyhow::Result<IpOsintResult> {
    let client = reqwest::Client::builder()
        .user_agent("ArtiShield/0.2 threat-monitor")
        .build()?;

    // Step 1: IP geolocation
    let geo = lookup_ip_api(&client, ip).await?;
    if geo.status != "success" {
        anyhow::bail!("ip-api.com returned status != success for {ip}");
    }

    let lat = geo.lat.unwrap_or(0.0);
    let lon = geo.lon.unwrap_or(0.0);

    // Step 2: nearby buildings (zoom 17 ≈ 100 m radius makes sense)
    let buildings = query_buildings(&client, lat, lon, 100)
        .await
        .unwrap_or_else(|e| {
            warn!("Overpass query failed: {e}");
            vec![]
        });

    // Step 3: OSM tile (zoom 17 ≈ street level)
    let (tile_png, tile_url) = fetch_tile(&client, lat, lon, 17).await.unwrap_or_else(|e| {
        warn!("OSM tile fetch failed: {e}");
        (vec![], String::new())
    });

    Ok(IpOsintResult {
        ip,
        country_code: geo.country_code.unwrap_or_default(),
        country: geo.country.unwrap_or_default(),
        region: geo.region.unwrap_or_default(),
        city: geo.city.unwrap_or_default(),
        lat,
        lon,
        isp: geo.isp.unwrap_or_default(),
        asn: geo.asn.unwrap_or_default(),
        postal: geo.zip.unwrap_or_default(),
        timezone: geo.timezone.unwrap_or_default(),
        buildings,
        tile_png: if tile_png.is_empty() {
            None
        } else {
            Some(tile_png)
        },
        tile_url,
    })
}
