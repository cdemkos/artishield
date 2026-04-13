//! MaxMind GeoLite2 City + ASN lookup service.

use maxminddb::Reader;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;

/// Geographic and network metadata resolved for a single IP address.
#[derive(Debug, Serialize, Clone, Default)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. `"CH"`, `"DE"`).
    pub country: Option<String>,
    /// City name, preferring German then English locale.
    pub city: Option<String>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// Human-readable ASN organisation name (e.g. `"Contabo GmbH"`).
    pub asn_name: Option<String>,
}

/// Thread-safe shared handle to a [`GeoIpServiceInner`].
pub type GeoIpService = Arc<GeoIpServiceInner>;

/// Holds the two MaxMind database readers (City + ASN).
#[derive(Debug)]
pub struct GeoIpServiceInner {
    city_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}

impl GeoIpServiceInner {
    /// Open the MaxMind GeoLite2-City and GeoLite2-ASN databases at the given paths.
    pub fn new(city_path: &str, asn_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            city_reader: Reader::open_readfile(city_path)?,
            asn_reader: Reader::open_readfile(asn_path)?,
        })
    }

    /// Look up geographic and ASN metadata for `ip`. Missing data fields are `None`.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let city: Option<maxminddb::geoip2::City<'_>> = self.city_reader.lookup(ip).ok();
        let asn: Option<maxminddb::geoip2::Asn<'_>> = self.asn_reader.lookup(ip).ok();

        GeoInfo {
            country: city.as_ref().and_then(|c| {
                c.country
                    .as_ref()
                    .and_then(|co| co.iso_code.map(|s| s.to_string()))
            }),
            city: city.and_then(|c| {
                c.city.and_then(|ci| {
                    ci.names
                        .and_then(|n| n.get("de").or(n.get("en")).map(|s| s.to_string()))
                })
            }),
            asn: asn.as_ref().and_then(|a| a.autonomous_system_number),
            asn_name: asn.and_then(|a| a.autonomous_system_organization.map(|s| s.to_string())),
        }
    }
}
