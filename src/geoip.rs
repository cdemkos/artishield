use maxminddb::Reader;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Serialize, Clone, Default)]
pub struct GeoInfo {
    pub country: Option<String>,   // z. B. "CH", "DE"
    pub city: Option<String>,      // z. B. "Zürich"
    pub asn: Option<u32>,
    pub asn_name: Option<String>,  // z. B. "Contabo GmbH"
}

pub type GeoIpService = Arc<GeoIpServiceInner>;

#[derive(Debug)]
pub struct GeoIpServiceInner {
    city_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}

impl GeoIpServiceInner {
    pub fn new(city_path: &str, asn_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            city_reader: Reader::open_readfile(city_path)?,
            asn_reader: Reader::open_readfile(asn_path)?,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let city: Option<maxminddb::geoip2::City> = self.city_reader.lookup(ip).ok();
        let asn: Option<maxminddb::geoip2::Asn> = self.asn_reader.lookup(ip).ok();

        GeoInfo {
            country: city.as_ref().and_then(|c| c.country.as_ref().and_then(|co| co.iso_code.map(|s| s.to_string()))),
            city: city.and_then(|c| c.city.and_then(|ci| ci.names.and_then(|n| n.get("de").or(n.get("en")).map(|s| s.to_string())))),
            asn: asn.as_ref().and_then(|a| a.autonomous_system_number),
            asn_name: asn.and_then(|a| a.autonomous_system_organization.map(|s| s.to_string())),
        }
    }
}
