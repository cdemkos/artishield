//! Legal offensive countermeasures against malicious Tor relays.
//!
//! All actions here are strictly legal and operate either locally (iptables,
//! config generation) or via public reporting channels (Tor Project bad-relays
//! mailing list, AbuseIPDB).  No action is taken without user confirmation in
//! the UI.
//!
//! # Countermeasure catalogue
//!
//! | Name | Effect | Requires root? |
//! |------|--------|----------------|
//! | [`exclude_nodes_snippet`]  | Arti/Torrc ExcludeNodes config line | No |
//! | [`iptables_drop_rule`]     | iptables OUTPUT DROP for relay IP   | Yes (show cmd) |
//! | [`nftables_drop_rule`]     | nftables equivalent                 | Yes (show cmd) |
//! | [`bad_relay_report`]       | Draft email for bad-relays@…        | No |
//! | [`abuseipdb_curl_cmd`]     | curl command for AbuseIPDB API      | No (needs key) |
//! | [`rdap_abuse_email_draft`] | Email draft to ASN abuse contact    | No |

use crate::osint::relay::RelayProfile;

// ── Config generation ─────────────────────────────────────────────────────────

/// Generate an `ExcludeNodes` line for `arti.toml` / `torrc` that bans all
/// fingerprints in `relays` and their declared families.
///
/// Paste the output into your arti config under `[path_config]`.
pub fn exclude_nodes_snippet(relays: &[RelayProfile]) -> String {
    let fps: Vec<&str> = relays.iter().map(|r| r.fingerprint.as_str()).collect();
    let family: Vec<&str> = relays
        .iter()
        .flat_map(|r| r.family_fingerprints.iter().map(|s| s.as_str()))
        .collect();

    let mut all: Vec<&str> = fps;
    all.extend(family);
    all.sort_unstable();
    all.dedup();

    format!(
        "# ArtiShield — generated ExcludeNodes\n\
         # Add to your arti.toml under [path_config] or to torrc\n\
         #\n\
         ExcludeNodes {}\n\
         \n\
         # arti.toml equivalent:\n\
         # [path_config]\n\
         # exclude_nodes = [{}]\n",
        all.iter().map(|fp| format!("${fp}")).collect::<Vec<_>>().join(","),
        all.iter()
            .map(|fp| format!("{{identity = \"{fp}\"}}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

// ── Firewall rules ────────────────────────────────────────────────────────────

/// Generate `iptables` rules that drop all outbound traffic to each relay's
/// OR-address (IP + port).
///
/// Prints a shell script; run as root.
pub fn iptables_drop_rule(relays: &[RelayProfile]) -> String {
    let mut lines = vec![
        "#!/bin/sh".to_owned(),
        "# ArtiShield — iptables block for malicious Tor relays".to_owned(),
        "# Run as root: sudo sh block_relays.sh".to_owned(),
        String::new(),
    ];
    for r in relays {
        let Some(ip) = r.ip else { continue };
        // Extract port from or_address "ip:port" or "[ipv6]:port"
        let port = r.or_address
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(9001);
        lines.push(format!(
            "# {} ({})",
            r.nickname, r.fingerprint
        ));
        lines.push(format!(
            "iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP"
        ));
        lines.push(format!(
            "iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j LOG \
             --log-prefix \"ARTISHIELD-BLOCK: \""
        ));
    }
    lines.push(String::new());
    lines.push("echo \"Rules applied.\"".to_owned());
    lines.join("\n")
}

/// Generate `nftables` rules (modern alternative to iptables).
pub fn nftables_drop_rule(relays: &[RelayProfile]) -> String {
    let mut lines = vec![
        "#!/usr/sbin/nft -f".to_owned(),
        "# ArtiShield — nftables block for malicious Tor relays".to_owned(),
        String::new(),
        "table inet artishield_block {".to_owned(),
        "  chain output {".to_owned(),
        "    type filter hook output priority 0; policy accept;".to_owned(),
    ];
    for r in relays {
        let Some(ip) = r.ip else { continue };
        let port = r.or_address
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(9001);
        lines.push(format!(
            "    # {} ({})", r.nickname, r.fingerprint
        ));
        lines.push(format!(
            "    ip daddr {ip} tcp dport {port} drop comment \"ArtiShield\";"
        ));
    }
    lines.push("  }".to_owned());
    lines.push("}".to_owned());
    lines.join("\n")
}

// ── Reporting ─────────────────────────────────────────────────────────────────

/// Generate a draft email for the Tor Project's
/// `bad-relays@lists.torproject.org` list.
///
/// The email follows the Tor Project's preferred format.
pub fn bad_relay_report(relay: &RelayProfile, reason: &str, evidence: &str) -> String {
    format!(
        "To: bad-relays@lists.torproject.org\n\
         Subject: Malicious relay report: {nickname} ({fp_short})\n\
         \n\
         Hi,\n\
         \n\
         I would like to report a relay that appears to be participating in a\n\
         malicious attack as detected by ArtiShield.\n\
         \n\
         Relay details:\n\
         \n\
         Fingerprint : {fp}\n\
         Nickname    : {nickname}\n\
         OR-Address  : {or_addr}\n\
         Country     : {country} ({geo_city})\n\
         ISP / ASN   : {isp} ({asn})\n\
         Flags       : {flags}\n\
         First seen  : {first_seen}\n\
         \n\
         Reason for report:\n\
         {reason}\n\
         \n\
         Evidence:\n\
         {evidence}\n\
         \n\
         Family members (if applicable):\n\
         {family}\n\
         \n\
         Detected by ArtiShield v0.2 — automated Tor threat monitor.\n\
         \n\
         Best regards",
        nickname  = relay.nickname,
        fp_short  = &relay.fingerprint[..8],
        fp        = relay.fingerprint,
        or_addr   = relay.or_address,
        country   = relay.country,
        geo_city  = relay.geo_city,
        isp       = relay.geo_isp,
        asn       = relay.asn,
        flags     = relay.flags.join(", "),
        first_seen = relay.first_seen,
        reason    = reason,
        evidence  = evidence,
        family    = if relay.family_fingerprints.is_empty() {
            "none declared".to_owned()
        } else {
            relay.family_fingerprints.join("\n")
        },
    )
}

/// Generate a `curl` command to file an AbuseIPDB report.
///
/// The user must substitute `YOUR_API_KEY` with their own key from
/// <https://www.abuseipdb.com/api>.
pub fn abuseipdb_curl_cmd(relay: &RelayProfile, reason: &str) -> String {
    let Some(ip) = relay.ip else {
        return "# No IP available for this relay".to_owned();
    };
    format!(
        "# AbuseIPDB report for relay {nickname} ({fp_short})\n\
         # Get your API key at https://www.abuseipdb.com/api\n\
         curl -s https://api.abuseipdb.com/api/v2/report \\\n\
           -H 'Key: YOUR_API_KEY' \\\n\
           -H 'Accept: application/json' \\\n\
           --data-urlencode 'ip={ip}' \\\n\
           --data-urlencode 'categories=14,19' \\\n\
           --data-urlencode 'comment=Tor malicious relay ({nickname}, {fp_short}): {reason}'\n",
        nickname  = relay.nickname,
        fp_short  = &relay.fingerprint[..8.min(relay.fingerprint.len())],
        ip        = ip,
        reason    = reason.replace('\n', " "),
    )
}

/// Generate a draft email to the ASN abuse contact (from RDAP).
pub fn rdap_abuse_email_draft(relay: &RelayProfile, reason: &str) -> String {
    let contact = relay.abuse_contact
        .as_deref()
        .unwrap_or("(no abuse contact found — check https://search.arin.net)");
    format!(
        "To: {contact}\n\
         Subject: Abuse report — Tor malicious relay hosted in your network\n\
         \n\
         Dear Network Operations team,\n\
         \n\
         We have detected a Tor relay hosted in your network ({asn} / {as_name})\n\
         that appears to be participating in malicious activity against Tor users.\n\
         \n\
         Relay IP    : {ip}\n\
         Fingerprint : {fp}\n\
         Nickname    : {nickname}\n\
         \n\
         Reason:\n\
         {reason}\n\
         \n\
         We request that you investigate and take appropriate action.\n\
         \n\
         Regards,\n\
         ArtiShield automated abuse reporting",
        contact  = contact,
        asn      = relay.asn,
        as_name  = relay.as_name,
        ip       = relay.ip.map(|i| i.to_string()).unwrap_or_else(|| "(unknown)".into()),
        fp       = relay.fingerprint,
        nickname = relay.nickname,
        reason   = reason,
    )
}

// ── Countermeasure result type ────────────────────────────────────────────────

/// All generated countermeasure texts for one relay, ready to display in the UI.
#[derive(Debug, Clone, Default)]
pub struct CountermeasureSet {
    /// ExcludeNodes torrc / arti.toml snippet.
    pub exclude_nodes: String,
    /// iptables shell script.
    pub iptables: String,
    /// nftables ruleset.
    pub nftables: String,
    /// bad-relays email draft.
    pub bad_relay_email: String,
    /// AbuseIPDB curl command.
    pub abuseipdb_cmd: String,
    /// ISP abuse contact email draft.
    pub isp_abuse_email: String,
}

/// Generate the full [`CountermeasureSet`] for a single relay profile.
pub fn generate(profile: &RelayProfile, reason: &str, evidence: &str) -> CountermeasureSet {
    CountermeasureSet {
        exclude_nodes:    exclude_nodes_snippet(std::slice::from_ref(profile)),
        iptables:         iptables_drop_rule(std::slice::from_ref(profile)),
        nftables:         nftables_drop_rule(std::slice::from_ref(profile)),
        bad_relay_email:  bad_relay_report(profile, reason, evidence),
        abuseipdb_cmd:    abuseipdb_curl_cmd(profile, reason),
        isp_abuse_email:  rdap_abuse_email_draft(profile, reason),
    }
}
