//! Self-contained HTML report renderer for [`EvidenceReport`].
//!
//! Produces a single `.html` file with all CSS inline — no external
//! dependencies, suitable for printing, emailing, or archiving.

use super::{Classification, EvidenceReport, Ioc, TimelineEntry};

// ── Public entry point ────────────────────────────────────────────────────────

/// Render `report` as a complete HTML document string.
pub fn render(r: &EvidenceReport) -> String {
    let severity_badge = r
        .max_severity()
        .map(|s| format!("{s:?}").to_uppercase())
        .unwrap_or_else(|| "INFO".into());
    let severity_color = match severity_badge.as_str() {
        "CRITICAL" => "#e53935",
        "HIGH" => "#fb8c00",
        "MEDIUM" => "#fdd835",
        "LOW" => "#1e88e5",
        _ => "#43a047",
    };
    let classification_color = match r.classification {
        Classification::Confidential => "#e53935",
        Classification::Restricted => "#fb8c00",
        Classification::Internal => "#1e88e5",
        Classification::Unclassified => "#43a047",
    };

    let events_html = render_events(r);
    let relays_html = render_relays(r);
    let iocs_html = render_iocs(&r.iocs);
    let timeline_html = render_timeline(&r.timeline);
    let cm_html = render_countermeasures(r);
    let integrity_html = render_integrity(r);
    let raw_json = html_escape(&r.to_json_pretty());

    format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ArtiShield Evidence Report — {case_id}</title>
<style>
:root {{
  --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3;
  --text2:#8b949e; --accent:#58a6ff; --red:#f85149; --orange:#d29922;
  --green:#3fb950; --yellow:#e3b341; --blue:#58a6ff; --purple:#bc8cff;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;
  font-size:14px;line-height:1.6;padding:24px}}
a{{color:var(--accent)}}
h1{{font-size:26px;font-weight:700;margin-bottom:4px}}
h2{{font-size:16px;font-weight:600;color:var(--text2);margin:28px 0 12px;
  border-bottom:1px solid var(--border);padding-bottom:6px;text-transform:uppercase;
  letter-spacing:.06em}}
h3{{font-size:14px;font-weight:600;margin-bottom:8px}}
.header{{display:flex;justify-content:space-between;align-items:flex-start;
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:20px 24px;margin-bottom:24px}}
.header-left h1 span.cls{{
  display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;
  font-weight:700;letter-spacing:.08em;margin-left:10px;
  background:{cls_color};color:#fff;vertical-align:middle}}
.meta{{display:grid;grid-template-columns:auto 1fr;gap:4px 16px;margin-top:12px;
  color:var(--text2);font-size:12px}}
.meta b{{color:var(--text)}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;
  font-weight:700;letter-spacing:.06em;background:{sev_color};color:#fff}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;
  margin-bottom:24px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:14px 16px;text-align:center}}
.card .num{{font-size:28px;font-weight:700;color:var(--accent)}}
.card .lbl{{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--surface);color:var(--text2);font-weight:600;text-align:left;
  padding:8px 12px;border-bottom:2px solid var(--border);font-size:11px;
  text-transform:uppercase;letter-spacing:.05em}}
td{{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:rgba(255,255,255,.03)}}
.mono{{font-family:"Courier New",monospace;font-size:12px;word-break:break-all}}
.flag{{display:inline-block;padding:1px 7px;border-radius:3px;font-size:11px;
  font-weight:600;margin:1px;background:#21262d;border:1px solid var(--border)}}
.flag.Guard{{background:#1a3a5c;border-color:#58a6ff;color:#58a6ff}}
.flag.Exit{{background:#3a1a1a;border-color:#f85149;color:#f85149}}
.flag.Fast,.flag.Stable,.flag.Running{{background:#1a3a1a;border-color:#3fb950;color:#3fb950}}
.ioc-fp{{color:var(--purple)}} .ioc-ip{{color:var(--orange)}}
.ioc-asn{{color:var(--yellow)}} .ioc-prefix{{color:var(--red)}}
.sev-CRITICAL{{color:#f85149;font-weight:700}} .sev-HIGH{{color:#d29922;font-weight:700}}
.sev-MEDIUM{{color:#e3b341}} .sev-LOW{{color:#58a6ff}} .sev-INFO{{color:#3fb950}}
.timeline{{list-style:none;position:relative;padding-left:28px}}
.timeline::before{{content:"";position:absolute;left:8px;top:0;bottom:0;
  width:2px;background:var(--border)}}
.timeline li{{position:relative;margin-bottom:14px}}
.timeline li::before{{content:"";position:absolute;left:-24px;top:6px;
  width:10px;height:10px;border-radius:50%;background:var(--accent);
  border:2px solid var(--bg)}}
.timeline .ts{{font-size:11px;color:var(--text2);font-family:monospace}}
.cm-block{{background:var(--surface);border:1px solid var(--border);border-radius:6px;
  margin-bottom:16px}}
.cm-title{{padding:10px 14px;font-weight:600;border-bottom:1px solid var(--border);
  font-size:13px;cursor:pointer;user-select:none}}
.cm-title:hover{{background:rgba(255,255,255,.03)}}
pre.cm-body{{padding:14px;overflow-x:auto;font-size:12px;font-family:"Courier New",monospace;
  color:#a5d6ff;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto}}
.integrity{{background:var(--surface);border:1px solid #3fb95050;border-radius:6px;
  padding:16px 20px}}
.integrity .row{{display:flex;gap:12px;margin-bottom:8px;font-size:12px}}
.integrity .lbl{{color:var(--text2);width:160px;flex-shrink:0;font-weight:600}}
.integrity .val{{color:#a5d6ff;font-family:monospace;word-break:break-all}}
.chain-ok{{color:#3fb950;font-weight:700}} .chain-warn{{color:#d29922;font-weight:700}}
details summary{{cursor:pointer;padding:10px 0;color:var(--text2);font-size:12px}}
details pre{{font-size:11px;font-family:monospace;color:#8b949e;overflow-x:auto;
  max-height:400px;overflow-y:auto;background:#0d1117;padding:12px;border-radius:4px;
  margin-top:8px;white-space:pre-wrap;word-break:break-all}}
@media print{{
  body{{background:#fff;color:#000;padding:12px}}
  .header,.card{{background:#f5f5f5;border-color:#ccc}}
  th{{background:#f0f0f0}}
  .badge{{-webkit-print-color-adjust:exact}}
  details[open] pre{{display:block}}
}}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>ArtiShield Evidence Report
      <span class="cls" style="background:{cls_color}">{cls}</span>
    </h1>
    <div class="meta">
      <b>Report-ID</b><span class="mono">{id}</span>
      <b>Erstellt</b><span>{created_at}</span>
      <b>Fall-ID</b><span>{case_id_disp}</span>
      <b>Ermittler</b><span>{investigator}</span>
      <b>Generator</b><span>{generator}</span>
      {prev_hash_row}
    </div>
  </div>
  <div>
    <div style="text-align:right;margin-bottom:8px">
      <span class="badge" style="background:{sev_color}">{severity_badge}</span>
    </div>
    {notes_block}
  </div>
</div>

<div class="cards">
  <div class="card"><div class="num">{n_events}</div><div class="lbl">Threat Events</div></div>
  <div class="card"><div class="num">{n_relays}</div><div class="lbl">Relay Profile</div></div>
  <div class="card"><div class="num">{n_iocs}</div><div class="lbl">IOCs</div></div>
  <div class="card"><div class="num">{n_tl}</div><div class="lbl">Timeline Einträge</div></div>
  <div class="card"><div class="num">{n_cm}</div><div class="lbl">Gegenmassnahmen</div></div>
</div>

<h2>Timeline</h2>
{timeline_html}

<h2>Threat Events ({n_events})</h2>
{events_html}

<h2>Relay OSINT ({n_relays})</h2>
{relays_html}

<h2>Indicators of Compromise ({n_iocs})</h2>
{iocs_html}

<h2>Gegenmassnahmen</h2>
{cm_html}

<h2>Integrität &amp; Beweiskette</h2>
{integrity_html}

<details>
  <summary>▶ Rohdaten (vollständiges JSON)</summary>
  <pre>{raw_json}</pre>
</details>

<p style="margin-top:32px;color:var(--text2);font-size:11px;text-align:center">
  Erstellt von <b>ArtiShield {ver}</b> · HMAC-SHA256 lokal signiert ·
  {created_at} UTC ·
  <span class="mono" style="font-size:10px">{hash_prefix}…</span>
</p>

</body>
</html>"#,
        cls_color = classification_color,
        cls = r.classification,
        sev_color = severity_color,
        severity_badge = severity_badge,
        id = r.id,
        created_at = r.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        case_id_disp = r.case_id.as_deref().unwrap_or("—"),
        investigator = r.investigator.as_deref().unwrap_or("—"),
        generator = html_escape(&r.generator),
        prev_hash_row = if let Some(ref ph) = r.prev_hash {
            format!("<b>Prev-Hash</b><span class=\"mono\">{}</span>", &ph[..20])
        } else {
            "<b>Prev-Hash</b><span style=\"color:#8b949e\">— (erster Bericht)</span>".into()
        },
        notes_block = if r.notes.is_empty() {
            String::new()
        } else {
            format!(
                "<div style=\"max-width:320px;font-size:13px;color:var(--text2)\">{}</div>",
                html_escape(&r.notes)
            )
        },
        n_events = r.threat_events.len(),
        n_relays = r.relay_profiles.len(),
        n_iocs = r.iocs.len(),
        n_tl = r.timeline.len(),
        n_cm = r.countermeasures.len(),
        timeline_html = timeline_html,
        events_html = events_html,
        relays_html = relays_html,
        iocs_html = iocs_html,
        cm_html = cm_html,
        integrity_html = integrity_html,
        raw_json = raw_json,
        ver = env!("CARGO_PKG_VERSION"),
        hash_prefix = &r.content_hash[..16.min(r.content_hash.len())],
        case_id = r.case_id.as_deref().unwrap_or("(kein Fall)"),
    )
}

// ── Section renderers ─────────────────────────────────────────────────────────

fn render_timeline(entries: &[TimelineEntry]) -> String {
    if entries.is_empty() {
        return "<p style=\"color:#8b949e\">Keine Einträge.</p>".into();
    }
    let items: String = entries
        .iter()
        .map(|e| {
            let kind_color = match e.kind.as_str() {
                "threat" => "#f85149",
                "osint" => "#58a6ff",
                "countermeasure" => "#3fb950",
                _ => "#8b949e",
            };
            format!(
                "<li><span class=\"ts\">{}</span>
             <span style=\"display:inline-block;width:10px;height:10px;border-radius:50%;\
               background:{};margin:0 8px -1px\"></span>
             <b style=\"color:{}\">[{}]</b> {}</li>",
                e.ts.format("%Y-%m-%d %H:%M:%S"),
                kind_color,
                kind_color,
                html_escape(&e.kind.to_uppercase()),
                html_escape(&e.description),
            )
        })
        .collect();
    format!("<ul class=\"timeline\">{items}</ul>")
}

fn render_events(r: &EvidenceReport) -> String {
    if r.threat_events.is_empty() {
        return "<p style=\"color:#8b949e\">Keine Ereignisse.</p>".into();
    }
    let rows: String = r
        .threat_events
        .iter()
        .map(|v| {
            let level = v["level"].as_str().unwrap_or("INFO");
            let ts = v["timestamp"].as_str().unwrap_or("—");
            let msg = v["message"].as_str().unwrap_or("—");
            let score = v["anomaly_score"].as_f64().unwrap_or(0.0);
            let id = v["id"].as_str().unwrap_or("—");
            format!(
                "<tr><td class=\"mono\" style=\"font-size:11px\">{}</td>\
             <td><span class=\"sev-{}\">{}</span></td>\
             <td>{}</td>\
             <td style=\"text-align:right\">{:.2}</td>\
             <td class=\"mono\" style=\"font-size:10px;color:#8b949e\">{}</td></tr>",
                html_escape(&ts[..19.min(ts.len())]),
                level,
                level,
                html_escape(msg),
                score,
                html_escape(&id[..8.min(id.len())]),
            )
        })
        .collect();
    format!(
        "<table><thead><tr><th>Zeitstempel</th><th>Level</th>\
         <th>Meldung</th><th style=\"text-align:right\">Score</th><th>ID</th></tr></thead>\
         <tbody>{rows}</tbody></table>"
    )
}

fn render_relays(r: &EvidenceReport) -> String {
    if r.relay_profiles.is_empty() {
        return "<p style=\"color:#8b949e\">Keine Relay-Profile vorhanden. \
                Arc-Endpunkt anklicken um OSINT zu starten.</p>"
            .into();
    }
    let rows: String = r
        .relay_profiles
        .iter()
        .map(|v| {
            let fp = v["fingerprint"].as_str().unwrap_or("—");
            let nick = v["nickname"].as_str().unwrap_or("—");
            let ip = v["ip"].as_str().unwrap_or("—");
            let country = v["geo_country"]
                .as_str()
                .unwrap_or(v["country"].as_str().unwrap_or("—"));
            let isp = v["geo_isp"].as_str().unwrap_or("—");
            let asn = v["asn"].as_str().unwrap_or("—");
            let flags: Vec<&str> = v["flags"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            let flags_html: String = flags
                .iter()
                .map(|f| format!("<span class=\"flag {}\">{f}</span>", f))
                .collect();
            let bw = v["bandwidth_rate"].as_u64().unwrap_or(0);
            let bw_str = if bw >= 1_000_000 {
                format!("{:.1} MB/s", bw as f64 / 1e6)
            } else {
                format!("{:.0} KB/s", bw as f64 / 1e3)
            };
            format!(
                "<tr><td class=\"mono\" style=\"font-size:11px\">{}</td>\
             <td><b>{}</b></td><td class=\"mono\">{}</td><td>{}</td>\
             <td style=\"font-size:12px\">{}</td><td>{}</td>\
             <td style=\"font-size:12px\">{}</td><td>{}</td></tr>",
                html_escape(&fp[..16.min(fp.len())]),
                html_escape(nick),
                html_escape(ip),
                html_escape(country),
                flags_html,
                html_escape(isp),
                html_escape(asn),
                bw_str,
            )
        })
        .collect();
    format!(
        "<table><thead><tr><th>Fingerprint (16)</th><th>Nickname</th><th>IP</th>\
         <th>Land</th><th>Flags</th><th>ISP</th><th>ASN</th><th>BW</th></tr></thead>\
         <tbody>{rows}</tbody></table>"
    )
}

fn render_iocs(iocs: &[Ioc]) -> String {
    if iocs.is_empty() {
        return "<p style=\"color:#8b949e\">Keine IOCs extrahiert.</p>".into();
    }
    let rows: String = iocs
        .iter()
        .map(|ioc| {
            let kind_class = format!("ioc-{}", ioc.kind);
            format!(
                "<tr><td><span class=\"{}\">{}</span></td>\
             <td class=\"mono\">{}</td>\
             <td>{}</td>\
             <td class=\"sev-{}\">{}</td>\
             <td class=\"mono\" style=\"font-size:11px\">{}</td></tr>",
                kind_class,
                html_escape(&ioc.kind.to_uppercase()),
                html_escape(&ioc.value),
                html_escape(&ioc.context),
                ioc.severity,
                html_escape(&ioc.severity),
                ioc.first_seen.format("%Y-%m-%d %H:%M:%S"),
            )
        })
        .collect();
    format!(
        "<table><thead><tr><th>Typ</th><th>Wert</th><th>Kontext</th>\
         <th>Schwere</th><th>Erstmals gesehen</th></tr></thead>\
         <tbody>{rows}</tbody></table>"
    )
}

fn render_countermeasures(r: &EvidenceReport) -> String {
    if r.countermeasures.is_empty() {
        return "<p style=\"color:#8b949e\">Keine Gegenmassnahmen dokumentiert.</p>".into();
    }
    let labels = [
        "ExcludeNodes (arti.toml / torrc)",
        "iptables DROP-Regel",
        "nftables-Regelwerk",
        "bad-relays E-Mail-Entwurf",
        "AbuseIPDB curl-Befehl",
        "ISP Abuse E-Mail-Entwurf",
    ];
    r.countermeasures
        .iter()
        .enumerate()
        .map(|(i, text)| {
            let title = labels.get(i).copied().unwrap_or("Gegenmassnahme");
            format!(
                "<div class=\"cm-block\">\
               <div class=\"cm-title\">▶ {title}</div>\
               <pre class=\"cm-body\">{}</pre>\
             </div>",
                html_escape(text)
            )
        })
        .collect()
}

fn render_integrity(r: &EvidenceReport) -> String {
    let chain_status = if r.prev_hash.is_some() {
        "<span class=\"chain-ok\">✓ Kettenelement (Hash-Kette lückenlos prüfbar)</span>"
    } else {
        "<span class=\"chain-warn\">○ Erster Bericht in dieser Kette</span>"
    };

    format!(
        "<div class=\"integrity\">\
           <div class=\"row\"><div class=\"lbl\">Report-ID</div>\
             <div class=\"val\">{id}</div></div>\
           <div class=\"row\"><div class=\"lbl\">Content-Hash (SHA-256)</div>\
             <div class=\"val\">{hash}</div></div>\
           <div class=\"row\"><div class=\"lbl\">HMAC-SHA256</div>\
             <div class=\"val\">{hmac}</div></div>\
           <div class=\"row\"><div class=\"lbl\">Vorheriger Hash</div>\
             <div class=\"val\">{prev}</div></div>\
           <div class=\"row\"><div class=\"lbl\">Hash-Kette</div>\
             <div class=\"val\">{chain}</div></div>\
           <div class=\"row\"><div class=\"lbl\">System</div>\
             <div class=\"val\">{os} · {host}</div></div>\
           <p style=\"margin-top:12px;font-size:12px;color:#8b949e\">\
             Zur Verifikation: <code>echo -n &quot;{hash}&quot; | openssl dgst -sha256 -hmac YOUR_KEY</code>\
             (Signing-Key liegt in <code>evidence.key</code>)\
           </p>\
         </div>",
        id   = r.id,
        hash = r.content_hash,
        hmac = r.hmac,
        prev = r.prev_hash.as_deref().unwrap_or("—"),
        chain = chain_status,
        os   = html_escape(&r.system_info.os),
        host = html_escape(r.system_info.hostname.as_deref().unwrap_or("unknown")),
    )
}

// ── Utility ───────────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
