//! Axum HTTP + WebSocket + Prometheus dashboard API.
//!
//! | Method | Path                    | Description                   |
//! |--------|-------------------------|-------------------------------|
//! | GET    | /                       | Interactive HTML dashboard    |
//! | GET    | /health                 | "ok"                          |
//! | GET    | /api/metrics            | MetricsSnapshot + arti_status |
//! | GET    | /api/events             | Last 100 ThreatEvents         |
//! | GET    | /api/relays/suspicious  | Relays with score ≥ 0.5       |
//! | POST   | /api/relay/:fp/flag     | Manually flag a relay         |
//! | DELETE | /api/ip/:ip/unblock     | Remove IP from blocklist      |
//! | GET    | /metrics                | Prometheus text exposition    |
//! | GET    | /ws                     | WebSocket live event stream   |

use crate::{
    event::ThreatEvent,
    storage::ReputationStore,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info};

use super::{metrics, SharedState};

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    pub shared:   Arc<RwLock<SharedState>>,
    pub store:    Arc<ReputationStore>,
    pub event_tx: broadcast::Sender<ThreatEvent>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub async fn serve(state: ApiState, addr: SocketAddr) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/",                      get(root))
        .route("/health",                get(health))
        .route("/api/metrics",           get(get_metrics))
        .route("/api/events",            get(get_events))
        .route("/api/relays/suspicious", get(get_suspicious))
        .route("/api/relay/:fp/flag",    post(flag_relay))
        .route("/api/ip/:ip/unblock",    delete(unblock_ip))
        .route("/metrics",               get(prometheus_metrics))
        .route("/ws",                    get(ws_handler))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> &'static str { "ok" }

async fn root() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
}

async fn get_metrics(State(s): State<ApiState>) -> impl IntoResponse {
    let state = s.shared.read().await;
    let mut json = serde_json::to_value(&state.metrics).unwrap_or_default();
    if let serde_json::Value::Object(ref mut map) = json {
        map.insert(
            "arti_status".into(),
            serde_json::Value::String(state.arti_status.clone()),
        );
    }
    Json(json)
}

async fn get_events(State(s): State<ApiState>) -> Json<Vec<EventDto>> {
    let state = s.shared.read().await;
    Json(
        state
            .recent_events
            .iter()
            .take(100)
            .map(|e| EventDto {
                id:            e.id.to_string(),
                timestamp:     e.timestamp.to_rfc3339(),
                level:         e.level.to_string(),
                message:       e.message.clone(),
                anomaly_score: e.anomaly_score,
                mitigations:   e.suggested_mitigations.clone(),
            })
            .collect(),
    )
}

async fn get_suspicious(State(s): State<ApiState>) -> impl IntoResponse {
    match s.store.suspicious_relays(0.5) {
        Ok(relays) => {
            let body: Vec<_> = relays
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "fingerprint":   r.fingerprint,
                        "score":         r.score,
                        "seen_circuits": r.seen_circuits,
                        "flags":         r.flags,
                        "asn":           r.asn,
                        "country":       r.country,
                        "last_seen":     r.last_seen,
                    })
                })
                .collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct FlagBody {
    flag: String,
}

async fn flag_relay(
    State(s): State<ApiState>,
    Path(fp): Path<String>,
    Json(body): Json<FlagBody>,
) -> impl IntoResponse {
    match s.store.add_flag(&fp, &body.flag) {
        Ok(_)  => (StatusCode::OK, "flagged").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn unblock_ip(State(s): State<ApiState>, Path(ip): Path<String>) -> impl IntoResponse {
    match s.store.unblock_ip(&ip) {
        Ok(_)  => {
            info!(ip, "IP unblocked via API");
            (StatusCode::OK, format!("{ip} unblocked")).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn prometheus_metrics(State(s): State<ApiState>) -> Response {
    let body = metrics::render(&s.shared, &s.store).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn ws_handler(ws: WebSocketUpgrade, State(s): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| ws_loop(socket, s.event_tx.subscribe()))
}

async fn ws_loop(mut socket: WebSocket, mut rx: broadcast::Receiver<ThreatEvent>) {
    info!("WS client connected");
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(evt) => {
                    let Ok(json) = serde_json::to_string(&evt) else { continue; };
                    if socket.send(Message::Text(json)).await.is_err() { break; }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(n, "WS lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(p))) => {
                    let _ = socket.send(Message::Pong(p)).await;
                }
                _ => {}
            },
        }
    }
    debug!("WS client disconnected");
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct EventDto {
    id:            String,
    timestamp:     String,
    level:         String,
    message:       String,
    anomaly_score: f64,
    mitigations:   Vec<String>,
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ArtiShield Monitor</title>
<style>
:root {
  --bg:     #0d1117; --bg2: #161b22; --bg3: #21262d;
  --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
  --green:  #3fb950; --red: #f85149; --amber: #d29922;
  --blue:   #388bfd; --teal: #39d353;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text);
       font-family: 'Cascadia Code','Fira Mono',monospace; font-size: 13px; }

header {
  background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: 12px 20px; display: flex; align-items: center; gap: 12px;
}
header h1 { font-size: 16px; font-weight: 600; color: #fff; }
header p  { font-size: 11px; color: var(--muted); }

.status-pill {
  margin-left: auto; padding: 3px 10px; border-radius: 20px;
  font-size: 10px; font-weight: 600; display: flex; align-items: center; gap: 5px;
}
.dot { width: 7px; height: 7px; border-radius: 50%; }
.pill-ok  { background:#0d2e1a; color:var(--green); border:1px solid #1a4a2a; }
.pill-err { background:#2e0d0d; color:var(--red);   border:1px solid #4a1a1a; }

main { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 52px); }

.sidebar { background:var(--bg2); border-right:1px solid var(--border);
           padding:16px; display:flex; flex-direction:column; gap:14px; }

.metric-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.metric-card { background:var(--bg3); border:1px solid var(--border);
               border-radius:6px; padding:10px; }
.metric-label { font-size:10px; color:var(--muted); text-transform:uppercase;
                letter-spacing:.06em; margin-bottom:3px; }
.metric-value { font-size:22px; font-weight:700; line-height:1; }
.metric-sub   { font-size:10px; color:var(--muted); margin-top:2px; }

.section-title { font-size:9px; text-transform:uppercase; letter-spacing:.1em;
                 color:var(--muted); margin-bottom:6px; padding-bottom:4px;
                 border-bottom:1px solid var(--border); }

.arti-box { padding:8px 10px; border-radius:6px; font-size:11px; }
.arti-online  { background:#0d2e1a; color:var(--green); }
.arti-connect { background:#2e1a0d; color:var(--amber); }
.arti-noarti  { background:var(--bg3); color:var(--muted); }
.arti-error   { background:#2e0d0d; color:var(--red); }

.gauge-wrap  { display:flex; align-items:center; gap:8px; }
.gauge-track { flex:1; height:6px; background:var(--bg3); border-radius:3px; overflow:hidden; }
.gauge-fill  { height:100%; border-radius:3px; transition:width .4s,background .4s; }

.content { padding:14px; display:flex; flex-direction:column; gap:12px; }
.panel   { background:var(--bg2); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.panel-header { padding:9px 14px; font-size:11px; font-weight:600;
                background:var(--bg3); border-bottom:1px solid var(--border);
                display:flex; align-items:center; justify-content:space-between; }

.event-log { max-height:260px; overflow-y:auto; }
.ev-entry  { display:flex; gap:8px; padding:5px 14px;
             border-bottom:1px solid var(--bg3); align-items:flex-start; }
.ev-entry:last-child { border:none; }
.ev-time  { color:var(--muted); flex-shrink:0; font-size:11px; width:76px; }
.ev-lvl   { flex-shrink:0; padding:1px 6px; border-radius:3px;
            font-size:9px; font-weight:700; }
.ev-CRITICAL { background:#2e0d0d; color:var(--red); }
.ev-HIGH     { background:#2e1a0d; color:var(--amber); }
.ev-MEDIUM   { background:#1a1a0d; color:#cccc44; }
.ev-LOW      { background:#0d1a2e; color:var(--blue); }
.ev-INFO     { background:#0d1a0d; color:var(--green); }
.ev-msg   { flex:1; font-size:11px; }
.ev-score { flex-shrink:0; font-size:10px; color:var(--muted); }

.relay-table { width:100%; border-collapse:collapse; font-size:11px; }
.relay-table th { font-size:9px; text-transform:uppercase; letter-spacing:.08em;
                  color:var(--muted); padding:4px 10px 6px; text-align:left;
                  border-bottom:1px solid var(--border); }
.relay-table td { padding:5px 10px; border-bottom:1px solid var(--bg3); }
.relay-table tr:last-child td { border:none; }
.relay-table tr:hover td { background:var(--bg3); }
.score-bar { height:3px; border-radius:2px; margin-top:2px; }

.badge { padding:1px 6px; border-radius:3px; font-size:9px;
         background:var(--bg3); color:var(--muted); }
.btn { font-size:10px; padding:2px 8px; background:var(--bg3); color:var(--text);
       border:1px solid var(--border); border-radius:3px; cursor:pointer; }
.btn:hover { background:var(--border); }
.empty { color:var(--muted); font-size:11px; padding:12px 0; text-align:center; }
::-webkit-scrollbar { width:4px; }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
</style>
</head>
<body>
<header>
  <span style="font-size:22px">🧅</span>
  <div><h1>ArtiShield</h1><p>Tor / arti threat monitor</p></div>
  <div class="status-pill pill-ok" id="ws-pill">
    <div class="dot" style="background:var(--green)" id="ws-dot"></div>
    <span id="ws-label">CONNECTING</span>
  </div>
</header>

<main>
  <div class="sidebar">
    <div>
      <div class="section-title">Live Metriken</div>
      <div class="metric-grid">
        <div class="metric-card">
          <div class="metric-label">Anomalie</div>
          <div class="metric-value" id="m-score" style="color:var(--green)">0.000</div>
          <div class="metric-sub">Score [0–1]</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Geblockt</div>
          <div class="metric-value" id="m-blocked" style="color:var(--amber)">0</div>
          <div class="metric-sub">IPs</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Events</div>
          <div class="metric-value" id="m-events" style="color:var(--blue)">0</div>
          <div class="metric-sub">letzte 60 s</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Circuits</div>
          <div class="metric-value" id="m-circuits" style="color:var(--teal)">—</div>
          <div class="metric-sub">aktiv</div>
        </div>
      </div>
    </div>

    <div>
      <div class="section-title">Anomalie-Score</div>
      <div class="gauge-wrap">
        <div class="gauge-track">
          <div class="gauge-fill" id="gauge" style="width:0%;background:var(--green)"></div>
        </div>
        <span id="gauge-pct" style="font-size:11px;color:var(--muted);min-width:30px">0%</span>
      </div>
    </div>

    <div>
      <div class="section-title">arti Status</div>
      <div id="arti-box" class="arti-box arti-noarti">◌ Initialisiere…</div>
    </div>

    <div>
      <div class="section-title">Threat Level</div>
      <span id="threat-level" class="ev-lvl ev-INFO" style="font-size:11px;padding:3px 8px">INFO</span>
    </div>

    <div>
      <div class="section-title">Guard Fingerprint</div>
      <div id="guard-fp" style="font-size:10px;color:var(--muted);word-break:break-all">—</div>
    </div>
  </div>

  <div class="content">
    <div class="panel">
      <div class="panel-header">
        <span>Event Log</span>
        <span id="ev-count" class="badge">0 events</span>
      </div>
      <div class="event-log" id="ev-log">
        <div class="empty">Warte auf Events…</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span>Verdächtige Relays</span>
        <button class="btn" onclick="loadRelays()">Aktualisieren</button>
      </div>
      <table class="relay-table">
        <thead>
          <tr>
            <th>Fingerprint</th><th>Score</th><th>Circuits</th>
            <th>Flags</th><th>ASN</th><th>Land</th>
          </tr>
        </thead>
        <tbody id="relay-tbody">
          <tr><td colspan="6" class="empty">Lade…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</main>

<script>
let events = [];
let ws;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen  = () => setWS(true);
  ws.onclose = () => { setWS(false); setTimeout(connectWS, 3000); };
  ws.onerror = () => setWS(false);
  ws.onmessage = e => { try { addEvent(JSON.parse(e.data)); } catch(_) {} };
}

function setWS(ok) {
  const pill  = document.getElementById('ws-pill');
  const dot   = document.getElementById('ws-dot');
  const label = document.getElementById('ws-label');
  pill.className = ok ? 'status-pill pill-ok' : 'status-pill pill-err';
  dot.style.background = ok ? 'var(--green)' : 'var(--red)';
  label.textContent    = ok ? 'LIVE' : 'GETRENNT';
}

function addEvent(evt) {
  events.unshift(evt);
  if (events.length > 200) events.pop();
  renderEvents();
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderEvents() {
  const log = document.getElementById('ev-log');
  document.getElementById('ev-count').textContent = `${events.length} events`;
  if (!events.length) { log.innerHTML='<div class="empty">Keine Events</div>'; return; }
  log.innerHTML = events.slice(0,100).map(e => {
    const ts  = new Date(e.timestamp).toLocaleTimeString('de-DE');
    const lvl = e.level || 'INFO';
    const sc  = Math.round((e.anomaly_score||0)*100);
    return `<div class="ev-entry">
      <span class="ev-time">${ts}</span>
      <span class="ev-lvl ev-${lvl}">${lvl}</span>
      <span class="ev-msg">${esc(e.message)}</span>
      <span class="ev-score">${sc}%</span>
    </div>`;
  }).join('');
}

async function pollMetrics() {
  try {
    const m = await fetch('/api/metrics').then(r=>r.json());
    const score = m.anomaly_score || 0;
    const pct   = Math.round(score*100);
    const color = score>.7?'var(--red)':score>.4?'var(--amber)':'var(--green)';

    document.getElementById('m-score').textContent   = score.toFixed(3);
    document.getElementById('m-score').style.color   = color;
    document.getElementById('m-blocked').textContent = m.blocked_ips||0;
    document.getElementById('m-events').textContent  = m.events_last_minute||0;
    document.getElementById('m-circuits').textContent= m.active_circuits>0?m.active_circuits:'—';
    document.getElementById('gauge').style.width      = `${pct}%`;
    document.getElementById('gauge').style.background = color;
    document.getElementById('gauge-pct').textContent  = `${pct}%`;
    document.getElementById('guard-fp').textContent   = m.guard_fingerprint||'—';

    const lvl  = m.threat_level||'INFO';
    const tlEl = document.getElementById('threat-level');
    tlEl.textContent = lvl; tlEl.className = `ev-lvl ev-${lvl}`;

    const as_  = m.arti_status||'';
    const box  = document.getElementById('arti-box');
    if (as_==='online')           { box.className='arti-box arti-online';  box.textContent='● arti online'; }
    else if (as_==='connecting')  { box.className='arti-box arti-connect'; box.textContent='◌ Verbinde mit Tor…'; }
    else if (as_==='no-arti')     { box.className='arti-box arti-noarti';  box.textContent='○ Kein arti (SOCKS-Modus)'; }
    else if (as_.startsWith('error')){ box.className='arti-box arti-error'; box.textContent='✕ '+as_; }
    else                          { box.className='arti-box arti-noarti';  box.textContent='◌ '+as_; }
  } catch(_) {}
}

async function loadRelays() {
  try {
    const rs = await fetch('/api/relays/suspicious').then(r=>r.json());
    const tb = document.getElementById('relay-tbody');
    if (!rs||!rs.length) {
      tb.innerHTML='<tr><td colspan="6" class="empty">Keine verdächtigen Relays</td></tr>'; return;
    }
    tb.innerHTML = rs.map(r => {
      const sc = r.score||0;
      const c  = sc>.7?'var(--red)':sc>.4?'var(--amber)':'var(--green)';
      return `<tr>
        <td style="font-family:monospace;font-size:10px">${esc(r.fingerprint||'—')}</td>
        <td><span style="color:${c}">${sc.toFixed(3)}</span>
            <div class="score-bar" style="width:${Math.round(sc*100)}%;background:${c}"></div></td>
        <td>${r.seen_circuits||0}</td>
        <td><span class="badge">${esc(r.flags||'—')}</span></td>
        <td>${r.asn||'—'}</td>
        <td>${esc(r.country||'—')}</td>
      </tr>`;
    }).join('');
  } catch(_) {}
}

async function loadEvents() {
  try {
    events = await fetch('/api/events').then(r=>r.json());
    renderEvents();
  } catch(_) {}
}

connectWS();
loadEvents();
loadRelays();
pollMetrics();
setInterval(pollMetrics, 5000);
setInterval(loadRelays, 30000);
</script>
</body>
</html>"#;
