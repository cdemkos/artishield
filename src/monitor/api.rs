//! Axum HTTP + WebSocket + Prometheus dashboard API.
//!
//! | Method | Path                    | Description                             |
//! |--------|-------------------------|-----------------------------------------|
//! | GET    | /                       | Interactive HTML dashboard (3D globe)   |
//! | GET    | /health                 | "ok"                                    |
//! | GET    | /api/metrics            | MetricsSnapshot + arti_status           |
//! | GET    | /api/events             | Last 100 ThreatEvents                   |
//! | GET    | /api/relays/suspicious  | Relays with score ≥ 0.5                 |
//! | POST   | /api/relay/:fp/flag     | Manually flag a relay (auth required)   |
//! | DELETE | /api/ip/:ip/unblock     | Remove IP from blocklist (auth required)|
//! | GET    | /metrics                | Prometheus text exposition              |
//! | GET    | /ws                     | WebSocket live event stream             |
//!
//! ## Write-endpoint authorisation
//!
//! If `api_token` is set in the config, POST/DELETE require:
//!   `Authorization: Bearer <token>`
//!
//! If `api_token` is **not** set, write endpoints are restricted to loopback
//! (127.0.0.1 / ::1) only — safe for local installs without extra config.

use crate::{event::ThreatEvent, storage::ReputationStore};
use axum::http::Method;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Instant,
};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info};

use super::{metrics, SharedState};

// ── State ─────────────────────────────────────────────────────────────────────

/// Maximum concurrent WebSocket connections accepted by this server.
const MAX_WS_CONNECTIONS: usize = 50;
/// Maximum write-endpoint (POST/DELETE) requests per IP per 60 s window.
const WRITE_RATE_LIMIT: u32 = 60;

/// Axum application state injected into every HTTP handler.
#[derive(Clone)]
pub struct ApiState {
    /// Shared runtime state (metrics, recent events, arti status).
    pub shared: Arc<RwLock<SharedState>>,
    /// Reputation store for relay and IP data.
    pub store: Arc<ReputationStore>,
    /// Event bus sender — WebSocket clients subscribe to its receiver.
    pub event_tx: broadcast::Sender<ThreatEvent>,
    /// Optional Bearer token required for write endpoints (POST/DELETE).
    /// `None` → restrict to loopback only.
    pub api_token: Option<String>,
    /// Live WebSocket connection counter.
    pub ws_connections: Arc<AtomicUsize>,
    /// Per-IP write-endpoint rate limiter: IP → (count, window_start).
    pub write_limiter: Arc<StdMutex<HashMap<std::net::IpAddr, (u32, Instant)>>>,
}

// ── Auth helper ───────────────────────────────────────────────────────────────

/// Returns `true` if the request is authorised to call write endpoints.
///
/// - Token configured → check `Authorization: Bearer <token>` header.
/// - No token          → allow loopback addresses only.
fn is_authorised(state: &ApiState, peer: &SocketAddr, headers: &HeaderMap) -> bool {
    match &state.api_token {
        Some(token) => headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| constant_time_eq(t.as_bytes(), token.as_bytes()))
            .unwrap_or(false),
        None => peer.ip().is_loopback(),
    }
}

/// Constant-time byte-slice equality to prevent timing-based token oracle attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Returns `true` if the IP has not yet exceeded [`WRITE_RATE_LIMIT`] requests
/// in the current 60-second window.  Advances the counter on each call.
fn check_write_rate(
    limiter: &StdMutex<HashMap<std::net::IpAddr, (u32, Instant)>>,
    ip: std::net::IpAddr,
) -> bool {
    let mut map = limiter.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let entry = map.entry(ip).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= 60 {
        *entry = (1, now);
        true
    } else if entry.0 < WRITE_RATE_LIMIT {
        entry.0 += 1;
        true
    } else {
        false
    }
}

/// Axum middleware that injects security headers into every response.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "X-Frame-Options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.insert(
        "X-Content-Type-Options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "Referrer-Policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "X-Permitted-Cross-Domain-Policies",
        axum::http::HeaderValue::from_static("none"),
    );
    h.insert(
        "Content-Security-Policy",
        axum::http::HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; \
             connect-src 'self' ws: wss:; \
             style-src 'unsafe-inline'",
        ),
    );
    resp
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Bind the Axum HTTP server to `addr` and serve the dashboard until the process exits.
pub async fn serve(state: ApiState, addr: SocketAddr) -> anyhow::Result<()> {
    // GET endpoints allow cross-origin access (monitoring dashboards, Prometheus scrapers).
    // POST / DELETE are handled in-handler: either token-gated or loopback-only.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/api/metrics", get(get_metrics))
        .route("/api/events", get(get_events))
        .route("/api/relays/suspicious", get(get_suspicious))
        .route("/api/relay/:fp/flag", post(flag_relay))
        .route("/api/ip/:ip/unblock", delete(unblock_ip))
        .route("/metrics", get(prometheus_metrics))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // into_make_service_with_connect_info provides ConnectInfo<SocketAddr> to handlers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

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
                id: e.id.to_string(),
                timestamp: e.timestamp.to_rfc3339(),
                level: e.level.to_string(),
                message: e.message.clone(),
                anomaly_score: e.anomaly_score,
                mitigations: e.suggested_mitigations.clone(),
                kind: serde_json::to_value(&e.kind).unwrap_or_default(),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(fp): Path<String>,
    Json(body): Json<FlagBody>,
) -> impl IntoResponse {
    if !is_authorised(&s, &peer, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            "Unauthorized — set Authorization: Bearer <token> or use loopback",
        )
            .into_response();
    }
    if !check_write_rate(&s.write_limiter, peer.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }
    if body.flag.is_empty()
        || body.flag.len() > 64
        || body.flag.contains(',')
        || body.flag.contains(char::is_whitespace)
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "flag must be 1–64 characters with no commas or whitespace",
        )
            .into_response();
    }
    if !s.store.relay_exists(&fp) {
        return (
            StatusCode::NOT_FOUND,
            format!("relay {fp} not in reputation store"),
        )
            .into_response();
    }
    match s.store.add_flag(&fp, &body.flag) {
        Ok(_) => {
            info!(peer = %peer, fp = %fp, flag = %body.flag, "Audit: relay flagged via API");
            (StatusCode::OK, "flagged").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn unblock_ip(
    State(s): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if !is_authorised(&s, &peer, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            "Unauthorized — set Authorization: Bearer <token> or use loopback",
        )
            .into_response();
    }
    if !check_write_rate(&s.write_limiter, peer.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }
    match s.store.unblock_ip(&ip) {
        Ok(_) => {
            info!(peer = %peer, ip = %ip, "Audit: IP unblocked via API");
            (StatusCode::OK, format!("{ip} unblocked")).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn prometheus_metrics(
    State(s): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // Require Bearer auth if a token is configured (Prometheus scraper should send it).
    if s.api_token.is_some() && !is_authorised(&s, &peer, &headers) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let body = metrics::render(&s.shared, &s.store).await;
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn ws_handler(ws: WebSocketUpgrade, State(s): State<ApiState>) -> Response {
    if s.ws_connections.load(Ordering::Relaxed) >= MAX_WS_CONNECTIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many WebSocket connections",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| ws_loop(socket, s.event_tx.subscribe(), s.ws_connections))
}

async fn ws_loop(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<ThreatEvent>,
    counter: Arc<AtomicUsize>,
) {
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    info!(connections = n, "WS client connected");
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
                Some(Ok(Message::Ping(p))) => { let _ = socket.send(Message::Pong(p)).await; }
                _ => {}
            },
        }
    }
    counter.fetch_sub(1, Ordering::Relaxed);
    debug!("WS client disconnected");
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct EventDto {
    id: String,
    timestamp: String,
    level: String,
    message: String,
    anomaly_score: f64,
    mitigations: Vec<String>,
    kind: serde_json::Value,
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
  --blue:   #388bfd; --teal: #39d353; --purple: #bc8cff;
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
           padding:16px; display:flex; flex-direction:column; gap:14px; overflow-y:auto; }

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

.content { padding:14px; display:flex; flex-direction:column; gap:12px; overflow-y:auto; }
.panel   { background:var(--bg2); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.panel-header { padding:9px 14px; font-size:11px; font-weight:600;
                background:var(--bg3); border-bottom:1px solid var(--border);
                display:flex; align-items:center; justify-content:space-between; }

/* Globe */
.globe-panel { position:relative; height:420px; background:#030810;
               border:1px solid var(--border); border-radius:8px; overflow:hidden; }
#globe        { width:100%; height:100%; display:block; cursor:grab; }
#globe:active { cursor:grabbing; }
.globe-legend { position:absolute; bottom:10px; left:14px; display:flex; gap:10px;
                font-size:9px; color:var(--muted); }
.globe-legend span { display:flex; align-items:center; gap:4px; }
.globe-legend .dot { width:6px; height:6px; border-radius:50%; }
#globe-fallback { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%);
                  text-align:center; color:var(--muted); font-size:12px; line-height:1.8; }
.globe-overlay { position:absolute; top:10px; right:14px; font-size:10px;
                 color:rgba(100,150,200,.7); pointer-events:none; }

/* Event log */
.event-log { max-height:260px; overflow-y:auto; }
.ev-entry  { display:flex; gap:8px; padding:5px 14px;
             border-bottom:1px solid var(--bg3); align-items:flex-start; }
.ev-entry:last-child { border:none; }
.ev-time  { color:var(--muted); flex-shrink:0; font-size:11px; width:76px; }
.ev-lvl   { flex-shrink:0; padding:1px 6px; border-radius:3px; font-size:9px; font-weight:700; }
.ev-CRITICAL { background:#2e0d0d; color:var(--red); }
.ev-HIGH     { background:#2e1a0d; color:var(--amber); }
.ev-MEDIUM   { background:#1a1a0d; color:#cccc44; }
.ev-LOW      { background:#0d1a2e; color:var(--blue); }
.ev-INFO     { background:#0d1a0d; color:var(--green); }
.ev-msg   { flex:1; font-size:11px; }
.ev-score { flex-shrink:0; font-size:10px; color:var(--muted); }

/* Relay table */
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
  <span style="font-size:22px">&#x1F9C5;</span>
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
          <div class="gauge-fill" id="gauge-fill" style="width:0%;background:var(--green)"></div>
        </div>
        <span id="gauge-pct" style="font-size:11px;color:var(--muted);min-width:30px">0%</span>
      </div>
    </div>

    <div>
      <div class="section-title">arti Status</div>
      <div id="arti-box" class="arti-box arti-noarti">&#9676; Initialisiere&hellip;</div>
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

    <!-- 3D Globe -->
    <div class="globe-panel">
      <canvas id="globe"></canvas>
      <div id="globe-fallback" style="display:none">
        <div style="font-size:24px;margin-bottom:8px">&#x1F310;</div>
        3D Globe nicht verf&uuml;gbar<br>
        <span style="font-size:10px">(Three.js konnte nicht geladen werden)</span>
      </div>
      <div class="globe-legend">
        <span><span class="dot" style="background:#f85149"></span>Critical</span>
        <span><span class="dot" style="background:#d29922"></span>High</span>
        <span><span class="dot" style="background:#cccc44"></span>Medium</span>
        <span><span class="dot" style="background:#388bfd"></span>Relay</span>
      </div>
      <div class="globe-overlay" id="globe-arc-count"></div>
    </div>

    <!-- Event Log -->
    <div class="panel">
      <div class="panel-header">
        <span>Event Log</span>
        <span id="ev-count" class="badge">0 events</span>
      </div>
      <div class="event-log" id="ev-log">
        <div class="empty">Warte auf Events&hellip;</div>
      </div>
    </div>

    <!-- Suspicious Relays -->
    <div class="panel">
      <div class="panel-header">
        <span>Verd&auml;chtige Relays</span>
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
          <tr><td colspan="6" class="empty">Lade&hellip;</td></tr>
        </tbody>
      </table>
    </div>

  </div>
</main>

<!-- Three.js — loaded from CDN; globe degrades gracefully if offline -->
<script src="https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js"></script>
<script>
'use strict';

// ── Country centroids (ISO-3166-1 alpha-2 → [lat, lon]) ────────────────────
const CC = {
  US:[37.1,-95.7], DE:[51.2,10.5], NL:[52.1,5.3],  FR:[46.2,2.2],   GB:[55.4,-3.4],
  RU:[61.5,105.3], SE:[60.1,18.6], CH:[46.8,8.2],  CA:[56.1,-106.3],AU:[-25.3,133.8],
  JP:[36.2,138.3], SG:[1.4,103.8], HK:[22.4,114.1],TW:[23.7,121.0], KR:[35.9,127.8],
  CN:[35.9,104.2], UA:[48.4,31.2], PL:[51.9,19.2], CZ:[49.8,15.5],  AT:[47.5,14.6],
  BE:[50.5,4.5],   FI:[62.0,26.0], NO:[60.5,8.5],  DK:[56.3,9.5],   IT:[41.9,12.6],
  ES:[40.5,-4.0],  PT:[39.4,-8.2], LU:[49.8,6.1],  IS:[65.0,-19.0], LT:[55.2,23.9],
  LV:[56.9,24.6],  EE:[58.6,25.0], BR:[-14.2,-51.9],AR:[-38.4,-63.6],MX:[23.6,-102.6],
  ZA:[-30.6,22.9], IN:[20.6,78.9], IL:[31.0,34.9], TR:[39.0,35.2],  HU:[47.2,19.5],
  BG:[42.7,25.5],  RO:[45.9,25.0], RS:[44.0,21.0], HR:[45.1,15.2],  SK:[48.7,19.7],
  MD:[47.4,28.4],  KZ:[48.0,66.9], IR:[32.4,53.7], NG:[9.1,8.7],    EG:[26.8,30.8],
  ZZ:[20.0,0.0],   // fallback: equator
};

// ── Globe state ────────────────────────────────────────────────────────────
let globeScene, globeCamera, globeRenderer, globeMesh, dotGroup;
let globeReady = false;
let isDragging = false, prevMouse = {x:0, y:0};
const arcs = [];        // {line, born, life}
const relayMap = {};    // fingerprint → {lat, lon}

function latLonToXYZ(lat, lon, r) {
  r = r || 1.0;
  const phi   = (90 - lat) * Math.PI / 180;
  const theta = (lon + 180) * Math.PI / 180;
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
     r * Math.cos(phi),
     r * Math.sin(phi) * Math.sin(theta)
  );
}

function randLatLon() {
  return [Math.random()*140 - 70, Math.random()*360 - 180];
}

function levelColor(lvl) {
  switch ((lvl||'').toUpperCase()) {
    case 'CRITICAL': return 0xf85149;
    case 'HIGH':     return 0xd29922;
    case 'MEDIUM':   return 0xcccc44;
    case 'LOW':      return 0x388bfd;
    default:         return 0x39d353;
  }
}

function buildGraticule() {
  const pts = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    for (let lat = -88; lat < 88; lat += 3) {
      pts.push(latLonToXYZ(lat, lon, 1.003));
      pts.push(latLonToXYZ(lat+3, lon, 1.003));
    }
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    for (let lon = -178; lon < 180; lon += 3) {
      pts.push(latLonToXYZ(lat, lon, 1.003));
      pts.push(latLonToXYZ(lat, lon+3, 1.003));
    }
  }
  const geo = new THREE.BufferGeometry().setFromPoints(pts);
  return new THREE.LineSegments(geo,
    new THREE.LineBasicMaterial({color:0x1a3a5c, transparent:true, opacity:0.35}));
}

function buildStars() {
  const positions = [];
  for (let i = 0; i < 1200; i++) {
    const v = new THREE.Vector3(
      (Math.random()-0.5)*300,
      (Math.random()-0.5)*300,
      (Math.random()-0.5)*300
    );
    if (v.length() > 4) { positions.push(v.x, v.y, v.z); }
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  return new THREE.Points(geo,
    new THREE.PointsMaterial({color:0xffffff, size:0.4, transparent:true, opacity:0.55}));
}

function addRelayDot(lat, lon, score) {
  if (!globeReady) return;
  const pos   = latLonToXYZ(lat, lon, 1.012);
  const s     = 0.010 + score * 0.012;
  const color = score > 0.7 ? 0xf85149 : score > 0.4 ? 0xd29922 : 0x388bfd;
  const mesh  = new THREE.Mesh(
    new THREE.SphereGeometry(s, 6, 6),
    new THREE.MeshBasicMaterial({color})
  );
  mesh.position.copy(pos);
  dotGroup.add(mesh);
}

function createArc(p1, p2, color) {
  const mid = p1.clone().add(p2).normalize().multiplyScalar(1.45 + Math.random()*0.15);
  const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
  const pts   = curve.getPoints(70);
  const geo   = new THREE.BufferGeometry().setFromPoints(pts);
  return new THREE.Line(geo,
    new THREE.LineBasicMaterial({color, transparent:true, opacity:0.85}));
}

function addGlobeArc(lat1, lon1, lat2, lon2, color) {
  if (!globeReady) return;
  const p1   = latLonToXYZ(lat1, lon1, 1.012);
  const p2   = latLonToXYZ(lat2, lon2, 1.012);
  const line = createArc(p1, p2, color);
  globeScene.add(line);
  arcs.push({line, born:Date.now(), life:5000});
  const el = document.getElementById('globe-arc-count');
  if (el) el.textContent = arcs.length + ' arcs';
}

function animate() {
  requestAnimationFrame(animate);
  if (!isDragging) globeMesh.rotation.y += 0.0015;
  dotGroup.rotation.y = globeMesh.rotation.y;

  const now = Date.now();
  for (let i = arcs.length - 1; i >= 0; i--) {
    const a = arcs[i];
    const t = (now - a.born) / a.life;
    if (t >= 1) {
      globeScene.remove(a.line);
      a.line.geometry.dispose();
      a.line.material.dispose();
      arcs.splice(i, 1);
    } else {
      a.line.material.opacity = 0.85 * (1 - t * t);
    }
  }
  if (arcs.length === 0) {
    const el = document.getElementById('globe-arc-count');
    if (el) el.textContent = '';
  }
  globeRenderer.render(globeScene, globeCamera);
}

function initGlobe() {
  if (typeof THREE === 'undefined') {
    document.getElementById('globe').style.display = 'none';
    document.getElementById('globe-fallback').style.display = 'block';
    return;
  }
  const canvas = document.getElementById('globe');
  const W = canvas.clientWidth  || 800;
  const H = canvas.clientHeight || 420;

  globeScene    = new THREE.Scene();
  globeCamera   = new THREE.PerspectiveCamera(42, W/H, 0.1, 1000);
  globeCamera.position.z = 2.6;

  globeRenderer = new THREE.WebGLRenderer({canvas, antialias:true, alpha:true});
  globeRenderer.setPixelRatio(window.devicePixelRatio);
  globeRenderer.setSize(W, H);
  globeRenderer.setClearColor(0x030810, 1);

  // Stars
  globeScene.add(buildStars());

  // Atmosphere glow (back side)
  const atmo = new THREE.Mesh(
    new THREE.SphereGeometry(1.06, 64, 64),
    new THREE.MeshPhongMaterial({color:0x1a4a8a, transparent:true, opacity:0.12, side:THREE.BackSide})
  );
  globeScene.add(atmo);

  // Earth sphere
  globeMesh = new THREE.Mesh(
    new THREE.SphereGeometry(1, 64, 64),
    new THREE.MeshPhongMaterial({color:0x0d2035, shininess:8})
  );
  globeScene.add(globeMesh);

  // Ocean sheen
  globeScene.add(new THREE.Mesh(
    new THREE.SphereGeometry(1.001, 64, 64),
    new THREE.MeshPhongMaterial({color:0x113355, transparent:true, opacity:0.25})
  ));

  // Graticule
  globeScene.add(buildGraticule());

  // Dot group (relay positions)
  dotGroup = new THREE.Group();
  globeScene.add(dotGroup);

  // Lights
  globeScene.add(new THREE.AmbientLight(0x223344, 1.2));
  const sun = new THREE.PointLight(0x4488ff, 2.5, 20);
  sun.position.set(5, 3, 5);
  globeScene.add(sun);

  // Mouse drag to rotate
  canvas.addEventListener('mousedown', e => { isDragging=true; prevMouse={x:e.clientX,y:e.clientY}; });
  window.addEventListener('mouseup',   () => { isDragging=false; });
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    const dx = e.clientX - prevMouse.x;
    const dy = e.clientY - prevMouse.y;
    globeMesh.rotation.y += dx * 0.005;
    globeMesh.rotation.x += dy * 0.005;
    dotGroup.rotation.y   = globeMesh.rotation.y;
    dotGroup.rotation.x   = globeMesh.rotation.x;
    prevMouse = {x:e.clientX, y:e.clientY};
  });

  // Resize
  window.addEventListener('resize', () => {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    globeCamera.aspect = w / h;
    globeCamera.updateProjectionMatrix();
    globeRenderer.setSize(w, h);
  });

  globeReady = true;
  animate();
}

// ── Dashboard logic ────────────────────────────────────────────────────────
let events = [];
let ws;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(proto + '://' + location.host + '/ws');
  ws.onopen    = () => setWS(true);
  ws.onclose   = () => { setWS(false); setTimeout(connectWS, 3000); };
  ws.onerror   = () => setWS(false);
  ws.onmessage = e => { try { handleEvent(JSON.parse(e.data)); } catch(_) {} };
}

function setWS(ok) {
  const pill  = document.getElementById('ws-pill');
  const dot   = document.getElementById('ws-dot');
  const label = document.getElementById('ws-label');
  pill.className         = ok ? 'status-pill pill-ok' : 'status-pill pill-err';
  dot.style.background   = ok ? 'var(--green)' : 'var(--red)';
  label.textContent      = ok ? 'LIVE' : 'GETRENNT';
}

function handleEvent(evt) {
  events.unshift(evt);
  if (events.length > 200) events.pop();
  renderEvents();
  fireGlobeArc(evt);
  // Relay-Tabelle sofort aktualisieren wenn ein Sybil- oder Guard-Discovery-Event ankommt
  const kind = evt.kind || {};
  if (kind.sybil_cluster || kind.guard_discovery) {
    loadRelays();
  }
}

function fireGlobeArc(evt) {
  const color = levelColor(evt.level);
  let positions = [];

  // Extract fingerprints from event kind
  const kind = evt.kind || {};
  const fps  = (kind.sybil_cluster    && kind.sybil_cluster.affected_fps)    ||
               (kind.guard_discovery  && kind.guard_discovery.suspicious_fingerprints) ||
               [];
  fps.forEach(fp => { if (relayMap[fp]) positions.push(relayMap[fp]); });

  if (positions.length >= 2) {
    addGlobeArc(positions[0][0], positions[0][1], positions[1][0], positions[1][1], color);
  } else if (positions.length === 1) {
    // Arc from relay to a random destination
    const dest = randLatLon();
    addGlobeArc(positions[0][0], positions[0][1], dest[0], dest[1], color);
  } else {
    // Fallback: random arc for visual activity
    const a = randLatLon(), b = randLatLon();
    addGlobeArc(a[0], a[1], b[0], b[1], color);
  }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderEvents() {
  const log = document.getElementById('ev-log');
  document.getElementById('ev-count').textContent = events.length + ' events';
  if (!events.length) { log.innerHTML = '<div class="empty">Keine Events</div>'; return; }
  log.innerHTML = events.slice(0,100).map(e => {
    const ts  = new Date(e.timestamp).toLocaleTimeString('de-DE');
    const lvl = e.level || 'INFO';
    const sc  = Math.round((e.anomaly_score||0)*100);
    return '<div class="ev-entry">' +
      '<span class="ev-time">' + ts + '</span>' +
      '<span class="ev-lvl ev-' + lvl + '">' + lvl + '</span>' +
      '<span class="ev-msg">' + esc(e.message) + '</span>' +
      '<span class="ev-score">' + sc + '%</span>' +
      '</div>';
  }).join('');
}

async function pollMetrics() {
  try {
    const data = await fetch('/api/metrics').then(r => r.json());

    // Anomalie-Score
    const score = data.anomaly_score || 0;
    const scoreEl = document.getElementById('m-score');
    if (scoreEl) {
      scoreEl.textContent = score.toFixed(3);
      scoreEl.style.color = score > 0.7 ? 'var(--red)' : score > 0.4 ? 'var(--amber)' : 'var(--green)';
    }

    // Blocked IPs
    const blockedEl = document.getElementById('m-blocked');
    if (blockedEl) blockedEl.textContent = data.blocked_ips || 0;

    // Events last minute
    const evEl = document.getElementById('m-events');
    if (evEl) evEl.textContent = data.events_last_minute || 0;

    // Active circuits
    const circEl = document.getElementById('m-circuits');
    if (circEl) circEl.textContent = data.active_circuits > 0 ? data.active_circuits : '—';

    // Gauge
    const fillEl = document.getElementById('gauge-fill');
    const pctEl  = document.getElementById('gauge-pct');
    if (fillEl) {
      const pct  = Math.min(score * 100, 100);
      const gcol = score > 0.7 ? 'var(--red)' : score > 0.4 ? 'var(--amber)' : 'var(--green)';
      fillEl.style.width      = pct + '%';
      fillEl.style.background = gcol;
    }
    if (pctEl) pctEl.textContent = Math.round(score * 100) + '%';

    // arti status
    const artiEl = document.getElementById('arti-box');
    if (artiEl) {
      const st = data.arti_status || 'booting';
      if (st === 'online') {
        artiEl.className = 'arti-box arti-online';
        artiEl.textContent = '● arti online';
      } else if (st === 'connecting') {
        artiEl.className = 'arti-box arti-connect';
        artiEl.textContent = '◌ Verbinde mit Tor…';
      } else if (st === 'no-arti') {
        artiEl.className = 'arti-box arti-noarti';
        artiEl.textContent = '○ SOCKS-Modus (kein arti)';
      } else if (st.startsWith('error')) {
        artiEl.className = 'arti-box arti-error';
        artiEl.textContent = '✕ ' + st;
      } else {
        artiEl.className = 'arti-box arti-noarti';
        artiEl.textContent = '◌ Initialisiere…';
      }
    }

    // Threat level
    const lvlEl = document.getElementById('threat-level');
    if (lvlEl && data.threat_level) {
      const lvl = data.threat_level.toUpperCase ? data.threat_level.toUpperCase() : String(data.threat_level).toUpperCase();
      lvlEl.textContent = lvl;
      lvlEl.className   = 'ev-lvl ev-' + lvl;
      lvlEl.style.cssText = 'font-size:11px;padding:3px 8px';
    }

    // Guard fingerprint
    const gpEl = document.getElementById('guard-fp');
    if (gpEl) gpEl.textContent = data.guard_fingerprint || '—';

  } catch(_) { /* server may be starting up */ }
}

async function loadEvents() {
  try {
    events = await fetch('/api/events').then(r => r.json());
    renderEvents();
  } catch(_) {}
}

async function loadRelays() {
  const tb = document.getElementById('relay-tbody');
  if (!tb) return;
  try {
    const rs = await fetch('/api/relays/suspicious').then(r => r.json());
    if (!rs || !rs.length) {
      tb.innerHTML = '<tr><td colspan="6" class="empty">Keine verd&auml;chtigen Relays</td></tr>';
      return;
    }

    // Update globe relay positions
    if (globeReady) {
      dotGroup.clear();
      rs.forEach(r => {
        const cc = (r.country || 'ZZ').toUpperCase();
        const pos = CC[cc] || CC['ZZ'];
        relayMap[r.fingerprint] = pos;
        addRelayDot(pos[0], pos[1], r.score || 0);
      });
    }

    // Sort by score descending, show top 1000
    const sorted = rs.slice().sort((a,b) => (b.score||0) - (a.score||0)).slice(0, 1000);
    tb.innerHTML = sorted.map(r => {
      const sc  = r.score || 0;
      const col = sc > 0.7 ? 'var(--red)' : sc > 0.4 ? 'var(--amber)' : 'var(--green)';
      const flags = r.flags ? esc(r.flags) : '—';
      return '<tr>' +
        '<td style="font-family:monospace;font-size:10px">' + esc(r.fingerprint || '—') + '</td>' +
        '<td><span style="color:' + col + '">' + sc.toFixed(3) + '</span>' +
             '<div class="score-bar" style="width:' + Math.round(sc*100) + '%;background:' + col + '"></div></td>' +
        '<td>' + (r.seen_circuits || 0) + '</td>' +
        '<td><span class="badge">' + flags + '</span></td>' +
        '<td>' + (r.asn || '—') + '</td>' +
        '<td>' + esc(r.country || '—') + '</td>' +
        '</tr>';
    }).join('');
  } catch(_) {
    tb.innerHTML = '<tr><td colspan="6" style="color:var(--red);padding:8px 14px">Ladefehler</td></tr>';
  }
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
initGlobe();
connectWS();
loadEvents();
loadRelays();
pollMetrics();
setInterval(pollMetrics, 5000);
setInterval(loadRelays, 30000);
</script>
</body>
</html>"#;
