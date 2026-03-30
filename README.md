# ArtiShield

**Threat-monitoring and mitigation layer for [arti](https://gitlab.torproject.org/tpo/core/arti) (Tor in Rust).**

## What it does

ArtiShield runs alongside arti and detects five classes of attack in real time:

| Detector | Signal | arti API |
|---|---|---|
| `SybilDetector` | /24 or ASN clustering in the consensus | `dirmgr().events()` + `NetDir::relays()` |
| `GuardDiscoveryDetector` | Unusual guard churn between consensuses | same DirEvent stream |
| `HsEnumDetector` | HSDir subnet concentration | same DirEvent stream |
| `TimingDetector` | RTT correlation between guard and exit | SOCKS5 probe via `tokio-socks` |
| `DosDetector` | Circuit-build latency spike / SENDME burst | SOCKS5 probe via `tokio-socks` |

Each detector emits `ThreatEvent`s onto a broadcast channel. The `MitigationEngine` reacts by updating relay reputation scores in SQLite and — when `--features arti-hooks` is active and the anomaly score crosses the threshold — calling `TorClient::isolated_client()` to rotate circuits.

---

## Real arti API surface

```rust
// Requires: arti-client feature "experimental-api"
let dirmgr  = tor_client.dirmgr();                        // Arc<dyn NetDirProvider>
let nd      = dirmgr.netdir(Timeliness::Timely)?;         // Arc<NetDir>
let events  = dirmgr.events();                            // BoxStream<DirEvent>

for relay in nd.relays() {
    let fp    = relay.rsa_id();      // &RsaIdentity (20 bytes)
    let addrs = relay.addrs();       // Iterator<&SocketAddr>  (HasAddrs trait)
}

// Circuit rotation (stable public API)
let new_client = tor_client.isolated_client();
```

What is **not** yet available in arti's public API:

| Feature | Status |
|---|---|
| Per-circuit hop list (guard + middle + exit) | `ClientCirc` internals private — `check_hops()` is ready, wire it when exposed |
| Per-cell SENDME counters | Circuit reactor is internal — RTT proxy via SOCKS used instead |
| Active circuit count | No public counter — shown as `0` in MetricsSnapshot |

---

## Quick start

**Prerequisites:** Rust ≥ 1.77

```bash
git clone https://github.com/cdemkos/artishield
cd artishield

# Dashboard available immediately at http://localhost:7878/
# (no arti needed in this mode)
cargo run

# With real arti integration (arti must be running on 127.0.0.1:9150)
cargo run --features arti-hooks
```

> **Note:** arti's dependency tree is large and uses heavy proc-macros.
> If `cargo` crashes with a SIGSEGV, the `.cargo/config.toml` in this repo
> sets `RUST_MIN_STACK=67108864` (64 MB) automatically.
> If it still crashes, try: `RUST_MIN_STACK=134217728 cargo run`

---

## Configuration

ArtiShield reads `artishield.toml` from the current directory at startup.
All fields have sensible defaults; the file is optional.

```toml
socks_addr = "127.0.0.1:9150"  # arti SOCKS5 port
api_addr   = "0.0.0.0:7878"    # dashboard + API listen address
db_path    = "artishield.db"   # SQLite reputation database
log_level  = "artishield=info,warn"

# Optional: MaxMind GeoLite2-ASN for ASN-based Sybil detection
# geoip_db = "/etc/artishield/GeoLite2-ASN.mmdb"

[detectors]
timing_correlation_threshold = 0.6  # Pearson |r| threshold
alert_threshold              = 0.70 # score that triggers mitigations

[mitigations]
auto_circuit_rotate = false  # call isolated_client() on alert
guard_pin           = true   # log alert on unexpected guard change
```

---

## API

| Method | Path | Description |
|---|---|---|
| GET | `/` | Interactive HTML dashboard |
| GET | `/health` | `"ok"` |
| GET | `/api/metrics` | MetricsSnapshot JSON + `arti_status` |
| GET | `/api/events` | Last 100 ThreatEvents |
| GET | `/api/relays/suspicious` | Relays with score ≥ 0.5 |
| POST | `/api/relay/:fp/flag` | Manually flag a relay |
| DELETE | `/api/ip/:ip/unblock` | Remove IP from blocklist |
| GET | `/metrics` | Prometheus text exposition |
| GET | `/ws` | WebSocket live ThreatEvent stream |

---

## CLI

```bash
artishield                             # run (reads artishield.toml)
artishield --config /path/to/cfg.toml # custom config
artishield check-config                # validate config and exit
artishield dump-events --limit 50      # print stored events
artishield dump-relays --threshold 0.7 # print suspicious relays
```

---

## Tests

```bash
# Unit + integration tests (no arti, no network required)
cargo test

# With arti integration compiled in
cargo test --features arti-hooks
```

---

## Deployment

### systemd
```bash
sudo cp deploy/artishield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now artishield
```

### Docker Compose
```bash
docker compose -f deploy/docker-compose.yml up -d
```

Includes Prometheus and Grafana. See `deploy/docker-compose.yml` for
instructions on connecting to a running arti instance.

---

## Extending

Wire in circuit hop inspection once arti stabilises `ClientCirc::path()`:

```rust
let hops = circuit.path_hops().map(|h| CircuitHop {
    fingerprint: h.rsa_identity().to_hex(),
    addrs:       h.addrs().collect(),
    is_guard:    h.is_guard(),
    is_exit:     h.is_exit(),
}).collect::<Vec<_>>();

if let Some(evt) = sybil_detector.check_hops(&hops) {
    tx.send(evt)?;
}
```

`check_hops()` is already implemented in `SybilDetector` and fully tested.

---

## Security note

ArtiShield is a **client-side heuristic layer**. It cannot defend against a
global passive adversary. Tor's built-in guard selection and path diversity
are your primary protection. ArtiShield adds visibility and alerting on top.

---

## License

MIT OR Apache-2.0
