# ArtiShield

**Threat-monitoring and mitigation layer for [arti](https://gitlab.torproject.org/tpo/core/arti).**

## Real arti hooks

| Component | arti API | Flag |
|---|---|---|
| `SybilDetector` | `TorClient::dirmgr()` → `NetDirProvider::events()` → `NetDir::relays()` | `experimental-api` |
| `GuardDiscoveryDetector` | same `dirmgr()` / `DirEvent` stream | `experimental-api` |
| `TimingDetector` | `tokio_socks::Socks5Stream` on arti SOCKS5 port | none |
| `MitigationEngine` | `TorClient::isolated_client()` — circuit rotation | stable |

What `experimental-api` gives us:

```rust
let dirmgr = tor_client.dirmgr();                        // Arc<dyn NetDirProvider>
let nd     = dirmgr.netdir(Timeliness::Timely)?;          // Arc<NetDir>
let events = dirmgr.events();                             // Stream<DirEvent>

for relay in nd.relays() {
    let fp    = relay.rsa_id();          // &RsaIdentity
    let addrs = relay.addrs();           // Iterator<&SocketAddr>
    let guard = relay.is_flagged_guard();
}
```

What is NOT in the stable API (documented honestly):

| Missing | Reason | Status |
|---|---|---|
| Per-circuit hop list (middle + exit) | `ClientCirc` internals private | `check_hops()` ready, plug in when exposed |
| Per-cell SENDME counters | Circuit reactor is internal | RTT proxy via SOCKS |
| Active circuit count | No public counter | `0` in MetricsSnapshot |

## Quick start

```bash
# Prerequisites: Rust >= 1.75, arti running on 127.0.0.1:9150
cargo build --release
cp artishield.toml.example artishield.toml
./target/release/artishield

# Tests
cargo test
```

## API

| Path | Description |
|---|---|
| `GET /api/metrics` | MetricsSnapshot |
| `GET /api/events` | Last 100 ThreatEvents |
| `GET /api/relays/suspicious` | Relays score ≥ 0.5 |
| `POST /api/relay/:fp/flag` | Manually flag relay |
| `GET /ws` | WebSocket live ThreatEvent stream |

## CLI

```bash
artishield                          # run
artishield check-config             # validate config
artishield dump-events --limit 50   # print stored events
artishield dump-relays --threshold 0.7
```

## Extending

Plug in circuit hop inspection once arti stabilises `ClientCirc::path()`:

```rust
let hops = circuit.path_hops().map(|h| CircuitHop {
    rsa_fp: h.rsa_identity(),
    addrs:  h.addrs().collect(),
    is_guard: h.is_guard(),
    is_exit:  h.is_exit(),
}).collect::<Vec<_>>();

if let Some(evt) = sybil_detector.check_hops(&hops) {
    tx.send(evt)?;
}
```

`check_hops()` is already implemented in `SybilDetector`.

## Security

ArtiShield is a client-side heuristic layer. It cannot defend against a
global passive adversary. Do not rely on it alone — Tor's built-in guard
selection and path diversity are your primary protection.

## License

MIT OR Apache-2.0
