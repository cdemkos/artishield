# Changelog

All notable changes to ArtiShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) published to GHCR on every tag
- Automated GitHub Release workflow with generated release notes
- `cargo audit` step in CI to catch known-vulnerable dependencies
- MSRV enforcement job in CI (reads `rust-version` from `Cargo.toml`)
- Docker build smoke-test in CI (validates `Dockerfile` on every PR)
- `concurrency` group in CI to cancel stale runs on force-push
- `SECURITY.md` with responsible disclosure policy
- `CHANGELOG.md` (this file)
- GitHub Issue templates (bug report, feature request)
- Pull-request template with testing checklist
- `CONTRIBUTING.md` with development workflow
- `.dockerignore` to keep image layers lean
- `rustfmt.toml` for consistent code style
- `deny.toml` for license and dependency policy

### Changed
- `Dockerfile`: pinned base images to digest-stable tags; non-root user enforced
- `docker-compose.yml`: pinned Prometheus and Grafana to specific minor versions
- `deploy/artishield.service`: added `WatchdogSec`, `OOMPolicy=kill`, `CapabilityBoundingSet`

## [0.2.1] — 2025-04-01

### Added
- Evidence store with HMAC-SHA256 hash-chain integrity
- HTML evidence report export (`artishield export-report`)
- `verify-chain` CLI subcommand
- Bevy 3D globe visualisation (`--features bevy-ui`)

## [0.2.0] — 2025-02-15

### Added
- DoS detector (circuit-build latency / SENDME burst)
- Timing detector (RTT correlation via SOCKS5 probe)
- Prometheus `/metrics` endpoint
- WebSocket live event stream (`/ws`)
- Docker Compose stack (ArtiShield + Prometheus + Grafana)

## [0.1.0] — 2025-01-10

### Added
- Initial release: Sybil, GuardDiscovery, HsEnum detectors
- SQLite reputation store
- Axum HTTP API + interactive HTML dashboard
- systemd service unit
