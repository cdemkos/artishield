# Contributing to ArtiShield

Thank you for your interest in contributing! This document describes the
development workflow and conventions used in this project.

## Prerequisites

- Rust ≥ 1.88 (MSRV declared in `Cargo.toml`)
- Docker (optional, for integration testing)
- `cargo-audit` — `cargo install cargo-audit --locked`

## Development workflow

```bash
# Clone and enter the repo
git clone https://github.com/cdemkos/artishield
cd artishield

# Run the dashboard (no arti required)
cargo run

# Run all tests
cargo test --all-targets

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt

# Audit dependencies
cargo audit
```

## Feature flags

| Flag | Purpose |
|------|---------|
| `geoip` (default) | MaxMind ASN lookups |
| `arti-hooks` | Real arti integration |
| `bevy-plugin` | Render-node only (no window) |
| `bevy-ui` | Full native 3D globe app |

## Branching strategy

- `main` — always releasable
- `feature/<name>` — new features
- `fix/<name>` — bug fixes
- `chore/<name>` — maintenance

Open a PR against `main`. All CI checks must pass before merging.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add X detector
fix: correct Y threshold
docs: update README
chore: bump dependencies
```

## Adding a new detector

1. Create `src/detectors/<name>.rs`
2. Implement the detector struct and emit `ThreatEvent`s on the broadcast channel
3. Register it in `src/detectors/mod.rs`
4. Add integration tests in `tests/<name>_integration.rs`
5. Document the signal and arti API surface in the README table

## Code style

- `cargo fmt` is enforced in CI — run it before committing
- `cargo clippy -- -D warnings` must pass
- Prefer `anyhow::Result` for fallible public functions
- Use `tracing::{info, warn, error, debug}` — never `println!` in library code

## Security

See [SECURITY.md](.github/SECURITY.md) for the vulnerability disclosure policy.
