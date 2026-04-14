//! artishield — CLI entry point.

use artishield::{monitor::ArtiShield, ShieldConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "artishield", version, about = "Threat monitor for arti")]
struct Cli {
    #[arg(short, long, default_value = "artishield.toml")]
    config: PathBuf,
    /// Emit logs as newline-delimited JSON (useful for log aggregation pipelines).
    #[arg(long, default_value_t = false)]
    json_logs: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    CheckConfig,
    DumpEvents {
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    DumpRelays {
        #[arg(short, long, default_value_t = 0.5)]
        threshold: f64,
    },
    /// List all stored evidence reports.
    ListReports,
    /// Verify the hash-chain integrity of all stored evidence reports.
    VerifyChain,
    /// Export a stored evidence report as HTML.
    ExportReport {
        /// Report UUID (from `list-reports`).
        #[arg(short, long)]
        id: String,
        /// Output file path (default: <id>.html).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Launch the Bevy native 3D globe app (requires feature `bevy-ui`).
    #[cfg(feature = "bevy-ui")]
    Native {
        /// Disable the ArtiShield monitor; show a simulated demo instead.
        /// Useful for testing the globe without a running arti instance.
        #[arg(long, default_value_t = false)]
        no_monitor: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = ShieldConfig::load(&cli.config)?;

    let log_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    if cli.json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_env_filter(log_filter)
            .init();
    }

    // Emit production warnings (missing secrets, misconfigured features, etc.)
    for warning in config.validate() {
        tracing::warn!("{warning}");
    }

    tracing::info!(api_addr = %config.api_addr, socks_addr = %config.socks_addr, db_path = %config.db_path.display(), "ArtiShield starting");

    match cli.command {
        Some(Command::CheckConfig) => {
            println!("Config OK:\n{config:#?}");
            return Ok(());
        }
        Some(Command::DumpEvents { limit }) => {
            let store = artishield::storage::ReputationStore::open(&config.db_path)?;
            let events = store.recent_events(limit)?;
            if events.is_empty() {
                println!("No events stored yet.");
            } else {
                for e in &events {
                    println!(
                        "[{}] {:8} {:.2}  {}",
                        e.timestamp, e.level, e.anomaly_score, e.message
                    );
                }
            }
            return Ok(());
        }
        Some(Command::DumpRelays { threshold }) => {
            let store = artishield::storage::ReputationStore::open(&config.db_path)?;
            let relays = store.suspicious_relays(threshold)?;
            if relays.is_empty() {
                println!("No relays with score ≥ {threshold:.2}.");
            } else {
                for r in &relays {
                    println!("{} score={:.3} flags={}", r.fingerprint, r.score, r.flags);
                }
            }
            return Ok(());
        }

        Some(Command::ListReports) => {
            let ev_db = config.db_path.with_file_name("evidence.db");
            let ev_key = config.db_path.with_file_name("evidence.key");
            let store = artishield::evidence::EvidenceStore::open(&ev_db, &ev_key)?;
            let list = store.list()?;
            if list.is_empty() {
                println!("No evidence reports stored yet.");
            } else {
                println!(
                    "{:<38} {:<26} {:<20} {}",
                    "ID", "Created", "Case-ID", "Hash (16)"
                );
                println!("{}", "-".repeat(100));
                for r in &list {
                    println!(
                        "{:<38} {:<26} {:<20} {}",
                        r.id,
                        r.created_at,
                        r.case_id.as_deref().unwrap_or("—"),
                        r.hash_prefix,
                    );
                }
            }
            return Ok(());
        }

        Some(Command::VerifyChain) => {
            let ev_db = config.db_path.with_file_name("evidence.db");
            let ev_key = config.db_path.with_file_name("evidence.key");
            let store = artishield::evidence::EvidenceStore::open(&ev_db, &ev_key)?;
            match store.verify_chain() {
                Ok(n) => println!("✓ Hash-Kette intakt — {n} Berichte verifiziert."),
                Err(e) => {
                    eprintln!("✗ Hash-Kette DEFEKT: {e:#}");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }

        Some(Command::ExportReport { id, out }) => {
            let ev_db = config.db_path.with_file_name("evidence.db");
            let ev_key = config.db_path.with_file_name("evidence.key");
            let store = artishield::evidence::EvidenceStore::open(&ev_db, &ev_key)?;
            let reports = store.load_all()?;
            let report = reports
                .iter()
                .find(|r| r.id.to_string().starts_with(&id))
                .ok_or_else(|| anyhow::anyhow!("Report '{id}' not found"))?;
            let out_path = out.unwrap_or_else(|| PathBuf::from(format!("{}.html", report.id)));
            std::fs::write(&out_path, report.to_html())?;
            println!("HTML exportiert: {}", out_path.display());
            return Ok(());
        }
        #[cfg(feature = "bevy-ui")]
        Some(Command::Native { no_monitor }) => {
            // Bevy takes over the main thread and never returns.
            artishield::run_native_app(config, no_monitor);
        }

        None => {}
    }

    tracing::debug!("Starting ArtiShield::run()");
    let shield = ArtiShield::new(config)?;

    // SIGTERM handler (systemd stop / docker stop) — Unix only.
    // On Windows this future never resolves, so the select still compiles.
    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        tracing::info!("SIGTERM received — shutting down");
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        result = shield.run() => {
            if let Err(e) = result {
                tracing::error!("ArtiShield error: {e:#}");
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received — shutting down");
        }
        _ = sigterm => {}
    }

    Ok(())
}
