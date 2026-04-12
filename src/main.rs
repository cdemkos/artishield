//! artishield — CLI entry point.

use artishield::{monitor::ArtiShield, ShieldConfig};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "artishield", version, about = "Threat monitor for arti")]
struct Cli {
    #[arg(short, long, default_value = "artishield.toml")]
    config: PathBuf,
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
    let cli    = Cli::parse();
    let config = ShieldConfig::load(&cli.config)?;

    // Always print to stderr so user can see what's happening
    eprintln!("ArtiShield starting...");
    eprintln!("  api_addr  = {}", config.api_addr);
    eprintln!("  socks_addr= {}", config.socks_addr);
    eprintln!("  db_path   = {}", config.db_path.display());

    tracing_subscriber::registry()
        .with(fmt::layer().compact())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .init();

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
                    println!("[{}] {:8} {:.2}  {}", e.timestamp, e.level, e.anomaly_score, e.message);
                }
            }
            return Ok(());
        }
        Some(Command::DumpRelays { threshold }) => {
            let store  = artishield::storage::ReputationStore::open(&config.db_path)?;
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
        #[cfg(feature = "bevy-ui")]
        Some(Command::Native { no_monitor }) => {
            // Bevy takes over the main thread and never returns.
            artishield::run_native_app(config, no_monitor);
        }

        None => {}
    }

    eprintln!("Starting ArtiShield::run()...");
    let shield = ArtiShield::new(config)?;

    // SIGTERM handler (systemd stop / docker stop) — Unix only.
    // On Windows this future never resolves, so the select still compiles.
    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        eprintln!("SIGTERM received — shutting down");
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        result = shield.run() => {
            if let Err(e) = result {
                eprintln!("ArtiShield error: {e:#}");
                return Err(e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("Ctrl-C received — shutting down");
        }
        _ = sigterm => {}
    }

    Ok(())
}
