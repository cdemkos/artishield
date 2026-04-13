//! ArtiShield — threat monitoring & mitigation for arti (Tor Rust client).
//!
//! # Feature flags
//!
//! | Feature       | Default | Description                                                  |
//! |---------------|---------|--------------------------------------------------------------|
//! | `arti-hooks`  | **no**  | Real arti integration via `experimental-api`                  |
//! | `geoip`       | **yes** | MaxMind GeoLite2-ASN for ASN-based Sybil detection           |
//! | `bevy-plugin` | **no**  | Bevy render-graph post-processing node                       |
//! | `bevy-ui`     | **no**  | Bevy native app: 3D globe + egui panel (implies `bevy-plugin`)|
#![forbid(unsafe_code)]
#![warn(clippy::all, missing_docs, rust_2018_idioms)]

// ── Core monitor modules (always compiled) ────────────────────────────────────
pub mod config;
pub mod detectors;
pub mod event;
#[cfg(feature = "geoip")]
pub mod geoip;
pub mod mitigations;
pub mod monitor;
pub mod storage;

pub use config::ShieldConfig;

// ── Bevy render-graph plugin (opt-in) ────────────────────────────────────────
#[cfg(feature = "bevy-plugin")]
pub mod node;

#[cfg(feature = "bevy-plugin")]
pub use bevy_plugin::ArtishieldPlugin;

#[cfg(feature = "bevy-plugin")]
mod bevy_plugin {
    use bevy::prelude::*;
    use bevy::render::extract_resource::ExtractResourcePlugin;
    use bevy::render::render_resource::Shader;
    use bevy::render::RenderApp;

    use super::node;
    // Re-export so callers can adjust settings without importing `node` directly.
    pub use node::ArtishieldSettings;

    /// Bevy [`Plugin`] that registers the ArtiShield fullscreen post-processing pass.
    ///
    /// Add it to your Bevy [`App`] after [`DefaultPlugins`]:
    /// ```no_run
    /// # use bevy::prelude::*;
    /// # use artishield::ArtishieldPlugin;
    /// App::new()
    ///     .add_plugins(DefaultPlugins)
    ///     .add_plugin(ArtishieldPlugin)
    ///     .run();
    /// ```
    pub struct ArtishieldPlugin;

    impl Plugin for ArtishieldPlugin {
        fn build(&self, app: &mut App) {
            // Register the embedded WGSL shader so PipelineCache can find it.
            app.world.resource_mut::<Assets<Shader>>().set_untracked(
                node::ARTISHIELD_SHADER_HANDLE,
                Shader::from_wgsl(
                    include_str!("../assets/artishield/effect.wgsl"),
                    "assets/artishield/effect.wgsl",
                ),
            );

            // Insert settings into the main world (enabled + default intensity).
            app.insert_resource(ArtishieldSettings {
                enabled: true,
                intensity: 0.8,
            });

            // Auto-extract ArtishieldSettings to the render world each frame.
            app.add_plugins(ExtractResourcePlugin::<ArtishieldSettings>::default());

            // Render-app wiring: only the pipeline resource; bind groups are now
            // created on-the-fly inside ArtishieldPassNode::run().
            let render_app = app.sub_app_mut(RenderApp);
            render_app.init_resource::<node::ArtishieldPipeline>();
            node::register_node(&mut render_app.world);
        }
    }
}

// ── OSINT engine (Onionoo + ip-api + Overpass + OSM tiles) ───────────────────
#[cfg(feature = "bevy-ui")]
pub mod osint;

// ── Forensic evidence &amp; report generation ──────────────────────────────────
pub mod evidence;

// ── Legal countermeasures (ExcludeNodes, iptables, reporting) ─────────────────
#[cfg(feature = "bevy-ui")]
pub mod countermeasures;

// ── Bevy native globe app (opt-in) ────────────────────────────────────────────
#[cfg(feature = "bevy-ui")]
pub mod globe;

#[cfg(feature = "bevy-ui")]
pub use globe::run_native_app;

// ── Bevy egui UI panel (opt-in) ───────────────────────────────────────────────
#[cfg(feature = "bevy-ui")]
pub mod ui;
