//! ArtiShield — threat monitoring & mitigation for arti (Tor Rust client).
//!
//! # Feature flags
//!
//! | Feature       | Default | Description                                                  |
//! |---------------|---------|--------------------------------------------------------------|
//! | `arti-hooks`  | **no**  | Real arti integration via `experimental-api`                  |
//! | `geoip`       | **yes** | MaxMind GeoLite2-ASN for ASN-based Sybil detection           |
//! | `bevy-plugin` | **no**  | Bevy render-graph post-processing node                       |
//! | `bevy-ui`     | **no**  | Bevy egui UI panel (implies `bevy-plugin`)                   |
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
    use bevy::render::render_graph::RenderGraph;
    use bevy::render::render_resource::Shader;
    use bevy::render::{ExtractSchedule, Render, RenderApp, RenderSet};

    use super::node;

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
            app.world
                .resource_mut::<Assets<Shader>>()
                .set_untracked(
                    node::ARTISHIELD_SHADER_HANDLE,
                    // Bevy 0.11: from_wgsl(source, path) — path is used for error reporting only.
                    Shader::from_wgsl(
                        include_str!("../assets/artishield/effect.wgsl"),
                        "assets/artishield/effect.wgsl",
                    ),
                );

            app.insert_resource(ArtishieldSettings::default());
            app.add_system(update_artishield_settings);

            // Render-app wiring (Bevy 0.11 uses schedules + sets, not stages)
            let render_app = app.sub_app_mut(RenderApp);
            render_app.init_resource::<node::ArtishieldPipeline>();
            render_app.add_systems(ExtractSchedule, node::extract_resources);
            render_app
                .add_systems(Render, node::queue_node.in_set(RenderSet::Queue));

            let mut graph = render_app.world.resource_mut::<RenderGraph>();
            node::register_node(&mut graph);
        }
    }

    /// Global settings forwarded to the render node.
    #[derive(Resource, Default)]
    pub struct ArtishieldSettings {
        /// Enable or disable the post-processing overlay.
        pub enabled: bool,
        /// Intensity of the visual effect (0.0 – 1.0).
        pub intensity: f32,
    }

    fn update_artishield_settings(mut settings: ResMut<ArtishieldSettings>) {
        if settings.intensity == 0.0 {
            settings.intensity = 0.8;
        }
    }
}

// ── Bevy egui UI panel (opt-in) ───────────────────────────────────────────────
#[cfg(feature = "bevy-ui")]
pub mod ui;
