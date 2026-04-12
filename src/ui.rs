//! Bevy egui panel that displays threat events and a fullscreen toggle (WASM).

use bevy::prelude::*;
use bevy_egui::{egui, EguiContexts, EguiPlugin};

use crate::event::ThreatEvent;

/// Shared UI state resource.
#[derive(Resource, Default)]
pub struct ArtishieldUiState {
    /// Latest threat events to display.
    pub latest_events: Vec<ThreatEvent>,
    /// Whether to show the fullscreen toggle button (set to `true` on WASM).
    pub show_fullscreen_button: bool,
}

/// Add the ArtiShield egui panel to a Bevy [`App`].
pub fn setup_ui(app: &mut App) {
    app.add_plugins(EguiPlugin)
        .insert_resource(ArtishieldUiState {
            show_fullscreen_button: cfg!(target_arch = "wasm32"),
            ..Default::default()
        })
        .add_systems(bevy::app::Update, artishield_egui_system);
}

/// Egui system that renders the ArtiShield overlay window.
pub fn artishield_egui_system(mut contexts: EguiContexts, ui_state: Res<ArtishieldUiState>) {
    let ctx = contexts.ctx_mut();
    egui::Window::new("ArtiShield")
        .resizable(true)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Events: {}", ui_state.latest_events.len()));
                if ui_state.show_fullscreen_button {
                    if ui.button("Toggle Fullscreen").clicked() {
                        toggle_fullscreen();
                    }
                }
            });

            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for e in &ui_state.latest_events {
                    ui.label(format!(
                        "[{}] {} — {}",
                        e.level as u8, e.timestamp, e.message
                    ));
                }
            });
        });
}

/// Call the JS fullscreen helper on WASM; no-op on native.
fn toggle_fullscreen() {
    #[cfg(target_arch = "wasm32")]
    wasm_fs::request_fullscreen_canvas();
    #[cfg(not(target_arch = "wasm32"))]
    tracing::debug!("fullscreen toggle is a no-op on native builds");
}

/// WASM-only JS bindings for the canvas fullscreen API.
#[cfg(target_arch = "wasm32")]
mod wasm_fs {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(module = "/static/fullscreen.js")]
    extern "C" {
        #[wasm_bindgen(js_name = requestFullScreenCanvas)]
        pub fn request_fullscreen_canvas();
    }
}
