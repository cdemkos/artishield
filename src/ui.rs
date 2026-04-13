//! Bevy egui panel: threat feed, relay OSINT detail, countermeasure console.

use bevy::prelude::*;
use bevy_egui::{egui, EguiContexts, EguiPlugin};

use crate::countermeasures;
use crate::event::ThreatEvent;
use crate::evidence::{Classification, ReportBuilder};
use crate::globe::SelectedArc;
use crate::osint::{OsintResult, OsintResultReceiver};
use crate::osint::relay::RelayProfile;

// ── Shared state ──────────────────────────────────────────────────────────────

/// Shared UI state resource.
#[derive(Resource, Default)]
pub struct ArtishieldUiState {
    /// Latest threat events to display in the feed.
    pub latest_events: Vec<ThreatEvent>,
    /// Whether to show the fullscreen toggle button (set to `true` on WASM).
    pub show_fullscreen_button: bool,
    /// Most recently completed relay OSINT lookup.
    pub relay_profile: Option<RelayProfile>,
    /// Generated countermeasure texts for the current relay.
    pub countermeasures: Option<countermeasures::CountermeasureSet>,
    /// Egui texture handle for the OSM tile (IP-level fallback).
    pub tile_texture: Option<egui::TextureHandle>,
    /// Which countermeasure text is currently shown in the text area.
    pub cm_tab: CmTab,
    /// Scrollback for the countermeasure text area.
    pub cm_scroll: f32,
    // ── Report builder form fields ────────────────────────────────────────────
    /// Case / incident ID input field.
    pub report_case_id: String,
    /// Investigator name input field.
    pub report_investigator: String,
    /// Notes input field.
    pub report_notes: String,
    /// Selected classification.
    pub report_classification: Classification,
    /// Status message after export attempt.
    pub report_status: String,
    /// Accumulated threat events for the next report.
    pub report_events: Vec<ThreatEvent>,
    /// Accumulated relay profiles for the next report.
    pub report_relays: Vec<RelayProfile>,
}

/// Which countermeasure to display in the text panel.
#[derive(Default, PartialEq, Eq, Clone, Copy)]
pub enum CmTab {
    /// Show the generated ExcludeNodes / arti.toml snippet.
    #[default]
    ExcludeNodes,
    /// Show the iptables shell script.
    Iptables,
    /// Show the nftables ruleset.
    Nftables,
    /// Show the bad-relays@lists.torproject.org email draft.
    BadRelayEmail,
    /// Show the AbuseIPDB curl command.
    AbuseIpDb,
    /// Show the ISP abuse contact email draft.
    IspAbuse,
    /// Forensic evidence report builder.
    Report,
}

// ── Setup ─────────────────────────────────────────────────────────────────────

/// Add the ArtiShield egui panel to a Bevy [`App`].
pub fn setup_ui(app: &mut App) {
    app.add_plugins(EguiPlugin)
        .insert_resource(ArtishieldUiState {
            show_fullscreen_button: cfg!(target_arch = "wasm32"),
            ..Default::default()
        })
        .add_systems(
            bevy::app::Update,
            (poll_osint_results, artishield_egui_system).chain(),
        );
}

// ── Systems ───────────────────────────────────────────────────────────────────

/// Drain completed OSINT results into [`ArtishieldUiState`].
fn poll_osint_results(
    receiver: Option<Res<'_, OsintResultReceiver>>,
    mut ui_state: ResMut<'_, ArtishieldUiState>,
    mut contexts: EguiContexts<'_, '_>,
) {
    let Some(recv) = receiver else { return };
    let rx = match recv.0.lock() {
        Ok(g)  => g,
        Err(e) => e.into_inner(),
    };
    while let Ok(result) = rx.try_recv() {
        match result {
            OsintResult::Relay(profile) => {
                let reason   = "Detected by ArtiShield threat monitor";
                let evidence = "See ArtiShield event log for details.";
                let cms = countermeasures::generate(&profile, reason, evidence);
                // Accumulate for report builder
                ui_state.report_relays.push(profile.clone());
                ui_state.countermeasures = Some(cms);
                ui_state.relay_profile   = Some(profile);
                ui_state.tile_texture    = None;
            }
            OsintResult::Ip(ip_result) => {
                // IP-level fallback: load OSM tile into egui texture
                if let Some(ref png) = ip_result.tile_png {
                    if let Ok(img) = image::load_from_memory(png) {
                        let rgba = img.to_rgba8();
                        let (w, h) = rgba.dimensions();
                        let color_img = egui::ColorImage::from_rgba_unmultiplied(
                            [w as usize, h as usize],
                            rgba.as_raw(),
                        );
                        let handle = contexts.ctx_mut().load_texture(
                            "osm_tile",
                            color_img,
                            egui::TextureOptions::LINEAR,
                        );
                        ui_state.tile_texture = Some(handle);
                    }
                }
            }
        }
    }
}

/// Main egui rendering system.
pub fn artishield_egui_system(
    mut contexts: EguiContexts<'_, '_>,
    mut ui_state: ResMut<'_, ArtishieldUiState>,
    selected_arc: Res<'_, SelectedArc>,
) {
    let ctx = contexts.ctx_mut();

    // ── Threat feed ───────────────────────────────────────────────────────────
    egui::Window::new("ArtiShield — Threats")
        .resizable(true)
        .default_pos([10.0, 10.0])
        .default_size([340.0, 220.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Events: {}", ui_state.latest_events.len()));
                if !selected_arc.label.is_empty() {
                    ui.separator();
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        format!("Selected: {}", selected_arc.label),
                    );
                }
                if ui_state.show_fullscreen_button && ui.button("Fullscreen").clicked() {
                    toggle_fullscreen();
                }
            });
            ui.label(egui::RichText::new("Left-click an arc endpoint to investigate").small().italics());
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for e in ui_state.latest_events.iter().rev().take(20) {
                    ui.colored_label(
                        level_color(e.level as u8),
                        format!("[{:?}] {} — {}", e.level, e.timestamp.format("%H:%M:%S"), e.message),
                    );
                }
            });
        });

    // ── Relay OSINT panel ─────────────────────────────────────────────────────
    if let Some(ref profile) = ui_state.relay_profile.clone() {
        egui::Window::new("Relay OSINT")
            .resizable(true)
            .default_pos([10.0, 250.0])
            .default_size([400.0, 520.0])
            .show(ctx, |ui| {
                egui::Grid::new("relay_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        row(ui, "Fingerprint", &profile.fingerprint);
                        row(ui, "Nickname",    &profile.nickname);
                        row(ui, "OR-Address",  &profile.or_address);
                        row(ui, "Land",        &format!("{} ({})", profile.geo_country, profile.country));
                        row(ui, "Stadt",       &profile.geo_city);
                        row(ui, "ISP",         &profile.geo_isp);
                        row(ui, "ASN",         &format!("{} {}", profile.asn, profile.as_name));
                        row(ui, "Flags",       &profile.flags.join(", "));
                        row(ui, "Bandwidth",   &fmt_bytes(profile.bandwidth_rate));
                        row(ui, "Uptime 30d",  &format!("{:.1}%", profile.uptime * 100.0));
                        row(ui, "Guard prob.", &format!("{:.4}", profile.guard_probability));
                        row(ui, "Exit prob.",  &format!("{:.4}", profile.exit_probability));
                        row(ui, "First seen",  &profile.first_seen);
                        row(ui, "Platform",    &profile.platform);
                        if let Some(ref abuse) = profile.abuse_contact {
                            row(ui, "Abuse-Mail", abuse);
                        }
                    });

                if !profile.family_fingerprints.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "Deklarierte Familie ({} Relays)",
                            profile.family_fingerprints.len()
                        ))
                        .strong(),
                    );
                    for fp in &profile.family_fingerprints {
                        ui.label(egui::RichText::new(fp).monospace().small());
                    }
                }

                if !profile.contact.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new("Betreiber-Kontakt").strong());
                    ui.label(&profile.contact);
                }
            });
    }

    // ── Countermeasure console ────────────────────────────────────────────────
    if let Some(ref cms) = ui_state.countermeasures.clone() {
        egui::Window::new("Gegenmassnahmen")
            .resizable(true)
            .default_pos([430.0, 10.0])
            .default_size([520.0, 640.0])
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Alle Massnahmen sind legal und wirken lokal oder über offizielle \
                         Meldewege. Kein Angriff auf Fremdsysteme.",
                    )
                    .small()
                    .color(egui::Color32::from_rgb(150, 220, 150)),
                );
                ui.separator();

                // Tab bar
                ui.horizontal_wrapped(|ui| {
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::ExcludeNodes, "ExcludeNodes");
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::Iptables,     "iptables");
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::Nftables,     "nftables");
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::BadRelayEmail,"bad-relays Mail");
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::AbuseIpDb,   "AbuseIPDB");
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::IspAbuse,    "ISP Abuse");
                    ui.separator();
                    tab_btn(ui, &mut ui_state.cm_tab, CmTab::Report,      "📋 Bericht");
                });
                ui.separator();

                if ui_state.cm_tab == CmTab::Report {
                    render_report_builder(ui, &mut ui_state);
                } else {
                    let text = match ui_state.cm_tab {
                        CmTab::ExcludeNodes  => &cms.exclude_nodes,
                        CmTab::Iptables      => &cms.iptables,
                        CmTab::Nftables      => &cms.nftables,
                        CmTab::BadRelayEmail => &cms.bad_relay_email,
                        CmTab::AbuseIpDb     => &cms.abuseipdb_cmd,
                        CmTab::IspAbuse      => &cms.isp_abuse_email,
                        CmTab::Report        => unreachable!(),
                    };

                    let desc = match ui_state.cm_tab {
                        CmTab::ExcludeNodes  => "Füge in arti.toml unter [path_config] ein. Verhindert Nutzung dieser Relays.",
                        CmTab::Iptables      => "Shell-Skript (als root ausführen). Blockiert ausgehende Verbindungen zur Relay-IP.",
                        CmTab::Nftables      => "nftables-Regelwerk (modernes Alternative zu iptables).",
                        CmTab::BadRelayEmail => "E-Mail-Entwurf an bad-relays@lists.torproject.org — offizieller Meldekanal.",
                        CmTab::AbuseIpDb     => "curl-Befehl für AbuseIPDB API (eigenen API-Key einsetzen).",
                        CmTab::IspAbuse      => "E-Mail-Entwurf an den ASN-Abuse-Kontakt (aus RDAP).",
                        CmTab::Report        => unreachable!(),
                    };
                    ui.label(egui::RichText::new(desc).small().italics());
                    ui.add_space(4.0);
                    if ui.button("Kopieren").clicked() {
                        ui.output_mut(|o| o.copied_text = text.clone());
                    }
                    egui::ScrollArea::vertical()
                        .id_source("cm_scroll")
                        .max_height(420.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut text.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .interactive(false),
                            );
                        });
                }
            });
    }
}

// ── Report builder panel ──────────────────────────────────────────────────────

fn render_report_builder(ui: &mut egui::Ui, state: &mut ArtishieldUiState) {
    ui.label(
        egui::RichText::new(
            "Erstellt einen kryptografisch signierten Forensik-Bericht mit \
             Hash-Kette. Alle gesammelten Ereignisse und Relay-Profile dieser \
             Sitzung werden eingeschlossen.",
        )
        .small()
        .italics(),
    );
    ui.add_space(8.0);

    egui::Grid::new("report_form")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("Fall-ID").strong());
            ui.text_edit_singleline(&mut state.report_case_id);
            ui.end_row();

            ui.label(egui::RichText::new("Ermittler").strong());
            ui.text_edit_singleline(&mut state.report_investigator);
            ui.end_row();

            ui.label(egui::RichText::new("Einstufung").strong());
            egui::ComboBox::from_id_source("cls_combo")
                .selected_text(format!("{}", state.report_classification))
                .show_ui(ui, |ui| {
                    use Classification::*;
                    ui.selectable_value(&mut state.report_classification, Unclassified, "UNCLASSIFIED");
                    ui.selectable_value(&mut state.report_classification, Internal,     "INTERNAL");
                    ui.selectable_value(&mut state.report_classification, Restricted,   "RESTRICTED");
                    ui.selectable_value(&mut state.report_classification, Confidential, "CONFIDENTIAL");
                });
            ui.end_row();

            ui.label(egui::RichText::new("Ereignisse").strong());
            ui.label(format!("{} gesammelt", state.report_events.len()));
            ui.end_row();

            ui.label(egui::RichText::new("Relay-Profile").strong());
            ui.label(format!("{} gesammelt", state.report_relays.len()));
            ui.end_row();
        });

    ui.add_space(4.0);
    ui.label(egui::RichText::new("Notizen / Beweisbeschreibung").strong());
    ui.add(
        egui::TextEdit::multiline(&mut state.report_notes)
            .desired_rows(4)
            .desired_width(f32::INFINITY)
            .hint_text("Beobachtungen, Kontext, Beweiskette…"),
    );
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        let can_export = !state.report_events.is_empty() || !state.report_relays.is_empty();

        if ui.add_enabled(can_export, egui::Button::new("HTML exportieren")).clicked() {
            export_report(state, false);
        }
        if ui.add_enabled(can_export, egui::Button::new("JSON exportieren")).clicked() {
            export_report(state, true);
        }
        if ui.add_enabled(can_export, egui::Button::new("In DB speichern")).clicked() {
            save_report_to_db(state);
        }
        if ui.button("Sitzung zurücksetzen").clicked() {
            state.report_events.clear();
            state.report_relays.clear();
            state.report_status = "Sitzungsdaten gelöscht.".into();
        }
    });

    if !state.report_status.is_empty() {
        ui.add_space(6.0);
        let color = if state.report_status.starts_with('✓') {
            egui::Color32::from_rgb(60, 220, 100)
        } else if state.report_status.starts_with('✗') {
            egui::Color32::from_rgb(240, 80, 80)
        } else {
            egui::Color32::from_rgb(180, 180, 180)
        };
        ui.colored_label(color, &state.report_status);
    }
}

fn export_report(state: &mut ArtishieldUiState, json: bool) {
    let ev_db  = std::path::PathBuf::from("evidence.db");
    let ev_key = std::path::PathBuf::from("evidence.key");
    let store  = match crate::evidence::EvidenceStore::open(&ev_db, &ev_key) {
        Ok(s)  => s,
        Err(e) => { state.report_status = format!("✗ DB-Fehler: {e}"); return; }
    };

    let builder = build_report_builder(state);
    let report = match builder.build(&store) {
        Ok(r)  => r,
        Err(e) => { state.report_status = format!("✗ Build-Fehler: {e}"); return; }
    };

    let ts    = report.created_at.format("%Y%m%d_%H%M%S");
    let base  = state.report_case_id
        .trim()
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "_");
    let base  = if base.is_empty() { "report".to_owned() } else { base };

    if json {
        let path = format!("{base}_{ts}.json");
        match std::fs::write(&path, report.to_json_pretty()) {
            Ok(_)  => state.report_status = format!("✓ JSON: {path}"),
            Err(e) => state.report_status = format!("✗ {e}"),
        }
    } else {
        let path = format!("{base}_{ts}.html");
        match std::fs::write(&path, report.to_html()) {
            Ok(_)  => state.report_status = format!("✓ HTML: {path}"),
            Err(e) => state.report_status = format!("✗ {e}"),
        }
    }
}

fn save_report_to_db(state: &mut ArtishieldUiState) {
    let ev_db  = std::path::PathBuf::from("evidence.db");
    let ev_key = std::path::PathBuf::from("evidence.key");
    let store  = match crate::evidence::EvidenceStore::open(&ev_db, &ev_key) {
        Ok(s)  => s,
        Err(e) => { state.report_status = format!("✗ DB-Fehler: {e}"); return; }
    };
    let builder = build_report_builder(state);
    let report  = match builder.build(&store) {
        Ok(r)  => r,
        Err(e) => { state.report_status = format!("✗ Build-Fehler: {e}"); return; }
    };
    let id_short = report.id.to_string()[..8].to_owned();
    match store.save(&report) {
        Ok(_)  => state.report_status = format!(
            "✓ In evidence.db gespeichert (ID: {id_short}…, Hash: {}…)",
            &report.content_hash[..12]
        ),
        Err(e) => state.report_status = format!("✗ Speicherfehler: {e}"),
    }
}

fn build_report_builder(state: &ArtishieldUiState) -> ReportBuilder {
    let mut b = ReportBuilder::new()
        .classification(state.report_classification)
        .notes(&state.report_notes)
        .events(state.report_events.clone());

    if !state.report_case_id.trim().is_empty() {
        b = b.case_id(state.report_case_id.trim());
    }
    if !state.report_investigator.trim().is_empty() {
        b = b.investigator(state.report_investigator.trim());
    }
    b = b.relays(state.report_relays.clone());

    // Attach countermeasure texts as documentation
    if let Some(ref cms) = state.countermeasures {
        b = b
            .countermeasure(&cms.exclude_nodes)
            .countermeasure(&cms.iptables)
            .countermeasure(&cms.bad_relay_email);
    }
    b
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).strong());
    ui.label(value);
    ui.end_row();
}

fn tab_btn(ui: &mut egui::Ui, state: &mut CmTab, tab: CmTab, label: &str) {
    let active = *state == tab;
    if ui.selectable_label(active, label).clicked() {
        *state = tab;
    }
}

fn fmt_bytes(bps: u64) -> String {
    if bps >= 1_000_000 {
        format!("{:.1} MB/s", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1} KB/s", bps as f64 / 1_000.0)
    } else {
        format!("{bps} B/s")
    }
}

fn level_color(level: u8) -> egui::Color32 {
    match level {
        4 => egui::Color32::from_rgb(255, 60,  60),  // Critical
        3 => egui::Color32::from_rgb(255, 160, 30),  // High
        2 => egui::Color32::from_rgb(240, 220, 30),  // Medium
        1 => egui::Color32::from_rgb(60,  190, 255), // Low
        _ => egui::Color32::from_rgb(60,  255, 120), // Info
    }
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
