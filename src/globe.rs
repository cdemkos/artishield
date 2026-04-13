//! Bevy 3D globe visualization for the ArtiShield native app.
//!
//! Renders a rotating Earth sphere with graticule lines, relay dots, and
//! animated Bézier attack arcs driven by real-time [`ThreatEvent`]s.
//!
//! # Threading model
//!
//! Bevy owns the main thread.  The ArtiShield monitor runs in a background
//! OS thread with its own `tokio` runtime.  Events (and optional GeoIP hints)
//! cross the thread boundary via [`GlobeMessage`] sent over a
//! [`std::sync::mpsc`] channel stored as [`GlobeEventReceiver`].

use bevy::{
    input::mouse::{MouseMotion, MouseWheel},
    prelude::*,
};
use std::sync::{mpsc, Mutex};

use crate::event::{ThreatEvent, ThreatKind, ThreatLevel};
use crate::osint::{OsintRequest, OsintRequestSender};

// ── Country centroid table ────────────────────────────────────────────────────
// ISO-3166 alpha-2 → (lat°, lon°).  Used to place relay dots and arc endpoints.

const COUNTRY_CENTROIDS: &[(&str, f32, f32)] = &[
    ("US", 38.0, -97.0),
    ("DE", 51.2, 10.5),
    ("NL", 52.1, 5.3),
    ("FR", 46.2, 2.2),
    ("GB", 55.4, -3.4),
    ("SE", 60.1, 18.6),
    ("CH", 47.0, 8.2),
    ("RU", 60.0, 90.0),
    ("CN", 35.0, 105.0),
    ("JP", 36.2, 138.3),
    ("AU", -25.3, 133.8),
    ("BR", -14.2, -51.9),
    ("CA", 56.1, -106.3),
    ("IN", 20.6, 79.0),
    ("UA", 48.4, 31.2),
    ("RO", 45.9, 24.9),
    ("LU", 49.8, 6.1),
    ("FI", 61.9, 25.7),
    ("AT", 47.5, 14.5),
    ("CZ", 49.8, 15.5),
    ("PL", 51.9, 19.1),
    ("SG", 1.4, 103.8),
    ("KR", 35.9, 127.8),
    ("ZA", -29.0, 25.0),
    ("MX", 23.6, -102.6),
    ("AR", -38.4, -63.6),
    ("TR", 38.9, 35.2),
    ("IR", 32.4, 53.7),
    ("EG", 26.8, 30.8),
    ("NG", 9.1, 8.7),
];

/// Convert geographic coordinates to a globe-surface point (Y-up, unit sphere).
pub fn lat_lon_to_vec3(lat_deg: f32, lon_deg: f32, radius: f32) -> Vec3 {
    let lat = lat_deg.to_radians();
    let lon = lon_deg.to_radians();
    Vec3::new(
        radius * lat.cos() * lon.sin(),
        radius * lat.sin(),
        radius * lat.cos() * lon.cos(),
    )
}

/// Look up a 2-letter country code in [`COUNTRY_CENTROIDS`].
pub fn country_pos(code: &str) -> Option<Vec3> {
    COUNTRY_CENTROIDS
        .iter()
        .find(|(c, _, _)| c.eq_ignore_ascii_case(code))
        .map(|(_, lat, lon)| lat_lon_to_vec3(*lat, *lon, 1.01))
}

// ── Cross-thread message ──────────────────────────────────────────────────────

/// Messages sent from the monitor background thread to the Bevy globe.
pub enum GlobeMessage {
    /// A threat event → spawn an attack arc.
    Threat(ThreatEvent),
    /// A geographic hint for a relay or scanner IP.
    ///
    /// Sent when GeoIP resolves an IP to a country code.
    RelayGeo {
        /// ISO-3166 alpha-2 country code, or `None` for the destination end.
        country: Option<String>,
        /// Latitude in degrees.
        lat: f32,
        /// Longitude in degrees.
        lon: f32,
        /// Severity of the associated event, used to colour the dot.
        level: ThreatLevel,
    },
}

/// Bevy resource wrapping the receiving end of the monitor channel.
#[derive(Resource)]
pub struct GlobeEventReceiver(pub Mutex<mpsc::Receiver<GlobeMessage>>);

// ── ECS components ────────────────────────────────────────────────────────────

/// Marker for the globe sphere entity.
#[derive(Component)]
pub struct Globe;

/// A relay dot on the globe surface.
#[derive(Component)]
pub struct RelayDot;

/// Animated great-circle arc representing an attack trajectory.
#[derive(Component)]
pub struct AttackArc {
    /// Start point on the globe surface (unit-sphere coords).
    pub start: Vec3,
    /// End point on the globe surface (unit-sphere coords).
    pub end: Vec3,
    /// Apex of the quadratic Bézier (lifted above the globe surface).
    pub apex: Vec3,
    /// Animation progress `[0, 1]`.
    pub progress: f32,
    /// Arc colour (threat-level tint).
    pub color: Color,
    /// Remaining lifetime in seconds.
    pub ttl: f32,
    /// Relay fingerprints associated with the source of this arc (if known).
    pub source_fingerprints: Vec<String>,
    /// The originating threat event (cloned at spawn time).
    pub threat_kind_label: String,
}

/// Currently selected arc endpoint — set by the click-picker system.
#[derive(Resource, Default)]
pub struct SelectedArc {
    /// Fingerprints to look up (from the clicked arc).
    pub fingerprints: Vec<String>,
    /// World-space position of the clicked endpoint (for highlighting).
    pub endpoint: Option<Vec3>,
    /// Short label shown in the UI.
    pub label: String,
}

// ── Plugin ────────────────────────────────────────────────────────────────────

/// Bevy plugin that owns the 3D globe scene and its ECS systems.
pub struct GlobePlugin;

impl Plugin for GlobePlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<SelectedArc>()
            .add_systems(Startup, setup_scene)
            .add_systems(
                Update,
                (
                    rotate_globe,
                    camera_orbit,
                    receive_globe_events,
                    pick_arc_endpoint,
                    animate_arcs,
                    draw_arcs,
                    draw_graticule,
                ),
            );
    }
}

// ── Startup ───────────────────────────────────────────────────────────────────

fn setup_scene(
    mut commands: Commands<'_, '_>,
    mut meshes: ResMut<'_, Assets<Mesh>>,
    mut materials: ResMut<'_, Assets<StandardMaterial>>,
    asset_server: Res<'_, AssetServer>,
) {
    // Camera
    commands.spawn(Camera3dBundle {
        transform: Transform::from_xyz(0.0, 1.0, 3.8).looking_at(Vec3::ZERO, Vec3::Y),
        ..Default::default()
    });

    // Lighting: ambient fill + directional sun + cool-blue underlight
    commands.insert_resource(AmbientLight {
        color: Color::rgb(0.08, 0.10, 0.15),
        brightness: 0.4,
    });
    commands.spawn(DirectionalLightBundle {
        directional_light: DirectionalLight {
            color: Color::rgb(1.0, 0.95, 0.85),
            illuminance: 12_000.0,
            ..Default::default()
        },
        transform: Transform::from_xyz(5.0, 8.0, 3.0).looking_at(Vec3::ZERO, Vec3::Y),
        ..Default::default()
    });
    commands.spawn(PointLightBundle {
        point_light: PointLight {
            color: Color::rgb(0.10, 0.20, 0.55),
            intensity: 1_200.0,
            range: 10.0,
            ..Default::default()
        },
        transform: Transform::from_xyz(-3.0, -2.0, -1.0),
        ..Default::default()
    });

    // Earth texture — loaded from assets/textures/earth_daymap.jpg.
    // Falls back to a flat ocean colour if the file is absent.
    let earth_texture: Handle<Image> = asset_server.load("textures/earth_daymap.jpg");

    // Globe sphere — 72×36 UV-sphere so texture pixels align with meridians
    commands.spawn((
        PbrBundle {
            mesh: meshes.add(
                shape::UVSphere {
                    radius: 1.0,
                    sectors: 72,
                    stacks: 36,
                }
                .into(),
            ),
            material: materials.add(StandardMaterial {
                base_color_texture: Some(earth_texture),
                // Slight fall-back tint when the texture hasn't loaded yet
                base_color: Color::rgb(0.04, 0.14, 0.32),
                metallic: 0.0,
                perceptual_roughness: 0.9,
                // Keep emissive very low — real texture carries its own colour
                emissive: Color::rgb(0.005, 0.008, 0.015),
                ..Default::default()
            }),
            ..Default::default()
        },
        Globe,
    ));

    // Atmosphere — slightly larger translucent sphere
    commands.spawn(PbrBundle {
        mesh: meshes.add(
            shape::UVSphere {
                radius: 1.03,
                sectors: 32,
                stacks: 16,
            }
            .into(),
        ),
        material: materials.add(StandardMaterial {
            base_color: Color::rgba(0.15, 0.45, 0.85, 0.07),
            alpha_mode: AlphaMode::Blend,
            unlit: true,
            double_sided: true,
            cull_mode: None,
            ..Default::default()
        }),
        ..Default::default()
    });
}

// ── Per-frame systems ─────────────────────────────────────────────────────────

fn rotate_globe(time: Res<'_, Time>, mut q: Query<'_, '_, &mut Transform, With<Globe>>) {
    for mut t in q.iter_mut() {
        t.rotate_y(0.04 * time.delta_seconds());
    }
}

/// Mouse-drag orbit + scroll zoom.
fn camera_orbit(
    time: Res<'_, Time>,
    mouse_input: Res<'_, Input<MouseButton>>,
    mut motion: EventReader<'_, '_, MouseMotion>,
    mut scroll: EventReader<'_, '_, MouseWheel>,
    mut q: Query<'_, '_, &mut Transform, With<Camera>>,
) {
    let mut yaw = 0.0_f32;
    let mut pitch = 0.0_f32;

    if mouse_input.pressed(MouseButton::Left) {
        for ev in motion.iter() {
            yaw -= ev.delta.x * 0.4 * time.delta_seconds();
            pitch -= ev.delta.y * 0.4 * time.delta_seconds();
        }
    } else {
        // Consume events to clear the reader even when not dragging.
        for _ in motion.iter() {}
    }

    let mut zoom = 0.0_f32;
    for ev in scroll.iter() {
        zoom -= ev.y * 0.25;
    }

    for mut transform in q.iter_mut() {
        if yaw.abs() > 1e-4 || pitch.abs() > 1e-4 {
            let qy = Quat::from_rotation_y(yaw);
            let right = transform.right();
            let qx = Quat::from_axis_angle(right, pitch);
            transform.translation = qx * qy * transform.translation;
            transform.look_at(Vec3::ZERO, Vec3::Y);
        }
        if zoom.abs() > 1e-3 {
            let dir = transform.translation.normalize();
            let dist = (transform.translation.length() + zoom).clamp(1.8, 6.0);
            transform.translation = dir * dist;
        }
    }
}

/// Draw latitude/longitude graticule using [`Gizmos`].
fn draw_graticule(mut gizmos: Gizmos<'_>) {
    let color = Color::rgba(0.15, 0.35, 0.65, 0.18);
    let r = 1.005_f32;
    const STEPS: usize = 64;

    // Parallels every 30°
    for lat_i in (-60..=60_i32).step_by(30) {
        let lat = (lat_i as f32).to_radians();
        let ring_r = r * lat.cos();
        let y = r * lat.sin();
        let mut prev = Vec3::new(ring_r, y, 0.0);
        for i in 1..=STEPS {
            let lon = (i as f32 / STEPS as f32) * std::f32::consts::TAU;
            let next = Vec3::new(ring_r * lon.cos(), y, ring_r * lon.sin());
            gizmos.line(prev, next, color);
            prev = next;
        }
    }

    // Meridians every 30°
    for lon_i in (0..360_i32).step_by(30) {
        let lon = (lon_i as f32).to_radians();
        let lat0 = -std::f32::consts::FRAC_PI_2;
        let mut prev = Vec3::new(
            r * lat0.cos() * lon.sin(),
            r * lat0.sin(),
            r * lat0.cos() * lon.cos(),
        );
        for i in 1..=STEPS {
            let lat = lat0 + (i as f32 / STEPS as f32) * std::f32::consts::PI;
            let next = Vec3::new(
                r * lat.cos() * lon.sin(),
                r * lat.sin(),
                r * lat.cos() * lon.cos(),
            );
            gizmos.line(prev, next, color);
            prev = next;
        }
    }
}

// ── Event ingestion ───────────────────────────────────────────────────────────

fn receive_globe_events(
    mut commands: Commands<'_, '_>,
    mut meshes: ResMut<'_, Assets<Mesh>>,
    mut materials: ResMut<'_, Assets<StandardMaterial>>,
    receiver: Option<Res<'_, GlobeEventReceiver>>,
    osint_tx: Option<Res<'_, OsintRequestSender>>,
) {
    let receiver = match receiver {
        Some(r) => r,
        None => return,
    };

    let rx = match receiver.0.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };

    for _ in 0..16 {
        match rx.try_recv() {
            Ok(GlobeMessage::Threat(evt)) => {
                // Trigger relay OSINT for any fingerprints in the event
                if let Some(ref tx) = osint_tx {
                    let fps: Vec<String> = match &evt.kind {
                        ThreatKind::SybilCluster { affected_fps, .. } => {
                            affected_fps.iter().take(3).cloned().collect()
                        }
                        ThreatKind::GuardDiscovery {
                            suspicious_fingerprints,
                            ..
                        } => suspicious_fingerprints.iter().take(3).cloned().collect(),
                        ThreatKind::DenialOfService {
                            source_relay: Some(fp),
                            ..
                        } => vec![fp.clone()],
                        ThreatKind::HsEnumeration {
                            suspected_scanner: Some(ip),
                            ..
                        } => {
                            // IP-level lookup as fallback (relay acting as scanner)
                            let _ = tx.0.try_send(OsintRequest::Ip(*ip));
                            vec![]
                        }
                        _ => vec![],
                    };
                    for fp in fps {
                        let _ = tx.0.try_send(OsintRequest::Relay { fingerprint: fp });
                    }
                }
                spawn_arc(&mut commands, &evt);
            }
            Ok(GlobeMessage::RelayGeo {
                lat, lon, level, ..
            }) => {
                spawn_relay_dot(&mut commands, &mut meshes, &mut materials, lat, lon, level);
            }
            Err(_) => break,
        }
    }
}

/// Spawn a small glowing sphere at a geo-coordinate to represent a known relay.
fn spawn_relay_dot(
    commands: &mut Commands<'_, '_>,
    meshes: &mut Assets<Mesh>,
    materials: &mut Assets<StandardMaterial>,
    lat: f32,
    lon: f32,
    level: ThreatLevel,
) {
    let pos = lat_lon_to_vec3(lat, lon, 1.015);
    let col = level_color(level, 0.85);

    commands.spawn((
        PbrBundle {
            mesh: meshes.add(
                shape::UVSphere {
                    radius: 0.008,
                    sectors: 8,
                    stacks: 4,
                }
                .into(),
            ),
            material: materials.add(StandardMaterial {
                base_color: col,
                emissive: col * 0.6,
                unlit: false,
                ..Default::default()
            }),
            transform: Transform::from_translation(pos),
            ..Default::default()
        },
        RelayDot,
    ));
}

/// Spawn an [`AttackArc`] entity for the given event.
fn spawn_arc(commands: &mut Commands<'_, '_>, evt: &ThreatEvent) {
    let color = level_color(evt.level, 1.0);
    let seed = evt.timestamp.timestamp() as f32;

    let start = geo_pos_from_event(evt, seed, false);
    let end = geo_pos_from_event(evt, seed, true);

    let mid = (start + end) * 0.5;
    let apex = mid.normalize() * (mid.length() + 0.45);

    let ttl = match evt.level {
        ThreatLevel::Critical | ThreatLevel::High => 8.0,
        ThreatLevel::Medium => 6.0,
        _ => 4.0,
    };

    // Extract relay fingerprints for click-based OSINT
    let source_fingerprints: Vec<String> = match &evt.kind {
        ThreatKind::SybilCluster { affected_fps, .. } => {
            affected_fps.iter().take(5).cloned().collect()
        }
        ThreatKind::GuardDiscovery {
            suspicious_fingerprints,
            ..
        } => suspicious_fingerprints.iter().take(5).cloned().collect(),
        ThreatKind::DenialOfService {
            source_relay: Some(fp),
            ..
        } => vec![fp.clone()],
        _ => vec![],
    };

    let threat_kind_label = match &evt.kind {
        ThreatKind::SybilCluster { .. } => "Sybil Cluster",
        ThreatKind::GuardDiscovery { .. } => "Guard Discovery",
        ThreatKind::DenialOfService { .. } => "Denial of Service",
        ThreatKind::HsEnumeration { .. } => "HS Enumeration",
        ThreatKind::TimingCorrelation { .. } => "Timing Correlation",
        ThreatKind::AnomalySpike { .. } => "Anomaly Spike",
        ThreatKind::CanaryFailure { .. } => "Canary Failure",
    }
    .to_owned();

    commands.spawn(AttackArc {
        start,
        end,
        apex,
        progress: 0.0,
        color,
        ttl,
        source_fingerprints,
        threat_kind_label,
    });
}

/// Derive a globe-surface position from an event.
///
/// `destination = true` returns the arc's target end; `false` returns the source.
/// Falls back to a deterministic pseudo-random position from the event timestamp.
fn geo_pos_from_event(evt: &ThreatEvent, seed: f32, destination: bool) -> Vec3 {
    // Try to extract a country code or IP from the event kind.
    match &evt.kind {
        ThreatKind::HsEnumeration {
            suspected_scanner: Some(ip),
            ..
        } if !destination => {
            // Rough lat/lon from first IP octet (placeholder until GeoIP is wired)
            let first: f32 = ip
                .to_string()
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(128.0);
            let lat = (first - 128.0) * 0.7;
            let lon = (seed * 13.7).rem_euclid(360.0) - 180.0;
            lat_lon_to_vec3(lat, lon, 1.01)
        }
        _ => {
            // Deterministic pseudo-random fallback
            let offset = if destination { 100.0 } else { 0.0 };
            let lat = ((seed * 17.3 + offset).rem_euclid(180.0)) - 90.0;
            let lon = ((seed * 31.7 + offset).rem_euclid(360.0)) - 180.0;
            lat_lon_to_vec3(lat, lon, 1.01)
        }
    }
}

// ── Click picking ─────────────────────────────────────────────────────────────

/// Raycast from camera through the mouse cursor; select the nearest arc endpoint.
///
/// A left-click within [`PICK_RADIUS`] world-units of any arc start/end triggers
/// a relay OSINT lookup and highlights the endpoint.
fn pick_arc_endpoint(
    windows: Query<'_, '_, &bevy::window::Window, With<bevy::window::PrimaryWindow>>,
    camera_q: Query<'_, '_, (&Camera, &GlobalTransform)>,
    arc_q: Query<'_, '_, &AttackArc>,
    mouse_btn: Res<'_, Input<MouseButton>>,
    mut selected: ResMut<'_, SelectedArc>,
    osint_tx: Option<Res<'_, OsintRequestSender>>,
) {
    if !mouse_btn.just_pressed(MouseButton::Left) {
        return;
    }

    let Ok(window) = windows.get_single() else {
        return;
    };
    let Some(cursor) = window.cursor_position() else {
        return;
    };
    let Ok((cam, cam_t)) = camera_q.get_single() else {
        return;
    };
    let Some(ray) = cam.viewport_to_world(cam_t, cursor) else {
        return;
    };

    // Radius (in world units) within which a click registers on an endpoint
    const PICK_RADIUS: f32 = 0.07;

    let mut best_dist = PICK_RADIUS;
    let mut best: Option<(&AttackArc, Vec3)> = None;

    for arc in arc_q.iter() {
        for &pt in &[arc.start, arc.end] {
            // Distance from world point to infinite ray
            let oc = pt - ray.origin;
            let proj = oc.dot(ray.direction).max(0.0);
            let closest = ray.origin + ray.direction * proj;
            let dist = (pt - closest).length();
            if dist < best_dist {
                best_dist = dist;
                best = Some((arc, pt));
            }
        }
    }

    if let Some((arc, pt)) = best {
        selected.fingerprints = arc.source_fingerprints.clone();
        selected.endpoint = Some(pt);
        selected.label = arc.threat_kind_label.clone();

        // Fire relay OSINT for all fingerprints in this arc
        if let Some(ref tx) = osint_tx {
            for fp in &arc.source_fingerprints {
                let _ = tx.0.try_send(OsintRequest::Relay {
                    fingerprint: fp.clone(),
                });
            }
        }
    }
}

// ── Arc animation ─────────────────────────────────────────────────────────────

fn animate_arcs(
    mut commands: Commands<'_, '_>,
    time: Res<'_, Time>,
    mut q: Query<'_, '_, (Entity, &mut AttackArc)>,
) {
    let dt = time.delta_seconds();
    for (entity, mut arc) in q.iter_mut() {
        arc.progress = (arc.progress + dt * 0.35).min(1.0);
        arc.ttl -= dt;
        if arc.ttl <= 0.0 {
            commands.entity(entity).despawn();
        }
    }
}

fn draw_arcs(mut gizmos: Gizmos<'_>, q: Query<'_, '_, &AttackArc>, selected: Res<'_, SelectedArc>) {
    const STEPS: usize = 48;

    for arc in q.iter() {
        let visible = (arc.progress * STEPS as f32) as usize;
        let alpha = (arc.ttl / 8.0).clamp(0.0, 1.0);
        let color = color_with_alpha(arc.color, alpha);

        let mut prev = arc.start;
        for i in 1..=visible.min(STEPS) {
            let t = i as f32 / STEPS as f32;
            let p = bezier(arc.start, arc.apex, arc.end, t);
            gizmos.line(prev, p, color);
            prev = p;
        }

        // Pulse dot at the arc head
        if visible > 0 && visible <= STEPS {
            let t = visible as f32 / STEPS as f32;
            let head = bezier(arc.start, arc.apex, arc.end, t);
            gizmos.sphere(
                head,
                Quat::IDENTITY,
                0.012,
                color_with_alpha(arc.color, alpha * 0.9),
            );
        }
    }

    // Highlight ring around the selected endpoint
    if let Some(pt) = selected.endpoint {
        let ring_color = Color::rgba(1.0, 1.0, 0.2, 0.9);
        gizmos.sphere(pt, Quat::IDENTITY, 0.04, ring_color);
        gizmos.sphere(pt, Quat::IDENTITY, 0.055, Color::rgba(1.0, 1.0, 0.2, 0.35));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn bezier(p0: Vec3, p1: Vec3, p2: Vec3, t: f32) -> Vec3 {
    let u = 1.0 - t;
    u * u * p0 + 2.0 * u * t * p1 + t * t * p2
}

#[inline]
fn color_with_alpha(c: Color, alpha: f32) -> Color {
    let [r, g, b, _] = c.as_rgba_f32();
    Color::rgba(r, g, b, alpha)
}

fn level_color(level: ThreatLevel, alpha: f32) -> Color {
    match level {
        ThreatLevel::Critical => Color::rgba(1.00, 0.10, 0.10, alpha),
        ThreatLevel::High => Color::rgba(1.00, 0.50, 0.05, alpha),
        ThreatLevel::Medium => Color::rgba(1.00, 0.90, 0.10, alpha),
        ThreatLevel::Low => Color::rgba(0.10, 0.75, 1.00, alpha),
        ThreatLevel::Info => Color::rgba(0.10, 1.00, 0.40, alpha),
    }
}

// ── Demo mode ─────────────────────────────────────────────────────────────────

/// Spawn a background thread that emits synthetic [`GlobeMessage`]s every 1.5 s.
///
/// Used when `--no-monitor` is passed to `artishield native`.
pub fn start_demo_thread(tx: mpsc::Sender<GlobeMessage>) {
    std::thread::spawn(move || {
        use crate::event::ThreatKind;

        let levels = [
            ThreatLevel::Info,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::Critical,
        ];
        let mut counter = 0usize;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1_500));

            let level = levels[counter % levels.len()];
            let evt = ThreatEvent::new(
                level,
                ThreatKind::AnomalySpike {
                    score: 0.6,
                    contributing_detectors: vec!["demo".into()],
                },
                format!("Demo event #{counter}"),
                0.6,
                vec![],
            );
            if tx.send(GlobeMessage::Threat(evt)).is_err() {
                break; // Bevy window closed
            }

            // Periodically emit relay position hints for visual richness
            if counter % 3 == 0 {
                let (_, lat, lon) = COUNTRY_CENTROIDS[counter % COUNTRY_CENTROIDS.len()];
                let _ = tx.send(GlobeMessage::RelayGeo {
                    country: None,
                    lat,
                    lon,
                    level,
                });
            }

            counter += 1;
        }
    });
}

// ── Native app entry point ────────────────────────────────────────────────────

/// Start the Bevy 3D globe, connecting it to the ArtiShield monitor.
///
/// - `no_monitor = false` → starts both the ArtiShield detectors and Bevy.
/// - `no_monitor = true`  → Bevy-only demo mode with synthetic events.
///
/// This function never returns; Bevy takes over the main thread.
pub fn run_native_app(config: crate::config::ShieldConfig, no_monitor: bool) -> ! {
    let (msg_tx, msg_rx) = mpsc::channel::<GlobeMessage>();

    if no_monitor {
        // Demo mode — synthetic events only, no real monitor
        start_demo_thread(msg_tx);
    } else {
        // Real monitor in a background OS thread
        let tx = msg_tx;
        let cfg = config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for ArtiShield monitor");

            rt.block_on(async move {
                use crate::detectors::{dos::DosDetector, timing::TimingDetector, EventTx};
                use tokio::sync::broadcast;

                let (event_tx, mut rx): (EventTx, _) = broadcast::channel(256);
                let socks_addr = cfg.socks_addr;

                tokio::spawn(TimingDetector::new(cfg.clone(), event_tx.clone(), socks_addr).run());
                tokio::spawn(DosDetector::new(cfg.clone(), event_tx.clone(), socks_addr).run());

                // Optionally load GeoIP for position hints
                #[cfg(feature = "geoip")]
                let geoip = cfg
                    .geoip_db
                    .as_ref()
                    .and_then(|p| {
                        let s = p.to_str()?;
                        // ASN DB used for both city and ASN slots (City lookup returns country)
                        crate::geoip::GeoIpServiceInner::new(s, s).ok()
                    })
                    .map(std::sync::Arc::new);

                loop {
                    match rx.recv().await {
                        Ok(evt) => {
                            // Emit a GeoIP position hint for IPs found in the event
                            #[cfg(feature = "geoip")]
                            if let Some(ref svc) = geoip {
                                emit_geo_hints(&tx, &evt, svc);
                            }

                            let _ = tx.send(GlobeMessage::Threat(evt));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(n, "globe event channel lagged");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        });
    }

    // ── Bevy app setup ────────────────────────────────────────────────────────
    use crate::node;
    use crate::node::{ArtishieldPipeline, ArtishieldSettings};
    use bevy::render::{extract_resource::ExtractResourcePlugin, RenderApp};

    let mut app = App::new();

    app.add_plugins(DefaultPlugins.set(WindowPlugin {
        primary_window: Some(Window {
            title: "ArtiShield — Live Threat Globe".into(),
            resolution: (1280.0, 800.0).into(),
            ..Default::default()
        }),
        ..Default::default()
    }));

    app.add_plugins(GlobePlugin);
    app.insert_resource(GlobeEventReceiver(Mutex::new(msg_rx)));

    // OSINT worker thread + channel resources
    let (osint_tx, osint_rx) = crate::osint::spawn_worker();
    app.insert_resource(osint_tx);
    app.insert_resource(osint_rx);

    // egui UI panel (threat feed + OSINT detail)
    crate::ui::setup_ui(&mut app);

    // Post-processing effect settings
    app.insert_resource(ArtishieldSettings {
        enabled: true,
        intensity: 0.6,
    });

    // Register WGSL shader
    {
        let mut shaders = app
            .world
            .resource_mut::<Assets<bevy::render::render_resource::Shader>>();
        shaders.set_untracked(
            node::ARTISHIELD_SHADER_HANDLE,
            bevy::render::render_resource::Shader::from_wgsl(
                include_str!("../assets/artishield/effect.wgsl"),
                "assets/artishield/effect.wgsl",
            ),
        );
    }

    // Wire render sub-app: only ArtishieldPipeline; bind groups are created
    // on-the-fly inside ArtishieldPassNode::run() using post_process_write().
    {
        let render_app = app.sub_app_mut(RenderApp);
        render_app.init_resource::<ArtishieldPipeline>();
        node::register_node(&mut render_app.world);
    }

    app.add_plugins(ExtractResourcePlugin::<ArtishieldSettings>::default());

    app.run();

    std::process::exit(0);
}

// ── GeoIP → RelayGeo bridge (feature-gated) ───────────────────────────────────

/// Extract IPs from a threat event, look them up via GeoIP, and emit
/// [`GlobeMessage::RelayGeo`] hints when a country centroid is found.
#[cfg(feature = "geoip")]
fn emit_geo_hints(
    tx: &mpsc::Sender<GlobeMessage>,
    evt: &ThreatEvent,
    svc: &crate::geoip::GeoIpServiceInner,
) {
    let ips: Vec<std::net::IpAddr> = match &evt.kind {
        ThreatKind::HsEnumeration {
            suspected_scanner: Some(ip),
            ..
        } => vec![*ip],
        ThreatKind::DenialOfService { .. } | ThreatKind::TimingCorrelation { .. } => vec![],
        _ => vec![],
    };

    for ip in ips {
        let info = svc.lookup(ip);
        if let Some(code) = info.country {
            if let Some(pos) = country_pos(&code) {
                let [lat, lon] = geo_vec3_to_lat_lon(pos);
                let _ = tx.send(GlobeMessage::RelayGeo {
                    country: Some(code),
                    lat,
                    lon,
                    level: evt.level,
                });
            }
        }
    }
}

/// Inverse of [`lat_lon_to_vec3`] — extract (lat, lon) from a unit-sphere point.
#[cfg(feature = "geoip")]
fn geo_vec3_to_lat_lon(v: Vec3) -> [f32; 2] {
    let n = v.normalize();
    let lat = n.y.asin().to_degrees();
    let lon = n.x.atan2(n.z).to_degrees();
    [lat, lon]
}
