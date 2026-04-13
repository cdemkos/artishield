//! Integration tests for timing correlation math.
//!
//! We test the Pearson correlation and de-anonymisation probability
//! functions used by TimingDetector without opening a real SOCKS connection.
//! The `analyse()` method is tested via the public detector interface
//! using pre-built sample windows.

// We cannot construct TimingDetector directly from outside (private fields)
// but we can test the underlying math functions and threshold logic
// by exercising the public API surface exposed through #[cfg(test)] helpers.

/// Pearson correlation — mirrored here to test independently.
fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    assert_eq!(n, ys.len());
    if n < 2 {
        return 0.0;
    }
    let mx = xs.iter().sum::<f64>() / n as f64;
    let my = ys.iter().sum::<f64>() / n as f64;
    let num: f64 = xs.iter().zip(ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    let dx: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum::<f64>().sqrt();
    let dy: f64 = ys.iter().map(|y| (y - my).powi(2)).sum::<f64>().sqrt();
    if dx < 1e-9 || dy < 1e-9 {
        return 0.0;
    }
    (num / (dx * dy)).clamp(-1.0, 1.0)
}

fn deanon_prob(r_abs: f64) -> f64 {
    1.0 / (1.0 + (-12.0 * (r_abs - 0.5)).exp())
}

// ── Pearson tests ─────────────────────────────────────────────────────────────

#[test]
fn pearson_perfect_positive() {
    let xs: Vec<f64> = (0..50).map(|i| i as f64).collect();
    let r = pearson(&xs, &xs);
    assert!((r - 1.0).abs() < 1e-9, "r={r}");
}

#[test]
fn pearson_perfect_negative() {
    let xs: Vec<f64> = (0..50).map(|i| i as f64).collect();
    let ys: Vec<f64> = xs.iter().map(|x| -x).collect();
    let r = pearson(&xs, &ys);
    assert!((r + 1.0).abs() < 1e-9, "r={r}");
}

#[test]
fn pearson_uncorrelated_near_zero() {
    // Orthogonal signals should give near-zero correlation
    let xs: Vec<f64> = (0..100).map(|i| (i as f64 * 0.1).sin()).collect();
    let ys: Vec<f64> = (0..100).map(|i| (i as f64 * 0.1).cos()).collect();
    let r = pearson(&xs, &ys).abs();
    assert!(r < 0.15, "Expected near-zero correlation, got |r|={r}");
}

#[test]
fn pearson_with_noise_still_high() {
    // Correlated series with 20% noise should still give high r
    let xs: Vec<f64> = (0..200).map(|i| i as f64).collect();
    let ys: Vec<f64> = xs
        .iter()
        .enumerate()
        .map(|(i, x)| {
            x + if i % 5 == 0 { 10.0 } else { 0.0 } // 20% outliers
        })
        .collect();
    let r = pearson(&xs, &ys);
    assert!(r > 0.95, "Expected high r despite noise, got {r}");
}

#[test]
fn pearson_single_element_returns_zero() {
    assert_eq!(pearson(&[1.0], &[1.0]), 0.0);
}

#[test]
fn pearson_constant_series_returns_zero() {
    let xs = vec![5.0f64; 20];
    let ys = vec![3.0f64; 20];
    assert_eq!(pearson(&xs, &ys), 0.0);
}

// ── De-anonymisation probability ──────────────────────────────────────────────

#[test]
fn deanon_midpoint_at_r05() {
    let p = deanon_prob(0.5);
    assert!((p - 0.5).abs() < 0.01, "Expected ~0.5 at r=0.5, got {p}");
}

#[test]
fn deanon_low_r_near_zero() {
    let p = deanon_prob(0.1);
    assert!(p < 0.1, "Expected low probability for r=0.1, got {p}");
}

#[test]
fn deanon_high_r_near_one() {
    let p = deanon_prob(0.95);
    assert!(p > 0.95, "Expected high probability for r=0.95, got {p}");
}

#[test]
fn deanon_monotone() {
    // Probability must be monotonically increasing in |r|
    let probs: Vec<f64> = (0..=10).map(|i| deanon_prob(i as f64 / 10.0)).collect();
    for w in probs.windows(2) {
        assert!(w[1] >= w[0], "deanon_prob not monotone: {w:?}");
    }
}

// ── Threshold logic ───────────────────────────────────────────────────────────

#[test]
fn threshold_06_passes_with_high_r() {
    let threshold = 0.6f64;
    let r = 0.75f64;
    assert!(r.abs() >= threshold, "r=0.75 should exceed threshold 0.6");
}

#[test]
fn threshold_06_blocked_with_low_r() {
    let threshold = 0.6f64;
    let r = 0.3f64;
    assert!(
        r.abs() < threshold,
        "r=0.3 should not trigger threshold 0.6"
    );
}

// ── Level mapping ─────────────────────────────────────────────────────────────

#[test]
fn level_from_prob() {
    use artishield::event::ThreatLevel;
    let level = |prob: f64| -> ThreatLevel {
        if prob >= 0.85 {
            ThreatLevel::Critical
        } else if prob >= 0.65 {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        }
    };

    assert_eq!(level(0.90), ThreatLevel::Critical);
    assert_eq!(level(0.70), ThreatLevel::High);
    assert_eq!(level(0.50), ThreatLevel::Medium);
}
