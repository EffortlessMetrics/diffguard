#![allow(clippy::all, unused)]
//! Tests to verify that public functions returning non-trivial values have #[must_use] attribute.
//!
//! These tests verify the fix for GitHub issue #398:
//! "3 public functions lack #[must_use] — clippy::must_use_candidate"
//!
//! RED TEST: These tests will FAIL if #[must_use] is missing, PASS if present.

use diffguard_core::{RuleMetadata, SensorReportContext, render_sensor_report};
use diffguard_types::CheckReceipt;

/// RED TEST: Verify via clippy that must_use_candidate lint does NOT fire
/// for render_sensor_report which should have #[must_use].
#[test]
fn test_clippy_no_must_use_candidate_for_render_sensor_report() {
    use std::process::Command;

    // Run clippy on the diffguard-core package, looking specifically for
    // must_use_candidate warnings related to render_sensor_report
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-core",
            "--",
            "-W",
            "clippy::must_use_candidate",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    // render_sensor_report should NOT appear in must_use_candidate warnings
    // if it has #[must_use] attribute properly applied.
    let has_render_sensor_report_warning = combined.contains("render_sensor_report");

    // FAIL (red) if warning exists - means #[must_use] is missing
    // PASS (green) if no warning - means #[must_use] is present
    assert!(
        !has_render_sensor_report_warning,
        "render_sensor_report should NOT trigger must_use_candidate - should have #[must_use]"
    );
}
