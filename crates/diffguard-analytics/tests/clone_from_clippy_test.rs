//! Test to verify that `merge_false_positive_baselines()` uses `clone_from()` instead of `.clone()`.
//!
//! This test runs clippy with the `assigning_clones` lint and verifies no warnings are produced.
//!
//! The `merge_false_positive_baselines()` function at lines 119-128 in
//! `crates/diffguard-analytics/src/lib.rs` should use `clone_from()` to avoid the
//! `clippy::assigning_clones` lint:
//!
//! ```text
//! existing.note.clone_from(&entry.note);     // instead of: existing.note = entry.note.clone();
//! existing.rule_id.clone_from(&entry.rule_id);  // instead of: existing.rule_id = entry.rule_id.clone();
//! existing.path.clone_from(&entry.path);     // instead of: existing.path = entry.path.clone();
//! ```

use std::process::Command;

/// Test that verifies `diffguard-analytics` crate passes `clippy::assigning_clones` lint.
///
/// This test will:
/// - FAIL if the code uses `.clone()` assignments (produces clippy warnings)
/// - PASS if the code uses `.clone_from()` (no warnings)
///
/// Acceptance criterion: "Clippy passes: `cargo clippy --package diffguard-analytics -- -W clippy::assigning_clones`
/// produces no warnings for the modified lines"
#[test]
fn test_merge_false_positive_baselines_uses_clone_from() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-analytics",
            "--",
            "-W",
            "clippy::assigning_clones",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to execute cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract warning count from clippy output
    // Clippy outputs: "warning: `diffguard-analytics` (lib) generated N warnings"
    let combined_output = format!("{}{}", stdout, stderr);

    // The test passes only if there are ZERO assigning_clones warnings
    assert!(
        !combined_output.contains("assigning_clones"),
        "Expected no assigning_clones warnings, but clippy reported them.\n\
         The merge_false_positive_baselines() function should use clone_from() instead of .clone():\n\
         - Line 121: existing.note.clone_from(&entry.note)\n\
         - Line 124: existing.rule_id.clone_from(&entry.rule_id)\n\
         - Line 127: existing.path.clone_from(&entry.path)\n\n\
         Full clippy output:\n{}",
        combined_output
    );
}
