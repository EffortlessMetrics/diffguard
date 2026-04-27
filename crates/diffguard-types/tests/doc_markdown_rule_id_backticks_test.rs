//! Tests verifying that doc_markdown lint is satisfied for `SensorFinding::code`.
//!
//! This test ensures the `rule_id` identifier in the doc comment at
//! `crates/diffguard-types/src/lib.rs:532` is wrapped in backticks.
//!
//! See: GitHub issue #573

use std::process::Command;

/// Test that `SensorFinding::code` doc comment has backticks around `rule_id`.
///
/// This verifies the `clippy::doc_markdown` lint is satisfied for the
/// doc comment: `/// Rule code (maps from \`rule_id\`, e.g., "rust.no_unwrap").`
///
/// The lint fires when identifiers appear without backticks in doc comments.
#[test]
fn test_sensor_finding_code_doc_rule_id_has_backticks() {
    // Read the source file and check the doc comment at line 532
    let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source_content =
        std::fs::read_to_string(&source_path).expect("Failed to read lib.rs source file");

    let lines: Vec<&str> = source_content.lines().collect();

    // Line 532 is 0-indexed as line 531
    let line_532 = lines.get(531).expect("Line 532 should exist in lib.rs");

    // The fixed doc comment should have `rule_id` wrapped in backticks
    // Current (broken): "/// Rule code (maps from rule_id, e.g., \"rust.no_unwrap\")."
    // Fixed:             "/// Rule code (maps from `rule_id`, e.g., \"rust.no_unwrap\")."
    assert!(
        line_532.contains("`rule_id`"),
        "SensorFinding::code doc comment at line 532 should have `rule_id` in backticks.\n\
         Expected: /// Rule code (maps from `rule_id`, e.g., \"rust.no_unwrap\").\n\
         Actual line 532: {}",
        line_532
    );
}

/// Test that clippy does not emit doc_markdown warning for `rule_id` in SensorFinding.
///
/// This runs clippy with the doc_markdown lint enabled and verifies that
/// line 532 of lib.rs does not trigger a warning about `rule_id`.
#[test]
fn test_clippy_no_doc_markdown_warning_for_rule_id() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // Run clippy with doc_markdown lint
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir(manifest_dir)
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check that there's no warning about `rule_id` at line 532
    // The warning looks like:
    // warning: item in documentation is missing backticks
    //    --> crates/diffguard-types/src/lib.rs:532:30
    //     |
    // 532 |     /// Rule code (maps from rule_id, e.g., "rust.no_unwrap").
    //     |                              ^^^^^^^
    let has_rule_id_warning = stderr.contains("lib.rs:532")
        && stderr.contains("rule_id")
        && stderr.contains("missing backticks");

    assert!(
        !has_rule_id_warning,
        "clippy should not warn about `rule_id` missing backticks at line 532.\n\
         The doc comment should have: /// Rule code (maps from `rule_id`, e.g., \"rust.no_unwrap\").\n\
         \n\
         Clippy output:\n{}",
        stderr
    );
}
