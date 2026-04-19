//! Red test for doc_markdown lint fix in diffguard-types/lib.rs
//!
//! This test verifies that the doc comments at lines 459, 519, 532, and 548
//! in crates/diffguard-types/src/lib.rs do not trigger clippy::doc_markdown warnings.
//!
//! The four identifiers that need backticks are:
//! - Line 459: `rust.no_unwrap` in RuleOverride.id doc comment
//! - Line 519: `missing_base`, `tool_error` in CapabilityStatus.reason doc comment
//! - Line 532: `rule_id`, `rust.no_unwrap` in SensorFinding.code doc comment
//! - Line 548: `match_text`, `snippet` in SensorFinding.data doc comment
//!
//! After the fix, running:
//! `cargo clippy --package diffguard-types --all-targets -- -W clippy::doc_markdown`
//! should produce zero warnings related to lib.rs at these lines.

use std::process::Command;

/// Test that RuleOverride.id doc comment has properly backtick-wrapped identifiers.
///
/// Before fix: `/// The rule ID to override (e.g., "rust.no_unwrap").`
/// After fix:  `/// The \`rule ID\` to override (e.g., \`rust.no_unwrap\`).`
#[test]
fn test_ruleoverride_id_doc_comment_no_doc_markdown_warning() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that line 459 (RuleOverride.id with rust.no_unwrap) does NOT appear in warnings
    assert!(
        !stderr.contains("lib.rs:459"),
        "Line 459 (RuleOverride.id rust.no_unwrap) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stderr
    );

    // Also check the stdout (clippy sometimes outputs there too)
    assert!(
        !stdout.contains("lib.rs:459"),
        "Line 459 (RuleOverride.id rust.no_unwrap) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stdout
    );
}

/// Test that CapabilityStatus.reason doc comment has properly backtick-wrapped identifiers.
///
/// Before fix: `/// Stable token reason (e.g., "missing_base", "tool_error").`
/// After fix:  `/// Stable token reason (e.g., \`missing_base\`, \`tool_error\`).`
#[test]
fn test_capabilitystatus_reason_doc_comment_no_doc_markdown_warning() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that line 519 (CapabilityStatus.reason with missing_base, tool_error) does NOT appear
    assert!(
        !stderr.contains("lib.rs:519"),
        "Line 519 (CapabilityStatus.reason missing_base/tool_error) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stderr
    );

    assert!(
        !stdout.contains("lib.rs:519"),
        "Line 519 (CapabilityStatus.reason missing_base/tool_error) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stdout
    );
}

/// Test that SensorFinding.code doc comment has properly backtick-wrapped identifiers.
///
/// Before fix: `/// Rule code (maps from rule_id, e.g., "rust.no_unwrap").`
/// After fix:  `/// Rule code (maps from \`rule_id\`, e.g., \`rust.no_unwrap\`).`
#[test]
fn test_sensorfinding_code_doc_comment_no_doc_markdown_warning() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that line 532 (SensorFinding.code with rule_id, rust.no_unwrap) does NOT appear
    assert!(
        !stderr.contains("lib.rs:532"),
        "Line 532 (SensorFinding.code rule_id/rust.no_unwrap) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stderr
    );

    assert!(
        !stdout.contains("lib.rs:532"),
        "Line 532 (SensorFinding.code rule_id/rust.no_unwrap) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stdout
    );
}

/// Test that SensorFinding.data doc comment has properly backtick-wrapped identifiers.
///
/// Before fix: `/// Additional data (match_text, snippet).`
/// After fix:  `/// Additional data (\`match_text\`, \`snippet\`).`
#[test]
fn test_sensorfinding_data_doc_comment_no_doc_markdown_warning() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that line 548 (SensorFinding.data with match_text, snippet) does NOT appear
    assert!(
        !stderr.contains("lib.rs:548"),
        "Line 548 (SensorFinding.data match_text/snippet) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stderr
    );

    assert!(
        !stdout.contains("lib.rs:548"),
        "Line 548 (SensorFinding.data match_text/snippet) should NOT have doc_markdown warning.\n\
         Clippy output:\n{}",
        stdout
    );
}

/// Comprehensive test: zero doc_markdown warnings at the four target lines in lib.rs.
///
/// This test aggregates all four lines (459, 519, 532, 548) and verifies that
/// none of them appear in clippy's doc_markdown warnings after the fix.
#[test]
fn test_all_four_doc_markdown_lines_have_no_warnings() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-types",
            "--",
            "-W",
            "clippy::doc_markdown",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    // All four lines should be absent from any doc_markdown warnings
    let problem_lines = ["lib.rs:459", "lib.rs:519", "lib.rs:532", "lib.rs:548"];

    for line in &problem_lines {
        assert!(
            !combined.contains(line),
            "Line {} should NOT appear in doc_markdown warnings after fix.\n\
             Full clippy output:\n{}",
            line,
            combined
        );
    }
}
