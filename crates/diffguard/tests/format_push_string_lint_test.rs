//! Test that clippy::format_push_string lint is not triggered in main.rs
//!
//! This test verifies that the inefficient `push_str(&format!(...))` pattern
//! has been replaced with `writeln!()` in the three functions that build
//! String output:
//! - format_rule_explanation() (16 violations)
//! - cmd_explain() error path (1 violation)
//! - render_markdown_with_baseline_annotations() (2 violations)
//!
//! The lint is allow-by-default, so we must explicitly enable it with
//! `-W clippy::format_push_string`.
//!
//! Note: The clippy output format has the file path on one line and the lint name
//! on a subsequent `= help:` line, so we need multi-line matching.

use std::process::Command;

/// Find warning blocks in clippy output that match both `main_rs_marker` and `lint_name`.
///
/// The clippy output format is:
/// ```text
/// warning: `format!(..)` appended to existing `String`
///   --> crates/diffguard/src/main.rs:1077:21
///    |
/// 77 |                     msg.push_str(&format!("  - {}\n", s));
///    |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
///    |
///    = help: consider using `write!` to avoid the extra allocation
///    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.92.0/index.html#format_push_string
/// ```
///
/// So we need to look for `lint_name` (format_push_string) and then check if any
/// of the preceding ~15 lines contains `main_rs_marker`.
fn count_warnings_from_file(combined: &str, main_rs_marker: &str, lint_name: &str) -> usize {
    let lines: Vec<&str> = combined.lines().collect();
    let mut count = 0;

    for (i, line) in lines.iter().enumerate() {
        if line.contains(lint_name) {
            // Check preceding lines for the main.rs marker
            let start = i.saturating_sub(15);
            let preceding_context = &lines[start..i];
            if preceding_context.iter().any(|l| l.contains(main_rs_marker)) {
                count += 1;
            }
        }
    }

    count
}

/// Test that main.rs has zero clippy::format_push_string warnings.
///
/// This test fails when the inefficient `push_str(&format!(...))` pattern
/// is present in main.rs. After replacing with `writeln!()`, this test passes.
///
/// Acceptance criterion: "Clippy passes: Running `cargo clippy --package diffguard`
/// produces zero `clippy::format_push_string` warnings in `main.rs`."
#[test]
fn test_no_format_push_string_warnings_in_main_rs() {
    // Invalidate any cached clippy results by touching the source file
    // This ensures we get fresh lint results.
    let touch_output = Command::new("touch")
        .arg("/home/hermes/repos/diffguard/crates/diffguard/src/main.rs")
        .output()
        .expect("touch should succeed");

    assert!(touch_output.status.success(), "touch should succeed");

    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard",
            "--",
            "-W",
            "clippy::format_push_string",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    // Count warnings from crates/diffguard/src/main.rs with format_push_string lint
    let main_rs_marker = "crates/diffguard/src/main.rs";
    let lint_name = "format_push_string";
    let warning_count = count_warnings_from_file(&combined, main_rs_marker, lint_name);

    // The test passes only when there are ZERO warnings from main.rs
    assert!(
        warning_count == 0,
        "Expected 0 format_push_string warnings in main.rs, but found {}.\n\
         Full clippy output:\n{}",
        warning_count,
        combined
    );
}

// NOTE: Output format is verified by existing unit tests in main.rs:
// - test_format_rule_explanation_basic
// - test_format_rule_explanation_minimal
// These tests ensure the refactoring maintains byte-for-byte identical output.
