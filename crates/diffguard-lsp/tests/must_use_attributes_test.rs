#![allow(clippy::all, unused)]
//! Tests to verify that public functions returning non-trivial values have #[must_use] attribute.
//!
//! These tests verify the fix for GitHub issue #398:
//! "3 public functions lack #[must_use] — clippy::must_use_candidate"
//!
//! RED TEST: These tests will FAIL if #[must_use] is missing, PASS if present.

use diffguard_lsp::text::{changed_lines_between, split_lines};
use std::collections::BTreeSet;

/// RED TEST: Verify via clippy that must_use_candidate lint does NOT fire
/// for split_lines and changed_lines_between (which should have #[must_use]).
#[test]
fn test_clippy_no_must_use_candidate_warnings_for_lsp_functions() {
    use std::process::Command;

    // Run clippy on the diffguard-lsp package
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
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

    // These functions should NOT appear in must_use_candidate warnings
    // if they have #[must_use] attribute properly applied.
    let has_split_lines_warning = combined.contains("split_lines");
    let has_changed_lines_warning = combined.contains("changed_lines_between");

    // FAIL (red) if warnings exist - means #[must_use] is missing
    // PASS (green) if no warnings - means #[must_use] is present
    assert!(
        !has_split_lines_warning,
        "split_lines should NOT trigger must_use_candidate - should have #[must_use]"
    );
    assert!(
        !has_changed_lines_warning,
        "changed_lines_between should NOT trigger must_use_candidate - should have #[must_use]"
    );
}

/// Basic sanity test that split_lines works correctly.
/// This test should always pass regardless of #[must_use] attribute.
#[test]
fn test_split_lines_returns_correct_result() {
    let text = "line1\nline2\nline3";
    let result = split_lines(text);
    assert!(
        !result.is_empty(),
        "split_lines should return non-empty result for multi-line text"
    );
    assert_eq!(result.len(), 3, "split_lines should return 3 lines");
}

/// Basic sanity test that changed_lines_between works correctly.
/// This test should always pass regardless of #[must_use] attribute.
#[test]
fn test_changed_lines_between_detects_changes() {
    let before = "line1\nline2\nline3";
    let after = "line1\nmodified\nline3";

    let result = changed_lines_between(before, after);
    assert!(
        !result.is_empty(),
        "changed_lines_between should detect changes"
    );
    assert!(
        result.contains(&2),
        "changed_lines_between should mark line 2 as changed"
    );
}
