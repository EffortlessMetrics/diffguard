//! Tests that `cargo fmt --check` passes for the diffguard crate.
//!
//! This verifies the formatting gate in CI is not broken by long lines
//! or other rustfmt violations in the diffguard crate.
//!
//! Issue: #466 - cargo fmt --check fails due to untracked property_test_checkstyle.rs
//! Root cause: Line 645 in main.rs exceeded rustfmt's 100-character default line width.

use std::process::Command;

/// Verifies `cargo fmt --check` passes for the diffguard crate.
/// This test would FAIL before the fix (line too long in main.rs:645)
/// and PASS after the fix (braces added to multi-line match arm).
///
/// Note: This only checks the diffguard crate, not the whole workspace.
/// There may be other formatting issues in other crates (e.g., diffguard-lsp)
/// that are unrelated to issue #466.
#[test]
fn test_diffguard_crate_fmt_check_passes() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut cmd = Command::new("cargo");
    cmd.arg("fmt").arg("--check").current_dir(manifest_dir);

    let output = cmd.output().expect("cargo fmt should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "cargo fmt --check failed for diffguard crate.\n\
         stdout: {}\n\
         stderr: {}\n\
         The problematic line was main.rs:645 - a 100-char line that needed braces.",
        stdout,
        stderr
    );
}
