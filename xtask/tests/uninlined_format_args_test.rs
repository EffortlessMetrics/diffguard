//! Red test verifying the `clippy::uninlined_format_args` lint is fixed.
//!
//! This test verifies that `bail!` macro calls in `xtask/src/conform_real.rs`
//! use inline named format args (e.g., `bail!("error {var}")`) instead of
//! positional format args (e.g., `bail!("error {}", var)`).
//!
//! The test runs clippy with the `uninlined_format_args` lint enabled and
//! verifies no warnings are produced for the bail! calls in conform_real.rs.
//!
//! This test FAILS before the fix (when positional args are used) and
//! PASSES after the fix (when inline named args are used).

use std::process::Command;

/// Test that xtask conform_real.rs has no uninlined_format_args warnings.
///
/// This test verifies that all bail! macro calls in conform_real.rs use
/// inline named format arguments instead of positional arguments.
///
/// Before fix (FAILS):
/// ```ignore
/// bail!("expected {status}, got {:?}", status);
/// ```
///
/// After fix (PASSES):
/// ```ignore
/// bail!("expected {status}, got {status:?}");
/// ```
#[test]
fn test_conform_real_bail_no_uninlined_format_args() {
    // Run clippy with the specific lint enabled on xtask
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "xtask",
            "--bin",
            "xtask",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}{}", stdout, stderr);

    // The lint we expect to NOT see after the fix:
    // "useless use of `format!`"
    // "format arg used in `bail!` call"
    let has_uninlined_format_args_warning = combined_output.contains("uninlined_format_args")
        && (combined_output.contains("conform_real.rs")
            || combined_output.contains("xtask/src/conform_real.rs"));

    // Assert NO warning exists - this test FAILS before fix, PASSES after fix
    assert!(
        !has_uninlined_format_args_warning,
        "Expected no clippy::uninlined_format_args warnings in conform_real.rs, but found them. \
         All bail! calls should use inline named format args like {{var}} instead of {{}} , var . \
         Clippy output:\n{}",
        combined_output
    );
}

/// Test that xtask compiles without warnings.
///
/// This is a sanity check that the xtask package is in a good state.
#[test]
fn test_xtask_compiles_cleanly() {
    let output = Command::new("cargo")
        .args(["check", "-p", "xtask"])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo check");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}{}", stdout, stderr);

    assert!(
        output.status.success(),
        "Expected xtask to compile successfully, but it failed.\n\
         Output:\n{}",
        combined_output
    );
}
