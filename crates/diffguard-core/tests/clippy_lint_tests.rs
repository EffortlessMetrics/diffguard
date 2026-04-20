//! Red tests to verify clippy::uninlined_format_args warnings are fixed.
//!
//! These tests run `cargo clippy` with the uninlined_format_args lint enabled
//! and assert that there are 0 warnings. These tests should:
//! - FAIL before the fix (warnings exist)
//! - PASS after the fix (all format args are inlined)

use std::process::Command;

/// Parse clippy output to count warnings for a specific crate.
/// Returns the count and the relevant output for debugging.
fn get_warning_count_for_crate(crate_name: &str) -> (usize, String) {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            crate_name,
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let combined = format!("{}\n{}", stdout, stderr);

    // Count warnings in the specified crate by looking for the --> marker
    // with the crate path
    let crate_marker = format!("crates/{}/", crate_name);
    let warnings: Vec<_> = combined
        .lines()
        .filter(|line| line.contains(&crate_marker) && line.contains(".rs:"))
        .collect();

    (warnings.len(), combined)
}

/// Test that diffguard-lsp has no uninlined_format_args warnings.
///
/// Before fix: 28 warnings in server.rs (19), config.rs (6), text.rs (3)
/// After fix: 0 warnings
#[test]
fn test_diffguard_lsp_no_uninlined_format_args_warnings() {
    let (warning_count, full_output) = get_warning_count_for_crate("diffguard-lsp");

    assert_eq!(
        warning_count, 0,
        "diffguard-lsp should have 0 uninlined_format_args warnings, but found {}.\n\
         Expected: The warnings in:\n\
         - server.rs (19 warnings)\n\
         - config.rs (6 warnings)\n\
         - text.rs (3 warnings)\n\
         should all be fixed by using inline format args like format!(\"{{var}}\") \
         instead of format!(\"{{var}}\", var = var)",
        warning_count
    );
}

/// Test that diffguard-core has no uninlined_format_args warnings.
///
/// Before fix: 3 warnings in csv.rs (1), checkstyle.rs (1), junit.rs (1)
/// After fix: 0 warnings
#[test]
fn test_diffguard_core_no_uninlined_format_args_warnings() {
    let (warning_count, full_output) = get_warning_count_for_crate("diffguard-core");

    assert_eq!(
        warning_count, 0,
        "diffguard-core should have 0 uninlined_format_args warnings, but found {}.\n\
         Expected: The warnings in:\n\
         - csv.rs (1 warning)\n\
         - checkstyle.rs (1 warning)\n\
         - junit.rs (1 warning)\n\
         should all be fixed by using inline format args like format!(\"{{var}}\") \
         instead of format!(\"{{var}}\", var = var)",
        warning_count
    );
}
