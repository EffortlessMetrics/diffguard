//! Red tests for work-d69e4759: `ConfigFile::built_in()` missing `# Panics` section
//!
//! These tests verify that `ConfigFile::built_in()` in `diffguard-types` has proper
//! documentation for its panic behavior, satisfying the `clippy::missing_panics_doc` lint.
//!
//! The `#[must_use]` attribute on `built_in()` signals callers must handle the return value,
//! but without a `# Panics` section, the doc comment misleads callers into thinking the
//! function is infallible. The `.expect()` call inside the function panics if
//! `rules/built_in.json` is missing, not valid UTF-8, or fails to parse as `ConfigFile`.
//!
//! These tests document the expected behavior:
//! - `ConfigFile::built_in()` MUST have a `# Panics` section in its doc comment
//! - The `# Panics` section MUST document that the function panics if `rules/built_in.json`
//!   is missing, not valid UTF-8, or fails to parse as `ConfigFile` JSON
//! - Running `cargo clippy -p diffguard-types -- -W clippy::missing_panics_doc` MUST
//!   produce ZERO warnings

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Find the workspace root by looking for Cargo.toml
fn find_workspace_root() -> PathBuf {
    let mut dir = env::current_dir().expect("Could not get current directory");
    loop {
        if dir.join("Cargo.toml").exists() {
            return dir;
        }
        dir = dir.parent().expect("Reached filesystem root").to_path_buf();
    }
}

/// Test that `cargo clippy` with `missing_panics_doc` lint produces zero warnings
/// for `ConfigFile::built_in()`.
///
/// This test verifies that the `# Panics` section has been properly added to the
/// doc comment on `ConfigFile::built_in()`.
///
/// Before the fix: This test FAILS because `clippy::missing_panics_doc` warns about
/// the missing `# Panics` section.
///
/// After the fix: This test PASSES because the `# Panics` section satisfies the lint.
#[test]
fn configfile_built_in_has_panics_doc_section() {
    let workspace_root = find_workspace_root();
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-types",
            "--",
            "-W",
            "clippy::missing_panics_doc",
        ])
        .current_dir(&workspace_root)
        .output()
        .expect("Failed to execute cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}\n{}", stdout, stderr);

    // The lint should produce ZERO warnings about missing `# Panics` section
    // If there are warnings about `built_in()` and `missing_panics_doc`, the test fails
    assert!(
        !combined_output.contains("missing `# Panics` section")
            || !combined_output.contains("built_in"),
        "clippy::missing_panics_doc should NOT warn about ConfigFile::built_in() after adding `# Panics` section. \
         Got output:\n{}",
        combined_output
    );

    // Also verify the lint check passes (exit code 0 means no warnings with -W flag)
    assert!(
        output.status.success(),
        "cargo clippy with -W clippy::missing_panics_doc should succeed (zero warnings). \
         Exit code: {:?}. Output:\n{}",
        output.status.code(),
        combined_output
    );
}

/// Test that running `cargo doc -p diffguard-types --no-deps` succeeds without warnings.
///
/// This verifies that the `# Panics` section is valid Rustdoc syntax that renders correctly.
///
/// Before the fix: This test may still pass (doc comment compiles fine without Panics section)
/// but the lint warning exists.
///
/// After the fix: This test continues to pass (doc comment with Panics section renders fine).
#[test]
fn diffguard_types_doc_compiles_cleanly() {
    let workspace_root = find_workspace_root();
    let output = Command::new("cargo")
        .args(["doc", "-p", "diffguard-types", "--no-deps"])
        .current_dir(&workspace_root)
        .output()
        .expect("Failed to execute cargo doc");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}\n{}", stdout, stderr);

    // Documentation should compile without errors or warnings
    assert!(
        output.status.success(),
        "cargo doc -p diffguard-types --no-deps should succeed. Exit code: {:?}. Output:\n{}",
        output.status.code(),
        combined_output
    );
}

/// Test that `cargo test -p diffguard-types` passes after the fix.
///
/// This is a regression test to ensure the documentation change doesn't break any tests.
///
/// Before the fix: This test passes (pure documentation change doesn't affect tests)
///
/// After the fix: This test continues to pass
#[test]
fn diffguard_types_tests_still_pass() {
    let workspace_root = find_workspace_root();
    let output = Command::new("cargo")
        .args(["test", "-p", "diffguard-types"])
        .current_dir(&workspace_root)
        .output()
        .expect("Failed to execute cargo test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}\n{}", stdout, stderr);

    assert!(
        output.status.success(),
        "cargo test -p diffguard-types should pass. Exit code: {:?}. Output:\n{}",
        output.status.code(),
        combined_output
    );
}
