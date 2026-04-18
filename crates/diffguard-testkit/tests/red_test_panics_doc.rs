//! Red test for verifying diffguard-testkit functions have # Panics documentation.
//!
//! This test verifies that all public functions in diffguard-testkit that can panic
//! have proper `# Panics` sections in their doc comments.
//!
//! The 8 functions missing # Panics documentation are:
//! 1. arb::arb_non_empty_string() - uses .expect() on regex generation
//! 2. arb::arb_line_content() - uses .expect() on regex generation
//! 3. arb::arb_safe_line_content() - uses .expect() on regex generation
//! 4. diff_builder::DiffBuilder::add_file() - uses assert! for MAX_FILES
//! 5. schema::load_config_schema() - uses .expect() on JSON parse
//! 6. schema::load_check_schema() - uses .expect() on JSON parse
//! 7. schema::validate_config_file() - uses .expect() on JSON serialize
//! 8. schema::validate_check_receipt() - uses .expect() on JSON serialize

use std::process::Command;

#[test]
fn test_diffguard_testkit_has_panics_documentation() {
    // Run clippy with missing_panics_doc lint on diffguard-testkit
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-testkit",
            "--no-deps",
            "--",
            "-D",
            "clippy::missing_panics_doc",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Print output for debugging
    if !stderr.is_empty() {
        eprintln!("clippy stderr:\n{}", stderr);
    }
    if !stdout.is_empty() {
        eprintln!("clippy stdout:\n{}", stdout);
    }

    // The test passes if clippy exits with success (no errors)
    // It fails if clippy exits with error (missing panics docs found)
    assert!(
        output.status.success(),
        "clippy::missing_panics_doc found {} missing # Panics documentation.\n\
        Run `cargo clippy -p diffguard-testkit --no-deps -- -D clippy::missing_panics_doc` to see all occurrences.\n\
        Expected: 0 missing # Panics docs\n\
        Actual: clippy exited with status {:?}\n\
        stderr: {}\n\
        stdout: {}",
        count_missing_panics_errors(&stderr),
        output.status,
        stderr,
        stdout
    );
}

/// Count the number of "missing `# Panics` section" errors in clippy output
fn count_missing_panics_errors(output: &str) -> usize {
    output
        .lines()
        .filter(|line| {
            line.contains("docs for function which may panic missing `# Panics` section")
        })
        .count()
}
