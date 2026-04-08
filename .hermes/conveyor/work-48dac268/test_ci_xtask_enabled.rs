// RED TEST: Verify xtask CI job is enabled and --exclude xtask is removed
//
// These tests define the target behavior for work-48dac268:
// Enable xtask CI job and run full workspace tests.
//
// AC1: .github/workflows/ci.yml line 40 uses `cargo test --workspace` (no `--exclude xtask`)
// AC2: .github/workflows/ci.yml line 45-46 xtask job has no `if: false` condition (job is enabled)

use std::path::Path;

/// Path to the CI workflow file (absolute path to diffguard repo)
const CI_YAML_PATH: &str = "/home/hermes/repos/diffguard/.github/workflows/ci.yml";

/// Extracts a specific line range from a file
fn get_line(file_content: &str, line_num: usize) -> Option<&str> {
    file_content.lines().nth(line_num.saturating_sub(1))
}

/// Verifies that line 40 of ci.yml uses `cargo test --workspace` WITHOUT `--exclude xtask`
#[test]
fn test_ci_yml_test_job_no_exclude_xtask() {
    let ci_path = Path::new(CI_YAML_PATH);
    let content = std::fs::read_to_string(ci_path)
        .expect("ci.yml should exist and be readable");

    // Line 40 should contain `cargo test --workspace` without `--exclude xtask`
    let line_40 = get_line(&content, 40)
        .expect("ci.yml should have at least 40 lines");

    // Assert that line 40 contains `cargo test --workspace`
    assert!(
        line_40.contains("cargo test --workspace"),
        "Line 40 should contain 'cargo test --workspace', but got: {}",
        line_40
    );

    // Assert that line 40 does NOT contain `--exclude xtask`
    assert!(
        !line_40.contains("--exclude xtask"),
        "Line 40 should NOT contain '--exclude xtask', but got: {}",
        line_40
    );
}

/// Verifies that the xtask CI job (around line 45-46) has NO `if: false` condition
#[test]
fn test_ci_yml_xtask_job_enabled() {
    let ci_path = Path::new(CI_YAML_PATH);
    let content = std::fs::read_to_string(ci_path)
        .expect("ci.yml should exist and be readable");

    // The xtask job section starts around line 42-43
    // Line 45 (xtask job) should NOT contain `if: false`
    let line_45 = get_line(&content, 45)
        .expect("ci.yml should have at least 45 lines");

    // Assert that line 45 does NOT contain `if: false`
    assert!(
        !line_45.contains("if: false"),
        "Line 45 (xtask job) should NOT contain 'if: false' (job should be enabled), but got: {}",
        line_45
    );
}

/// Verifies the xtask job has `cargo run -p xtask -- ci` command
#[test]
fn test_ci_yml_xtask_job_runs_ci_command() {
    let ci_path = Path::new(CI_YAML_PATH);
    let content = std::fs::read_to_string(ci_path)
        .expect("ci.yml should exist and be readable");

    // Line 49 should contain the xtask ci command
    let line_49 = get_line(&content, 49)
        .expect("ci.yml should have at least 49 lines");

    // Assert that line 49 contains `cargo run -p xtask -- ci`
    assert!(
        line_49.contains("cargo run -p xtask -- ci"),
        "Line 49 should contain 'cargo run -p xtask -- ci', but got: {}",
        line_49
    );
}

/// Verifies the overall structure: test job exists and xtask job exists
#[test]
fn test_ci_yml_has_both_test_and_xtask_jobs() {
    let ci_path = Path::new(CI_YAML_PATH);
    let content = std::fs::read_to_string(ci_path)
        .expect("ci.yml should exist and be readable");

    // Verify test job exists
    assert!(
        content.contains("name: Test"),
        "CI workflow should have a 'Test' job"
    );

    // Verify xtask job exists
    assert!(
        content.contains("name: xtask ci"),
        "CI workflow should have an 'xtask ci' job"
    );
}
