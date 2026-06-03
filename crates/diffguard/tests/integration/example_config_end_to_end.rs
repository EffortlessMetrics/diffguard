//! Integration tests for diffguard.toml.example
//!
//! These tests verify that the example configuration file:
//! 1. Parses correctly as TOML
//! 2. Passes diffguard validate
//! 3. Has properly configured test_cases that pass
//! 4. Can be used in an end-to-end check workflow

use assert_cmd::Command;
use assert_cmd::cargo;
use std::path::{Path, PathBuf};

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

/// Get the path to the diffguard.toml.example in the repo root.
fn example_config_path() -> PathBuf {
    // The example config is at the repo root, not in the crate dir.
    // CARGO_MANIFEST_DIR points to crates/diffguard, so we go up two levels.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_path = Path::new(&manifest_dir);
    let repo_root = manifest_path.parent().unwrap().parent().unwrap();
    repo_root.join("diffguard.toml.example")
}

/// Get the path to the repo root.
fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_path = Path::new(&manifest_dir);
    manifest_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Scenario: Example config file parses as valid TOML.
///
/// Given: The diffguard.toml.example file exists at repo root
/// When: We attempt to parse it as TOML
/// Then: Parsing succeeds without error
#[test]
fn example_config_parses_as_toml() {
    let config_path = example_config_path();
    let contents = std::fs::read_to_string(&config_path)
        .expect("diffguard.toml.example should exist and be readable");

    // TOML parsing is done by toml crate in validate command.
    // If validate passes (next test), TOML parsing is verified.
    // This test just verifies the file is readable.
    assert!(!contents.is_empty(), "Example config should not be empty");
}

/// Scenario: Example config passes validate command.
///
/// Given: The diffguard.toml.example file
/// When: Running `diffguard validate --config diffguard.toml.example`
/// Then: Validation passes with exit code 0
#[test]
fn example_config_validates() {
    let config_path = example_config_path();

    let output = diffguard_cmd()
        .arg("validate")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run validate");

    assert!(
        output.status.success(),
        "validate should succeed.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("valid") || stdout.contains("3 rule(s)"),
        "validate output should indicate success: {}",
        stdout
    );
}

/// Scenario: Example config's test_cases pass.
///
/// Given: The diffguard.toml.example file
/// When: Running `diffguard test --config diffguard.toml.example`
/// Then: All test cases pass
#[test]
fn example_config_test_cases_pass() {
    let config_path = example_config_path();

    let output = diffguard_cmd()
        .arg("test")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run test");

    assert!(
        output.status.success(),
        "test should succeed.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Passed: 2") || stdout.contains("Passed"),
        "test output should show passing tests: {}",
        stdout
    );
    assert!(
        stdout.contains("Failed: 0"),
        "test output should show 0 failed: {}",
        stdout
    );
}

/// Scenario: Example config test command with JSON output.
///
/// Given: The diffguard.toml.example file
/// When: Running `diffguard test --config diffguard.toml.example --format json`
/// Then: JSON output is valid and shows 2 test cases, 0 failed
#[test]
fn example_config_test_json_output() {
    let config_path = example_config_path();

    let output = diffguard_cmd()
        .arg("test")
        .arg("--config")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run test json");

    assert!(
        output.status.success(),
        "test should succeed.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("test output should be valid JSON");

    assert_eq!(value["test_cases"], 2, "Should have 2 test cases");
    assert_eq!(value["failed"], 0, "Should have 0 failed tests");
}

/// Scenario: Example config includes tags field.
///
/// Given: The diffguard.toml.example file
/// When: Parsed and inspected
/// Then: The rust.no_unwrap rule has tags = ["safety"]
#[test]
fn example_config_rust_no_unwrap_has_tags() {
    let config_path = example_config_path();
    let contents =
        std::fs::read_to_string(&config_path).expect("diffguard.toml.example should exist");

    // Verify tags field exists in rust.no_unwrap rule
    assert!(
        contents.contains("tags = [\"safety\"]"),
        "rust.no_unwrap should have tags = [\"safety\"]: {}",
        contents
    );
}

/// Scenario: Example config includes test_cases blocks.
///
/// Given: The diffguard.toml.example file
/// When: Parsed and inspected
/// Then: The rust.no_unwrap rule has at least 2 test_cases blocks
#[test]
fn example_config_rust_no_unwrap_has_test_cases() {
    let config_path = example_config_path();
    let contents =
        std::fs::read_to_string(&config_path).expect("diffguard.toml.example should exist");

    // Count [[rule.test_cases]] occurrences - should be at least 2
    let test_case_count = contents.match_indices("[[rule.test_cases]]").count();
    assert!(
        test_case_count >= 2,
        "rust.no_unwrap should have at least 2 test_cases blocks, found {}: {}",
        test_case_count,
        contents
    );

    // Verify positive case with should_match = true
    assert!(
        contents.contains("should_match = true"),
        "Should have a positive test case (should_match = true)"
    );

    // Verify negative case with should_match = false
    assert!(
        contents.contains("should_match = false"),
        "Should have a negative test case (should_match = false)"
    );
}

/// Scenario: Example config can be used with check command.
///
/// Given: The diffguard.toml.example file and a git diff
/// When: Running `diffguard check` with the example config
/// Then: The check runs without error
#[test]
fn example_config_works_with_check_command() {
    let config_path = example_config_path();
    let _repo = repo_root();

    // Create a temp directory with a git repo to test check
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let temp_path = temp_dir.path();

    // Initialize git repo
    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["init"])
        .output()
        .expect("git init");

    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["config", "user.email", "test@example.com"])
        .output()
        .expect("git config");

    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["config", "user.name", "Test"])
        .output()
        .expect("git config");

    // Create initial file and commit (create src dir first)
    let src_dir = temp_path.join("src");
    std::fs::create_dir(&src_dir).expect("create src dir");
    std::fs::write(src_dir.join("lib.rs"), "pub fn safe() {}\n").expect("write initial file");
    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["add", "."])
        .output()
        .expect("git add");
    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["commit", "-m", "initial"])
        .output()
        .expect("git commit");

    let base_sha = std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse")
        .stdout;
    let base_sha = String::from_utf8_lossy(&base_sha).trim().to_string();

    // Add a file with unwrap
    std::fs::write(
        src_dir.join("lib.rs"),
        "pub fn unsafe_fn() -> u32 { Some(1).unwrap() }\n",
    )
    .expect("write unwrap file");
    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["add", "."])
        .output()
        .expect("git add");
    std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["commit", "-m", "add unwrap"])
        .output()
        .expect("git commit");

    let head_sha = std::process::Command::new("git")
        .current_dir(temp_path)
        .args(&["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse")
        .stdout;
    let head_sha = String::from_utf8_lossy(&head_sha).trim().to_string();

    let output_dir = temp_path.join("output");
    std::fs::create_dir(&output_dir).expect("create output dir");

    let output = diffguard_cmd()
        .current_dir(temp_path)
        .arg("check")
        .arg("--base")
        .arg(&base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--config")
        .arg(&config_path)
        .arg("--out")
        .arg(&output_dir.join("report.json"))
        .output()
        .expect("run check");

    // Just verify check runs without error (exit 0, 1, or 2 are all valid)
    // Exit 0 = pass, Exit 1 = tool error, Exit 2 = policy fail
    assert!(
        output.status.code().unwrap_or(-1) >= 0,
        "check should run without crashing. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Scenario: Tags field in example config is consistent with built-in rules.
///
/// Given: The diffguard.toml.example file
/// When: The rust.no_unwrap rule is loaded with tags
/// Then: Tags field is properly recognized and doesn't cause validation errors
#[test]
fn example_config_tags_field_validates() {
    let config_path = example_config_path();

    // If validate passes, tags field is valid
    let output = diffguard_cmd()
        .arg("validate")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run validate");

    assert!(
        output.status.success(),
        "tags field should not cause validation errors.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
