//! Snapshot tests for diffguard.toml.example CLI outputs.
//!
//! These tests capture the current output of diffguard commands when run
//! against the example configuration file. Any change to the output will
//! be detected by these tests.
//!
//! Coverage:
//! 1. validate --config diffguard.toml.example
//! 2. test --config diffguard.toml.example
//! 3. explain rust.no_unwrap --config diffguard.toml.example

use assert_cmd::Command;
use assert_cmd::cargo;
use std::path::{Path, PathBuf};

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

/// Returns the path to the repo root (parent of the crate's manifest dir).
/// CARGO_MANIFEST_DIR = crates/diffguard, so we go up two levels to repo root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Snapshot test: validate command on example config file.
/// This captures the output when validating a well-formed config with
/// the new tags and test_cases fields.
#[test]
fn snapshot_validate_example_config() {
    let mut cmd = diffguard_cmd();
    cmd.current_dir(repo_root())
        .arg("validate")
        .arg("--config")
        .arg("diffguard.toml.example");

    let output = cmd.output().expect("validate should succeed");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    insta::assert_snapshot!(
        "snapshot_validate_example_config",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, stdout, stderr
        )
    );
}

/// Snapshot test: test command on example config file.
/// This captures the output when running test cases defined in the
/// diffguard.toml.example file (including the new test_cases blocks).
#[test]
fn snapshot_test_example_config() {
    let mut cmd = diffguard_cmd();
    cmd.current_dir(repo_root())
        .arg("test")
        .arg("--config")
        .arg("diffguard.toml.example");

    let output = cmd.output().expect("test should succeed");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    insta::assert_snapshot!(
        "snapshot_test_example_config",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, stdout, stderr
        )
    );
}

/// Snapshot test: explain command for rust.no_unwrap rule.
/// This captures the detailed output for a rule that has both
/// tags and test_cases defined in the example config.
#[test]
fn snapshot_explain_rust_no_unwrap() {
    let mut cmd = diffguard_cmd();
    cmd.current_dir(repo_root())
        .arg("explain")
        .arg("rust.no_unwrap")
        .arg("--config")
        .arg("diffguard.toml.example");

    let output = cmd.output().expect("explain should succeed");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    insta::assert_snapshot!(
        "snapshot_explain_rust_no_unwrap",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, stdout, stderr
        )
    );
}

/// Snapshot test: rules command on example config (first 50 lines).
/// This captures the effective rules output showing how the example
/// config merges with built-in rules.
#[test]
fn snapshot_rules_example_config_head() {
    let mut cmd = diffguard_cmd();
    cmd.current_dir(repo_root())
        .arg("rules")
        .arg("--config")
        .arg("diffguard.toml.example");

    let output = cmd.output().expect("rules should succeed");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Only snapshot the first 50 lines of output to keep snapshot size manageable
    let stdout_head: String = stdout.lines().take(50).collect::<Vec<_>>().join("\n");

    insta::assert_snapshot!(
        "snapshot_rules_example_config_head",
        format!(
            "exit_code={:?}\n\nSTDOUT (first 50 lines):\n{}\n\nSTDERR:\n{}",
            exit_code, stdout_head, stderr
        )
    );
}
