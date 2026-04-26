//! Integration tests for the `diffguard doctor` subcommand.
//!
//! These are RED tests — they define expected behavior but will fail
//! because the `doctor` command has not been implemented yet.

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git should run");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_git_repo() -> TempDir {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);
    td
}

fn write_config(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("diffguard.toml");
    std::fs::write(&path, contents).expect("write config");
    path
}

/// Run diffguard doctor in the given directory and return (exit_code, stdout).
fn run_doctor(dir: &std::path::Path, extra_args: &[&str]) -> (i32, String) {
    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("doctor");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout)
}

// ---- FR1: Git availability check ----

#[test]
fn doctor_subcommand_exists() {
    let td = init_git_repo();
    let (code, _) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0, "doctor should succeed in a git repo");
}

#[test]
fn doctor_shows_git_pass_with_version() {
    let td = init_git_repo();
    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("git"),
        "stdout should mention git, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PASS"),
        "stdout should contain PASS, got:\n{}",
        stdout
    );
}

// ---- FR2: Git repository check ----

#[test]
fn doctor_reports_git_repo_pass_in_repo() {
    let td = init_git_repo();
    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("git-repo"),
        "should report git-repo check, got:\n{}",
        stdout
    );
    // The git-repo line should show PASS
    assert!(
        stdout.contains("PASS"),
        "should contain PASS, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_reports_git_repo_fail_outside_repo() {
    let td = TempDir::new().expect("temp");
    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 1, "should exit 1 when not in a git repo");
    assert!(
        stdout.contains("git-repo"),
        "should report git-repo, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "should contain FAIL, got:\n{}",
        stdout
    );
}

// ---- Edge case: doctor --config with stdin/pipe behavior ----

#[test]
fn doctor_with_config_flag_and_nonexistent_path() {
    let td = init_git_repo();

    let (code, stdout) = run_doctor(td.path(), &["--config", "/tmp/this/path/does/not/exist.toml"]);
    assert_eq!(code, 1, "should fail with nonexistent config path, got:\n{}", stdout);
    assert!(
        stdout.contains("config"),
        "should report config check, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "config should FAIL, got:\n{}",
        stdout
    );
}
        stdout.contains("PASS"),
        "config should PASS, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_with_invalid_config_fails() {
    let td = init_git_repo();
    let dir = td.path();

    // Invalid regex pattern
    let config_content = r#"
[[rule]]
id = "test.bad_regex"
description = "Bad regex"
severity = "error"
match = "[invalid(regex"
"#;
    write_config(dir, config_content);

    let (code, stdout) = run_doctor(dir, &[]);
    assert_eq!(code, 1, "should exit 1 with invalid config");
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "config should FAIL, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_no_config_passes_with_defaults_note() {
    let td = init_git_repo();
    // Do NOT create any config file

    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("config"),
        "should still report config check, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PASS"),
        "config should PASS with defaults, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_config_flag_missing_file_fails() {
    let td = init_git_repo();

    let (code, stdout) = run_doctor(td.path(), &["--config", "nonexistent.toml"]);
    assert_eq!(code, 1, "should exit 1 with missing config file");
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "config should FAIL, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_config_flag_valid_file_passes() {
    let td = init_git_repo();
    let dir = td.path();

    let config_path = dir.join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "custom.rule"
description = "Custom rule"
severity = "warn"
match = "breakpoint"
"#,
    )
    .unwrap();

    let (code, stdout) = run_doctor(dir, &["--config", "custom.toml"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PASS"),
        "config should PASS, got:\n{}",
        stdout
    );
}

// ---- FR5: Output format ----

#[test]
fn doctor_output_has_human_readable_format() {
    let td = init_git_repo();

    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("PASS"),
        "output should contain PASS, got:\n{}",
        stdout
    );
}

// ---- FR6: Exit code ----

#[test]
fn doctor_exit_code_zero_when_all_pass() {
    let td = init_git_repo();
    let (code, _) = run_doctor(td.path(), &[]);
    assert_eq!(code, 0);
}

#[test]
fn doctor_exit_code_one_when_any_check_fails() {
    let td = TempDir::new().expect("temp");
    let (code, _) = run_doctor(td.path(), &[]);
    assert_eq!(code, 1);
}

// ---- FR7: CLI integration ----

#[test]
fn doctor_help_shows_usage() {
    let mut cmd = diffguard_cmd();
    cmd.arg("doctor").arg("--help");
    let output = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "help should succeed");
    assert!(
        stdout.contains("doctor"),
        "help should mention doctor, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_config_flag_shown_in_help() {
    let mut cmd = diffguard_cmd();
    cmd.arg("doctor").arg("--help");
    let output = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(
        stdout.contains("--config"),
        "help should mention --config, got:\n{}",
        stdout
    );
}

// ---- Edge cases ----

#[test]
fn doctor_handles_duplicate_rule_ids() {
    let td = init_git_repo();
    let dir = td.path();

    let config_content = r#"
[[rule]]
id = "test.dup"
description = "First rule"
severity = "warn"
match = "foo"

[[rule]]
id = "test.dup"
description = "Duplicate rule"
severity = "error"
match = "bar"
"#;
    write_config(dir, config_content);

    let (code, stdout) = run_doctor(dir, &[]);
    assert_eq!(code, 1, "should exit 1 with duplicate rule IDs");
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "config should FAIL, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_all_checks_run_even_if_one_fails() {
    let td = TempDir::new().expect("temp");

    // Not in a git repo — git-repo fails, but all checks should appear
    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 1);
    assert!(
        stdout.contains("git"),
        "should report git check, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("git-repo"),
        "should report git-repo check, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("config"),
        "should report config check, got:\n{}",
        stdout
    );
}

// ---- Additional edge-case tests ----

#[test]
fn doctor_config_path_with_spaces_and_unicode() {
    let td = init_git_repo();
    let dir = td.path();

    // Create a subdirectory with spaces and unicode characters
    let subdir = dir.join("my config \u{1f4be}");
    std::fs::create_dir_all(&subdir).expect("create subdir");

    let config_path = subdir.join("diffguard.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "unicode.rule"
description = "Unicode path test"
severity = "warn"
match = "test"
"#,
    )
    .unwrap();

    let rel_path = "my config \u{1f4be}/diffguard.toml".to_string();
    let (code, stdout) = run_doctor(dir, &["--config", &rel_path]);
    assert_eq!(
        code, 0,
        "should handle config paths with spaces and unicode"
    );
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PASS"),
        "config should PASS, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_multiple_config_issues_at_once() {
    let td = init_git_repo();
    let dir = td.path();

    // Config with BOTH an invalid regex AND duplicate rule IDs
    let config_content = r#"
[[rule]]
id = "test.dup"
description = "First"
severity = "warn"
match = "foo"

[[rule]]
id = "test.dup"
description = "Duplicate"
severity = "error"
match = "[invalid(regex"
"#;
    write_config(dir, config_content);

    let (code, stdout) = run_doctor(dir, &[]);
    assert_eq!(code, 1, "should exit 1 with multiple config issues");
    assert!(
        stdout.contains("config"),
        "should report config, got:\n{}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "config should FAIL, got:\n{}",
        stdout
    );
}

#[test]
fn doctor_help_text_completeness() {
    let mut cmd = diffguard_cmd();
    cmd.arg("doctor").arg("--help");
    let output = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "help should succeed");
    // Check that help describes what doctor does
    assert!(
        stdout.to_lowercase().contains("check") || stdout.to_lowercase().contains("diagnos"),
        "help should describe doctor purpose, got:\n{}",
        stdout
    );
    // Check --config flag is documented
    assert!(stdout.contains("--config"), "help should mention --config");
    // Check usage line exists
    assert!(
        stdout.contains("Usage:")
            || stdout.contains("Usage ")
            || stdout.contains("diffguard doctor"),
        "help should show usage, got:\n{}",
        stdout
    );
}
