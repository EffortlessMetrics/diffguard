//! Property tests for `validate_config_for_doctor` function invariants.
//!
//! These tests verify the behavioral invariants of the config validation
//! logic used by the `doctor` subcommand. Since `validate_config_for_doctor`
//! is a private function, we test through the CLI interface.
//!
//! Invariants tested:
//! 1. Determinism: same inputs → same outputs
//! 2. explicit_config=true with missing config → FAIL
//! 3. explicit_config=false with no config → PASS (defaults)
//! 4. Valid config → PASS
//! 5. Invalid regex in config → FAIL
//! 6. Duplicate Rule IDs → FAIL
//! 7. Idempotence: running doctor twice gives same result

use assert_cmd::Command;
use assert_cmd::cargo;
use std::path::Path;
use tempfile::TempDir;

/// Run diffguard doctor in the given directory and return (exit_code, stdout).
fn run_doctor(dir: &Path, extra_args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir).arg("doctor");
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().expect("command should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (code, stdout)
}

fn init_git_repo() -> TempDir {
    let td = TempDir::new().expect("temp");
    let dir = td.path();
    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);
    td
}

fn run_git(dir: &Path, args: &[&str]) -> String {
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

// ---- Property 1: Determinism ----
// Running doctor with the same inputs should produce the same outputs

#[test]
fn property_determinism_no_config() {
    let td = init_git_repo();
    let dir = td.path();

    // Run multiple times with no config
    let results: Vec<(i32, String)> = (0..10).map(|_| run_doctor(dir, &[])).collect();

    // All runs should be identical
    for (i, (code, stdout)) in results.iter().enumerate() {
        assert_eq!(
            *code, results[0].0,
            "Run {} exit code differs from first run",
            i
        );
        assert_eq!(
            stdout, &results[0].1,
            "Run {} stdout differs from first run",
            i
        );
    }
}

#[test]
fn property_determinism_with_valid_config() {
    let td = init_git_repo();
    let dir = td.path();

    // Write a valid config - using patterns = [...] array syntax
    let config_content = r#"
[[rule]]
id = "test.rule"
description = "Test rule"
severity = "error"
patterns = ["test"]
"#;
    std::fs::write(dir.join("diffguard.toml"), config_content).unwrap();

    // Run multiple times
    let results: Vec<(i32, String)> = (0..10).map(|_| run_doctor(dir, &[])).collect();

    // All runs should be identical
    for (i, (code, stdout)) in results.iter().enumerate() {
        assert_eq!(
            *code, results[0].0,
            "Run {} exit code differs from first run",
            i
        );
        assert_eq!(
            stdout, &results[0].1,
            "Run {} stdout differs from first run",
            i
        );
    }
}

#[test]
fn property_determinism_with_invalid_config() {
    let td = init_git_repo();
    let dir = td.path();

    // Write an invalid config (bad regex) - using patterns = [...]
    let config_content = r#"
[[rule]]
id = "test.rule"
description = "Test rule"
severity = "error"
patterns = ["[invalid(regex"]
"#;
    std::fs::write(dir.join("diffguard.toml"), config_content).unwrap();

    // Run multiple times
    let results: Vec<(i32, String)> = (0..10).map(|_| run_doctor(dir, &[])).collect();

    // All runs should be identical
    for (i, (code, stdout)) in results.iter().enumerate() {
        assert_eq!(
            *code, results[0].0,
            "Run {} exit code differs from first run",
            i
        );
        assert_eq!(
            stdout, &results[0].1,
            "Run {} stdout differs from first run",
            i
        );
    }
}

// ---- Property 2: explicit_config=true with missing config → FAIL ----

#[test]
fn property_explicit_config_missing_file_fails() {
    let td = init_git_repo();
    let dir = td.path();

    // Use --config with a non-existent file
    let (code, stdout) = run_doctor(dir, &["--config", "nonexistent_config_abc123.toml"]);

    assert_eq!(
        code, 1,
        "Exit code should be 1 when explicit config is missing"
    );
    assert!(
        stdout.contains("config"),
        "Output should mention config: {}",
        stdout
    );
    assert!(
        stdout.contains("FAIL"),
        "Output should show FAIL: {}",
        stdout
    );
}

// ---- Property 3: explicit_config=false with no config → PASS (defaults) ----

#[test]
fn property_no_config_uses_defaults() {
    let td = init_git_repo();
    let dir = td.path();

    // Don't create any config file
    let (code, stdout) = run_doctor(dir, &[]);

    assert_eq!(
        code, 0,
        "Exit code should be 0 when no config and none expected"
    );
    assert!(
        stdout.contains("config"),
        "Output should mention config: {}",
        stdout
    );
    assert!(
        stdout.contains("PASS"),
        "Output should show PASS with defaults: {}",
        stdout
    );
}

// ---- Property 4: Valid config → PASS ----

#[test]
fn property_valid_config_passes() {
    let td = init_git_repo();
    let _dir = td.path();

    // Create a valid config - using patterns = [...] array syntax
    let configs = vec![
        // Minimal valid config
        r#"
[[rule]]
id = "test.minimal"
description = "Minimal rule"
severity = "error"
patterns = ["test"]
"#,
        // Config with multiple rules
        r#"
[[rule]]
id = "test.rule1"
description = "Rule 1"
severity = "error"
patterns = ["foo"]

[[rule]]
id = "test.rule2"
description = "Rule 2"
severity = "error"
patterns = ["bar"]
"#,
    ];

    for config_content in configs {
        let td = init_git_repo();
        std::fs::write(td.path().join("diffguard.toml"), config_content).unwrap();

        let (code, stdout) = run_doctor(td.path(), &[]);
        assert_eq!(code, 0, "Valid config should PASS: {}", stdout);
        assert!(
            stdout.contains("config"),
            "Output should mention config: {}",
            stdout
        );
        assert!(
            stdout.contains("PASS"),
            "Valid config should show PASS: {}",
            stdout
        );
    }
}

// ---- Property 5: Invalid regex in config → FAIL ----

#[test]
fn property_invalid_regex_fails() {
    let _td = init_git_repo();

    // Invalid regex patterns - using patterns = [...]
    let invalid_patterns = vec![
        "[unclosed", // Unclosed bracket
        "(unclosed", // Unclosed paren
        "*invalid",  // Quantifier at start
        "+invalid",  // Quantifier at start
        "???",       // Multiple quantifiers
        "[",         // Just a bracket
        "(",         // Just a paren
    ];

    for pattern in invalid_patterns {
        let td = init_git_repo();
        let config_content = format!(
            r#"
[[rule]]
id = "test.invalid"
description = "Invalid regex test"
severity = "error"
patterns = ["{}"]
"#,
            pattern
        );
        std::fs::write(td.path().join("diffguard.toml"), config_content).unwrap();

        let (code, stdout) = run_doctor(td.path(), &[]);
        assert_eq!(
            code, 1,
            "Invalid regex should FAIL: pattern={}, output={}",
            pattern, stdout
        );
        assert!(
            stdout.contains("FAIL"),
            "Should show FAIL for invalid regex: {}",
            stdout
        );
    }
}

// ---- Property 6: Duplicate Rule IDs → FAIL ----

#[test]
fn property_duplicate_rule_ids_fails() {
    let _td = init_git_repo();

    // Duplicate rule IDs - using [[rule]] (singular) with patterns
    let config_content = r#"
[[rule]]
id = "test.dup"
description = "First"
severity = "error"
patterns = ["foo"]

[[rule]]
id = "test.dup"
description = "Duplicate"
severity = "error"
patterns = ["bar"]
"#;

    let td = init_git_repo();
    std::fs::write(td.path().join("diffguard.toml"), config_content).unwrap();

    let (code, stdout) = run_doctor(td.path(), &[]);
    assert_eq!(code, 1, "Duplicate rule IDs should FAIL: output={}", stdout);
    assert!(
        stdout.contains("FAIL"),
        "Should show FAIL for duplicate rule IDs: {}",
        stdout
    );
}

// ---- Property 7: Idempotence ----
// Running doctor twice in a row gives same result (no side effects)

#[test]
fn property_idempotence_no_config() {
    let td = init_git_repo();
    let dir = td.path();

    // First run
    let (code1, stdout1) = run_doctor(dir, &[]);

    // Second run (in same directory, same state)
    let (code2, stdout2) = run_doctor(dir, &[]);

    assert_eq!(
        code1, code2,
        "First and second run should have same exit code"
    );
    assert_eq!(
        stdout1, stdout2,
        "First and second run should have same output"
    );
}

#[test]
fn property_idempotence_with_config() {
    let td = init_git_repo();
    let dir = td.path();

    // Write a valid config
    let config_content = r#"
[[rule]]
id = "test.rule"
description = "Test rule"
severity = "error"
patterns = ["test"]
"#;
    std::fs::write(dir.join("diffguard.toml"), config_content).unwrap();

    // First run
    let (code1, stdout1) = run_doctor(dir, &[]);

    // Second run
    let (code2, stdout2) = run_doctor(dir, &[]);

    assert_eq!(
        code1, code2,
        "First and second run should have same exit code"
    );
    assert_eq!(
        stdout1, stdout2,
        "First and second run should have same output"
    );
}

// ---- Property 8: Bounded output ----
// Exit code should always be 0 or 1 (never negative except -1 for errors)

#[test]
fn property_bounded_exit_code() {
    let _td = init_git_repo();

    let test_cases = vec![
        // No config - exit code 0
        (&[] as &[&str], 0),
    ];

    for (args, _expected_min) in test_cases {
        let td = init_git_repo();
        let dir = td.path();

        if !args.is_empty() {
            // Create a valid config
            let config_content = r#"
[[rule]]
id = "test"
description = "Test"
severity = "error"
patterns = ["test"]
"#;
            std::fs::write(dir.join("diffguard.toml"), config_content).unwrap();
        }

        let (code, stdout) = run_doctor(dir, args);
        assert!(
            code >= 0 && code <= 1,
            "Exit code should be 0 or 1, got {} for args {:?}: {}",
            code,
            args,
            stdout
        );
    }
}

// ---- Property 9: Monotonicity of explicit_config ----
// If config exists and is valid, explicit_config=true and explicit_config=false should both PASS

#[test]
fn property_explicit_flag_does_not_affect_valid_config() {
    let td = init_git_repo();
    let dir = td.path();

    let config_content = r#"
[[rule]]
id = "test.rule"
description = "Test rule"
severity = "error"
patterns = ["test"]
"#;
    let config_path = dir.join("my_config.toml");
    std::fs::write(&config_path, config_content).unwrap();

    // Run with explicit config
    let (code_explicit, stdout_explicit) = run_doctor(dir, &["--config", "my_config.toml"]);

    // Run without explicit config (uses diffguard.toml in cwd)
    let td2 = init_git_repo();
    std::fs::write(td2.path().join("diffguard.toml"), config_content).unwrap();
    let (code_default, stdout_default) = run_doctor(td2.path(), &[]);

    // Both should PASS for valid config
    assert_eq!(
        code_explicit, 0,
        "Valid explicit config should PASS: {}",
        stdout_explicit
    );
    assert_eq!(
        code_default, 0,
        "Valid default config should PASS: {}",
        stdout_default
    );
    assert!(
        stdout_explicit.contains("PASS"),
        "Explicit should show PASS: {}",
        stdout_explicit
    );
    assert!(
        stdout_default.contains("PASS"),
        "Default should show PASS: {}",
        stdout_default
    );
}

// ---- Property 10: Missing file with explicit_config=false does NOT use defaults ----
// When --config points to a file that doesn't exist, it should FAIL even if diffguard.toml exists

#[test]
fn property_explicit_missing_overrides_default() {
    let td = init_git_repo();
    let dir = td.path();

    // Create diffguard.toml (default config)
    let default_config = r#"
[[rule]]
id = "test"
description = "Test"
severity = "error"
patterns = ["test"]
"#;
    std::fs::write(dir.join("diffguard.toml"), default_config).unwrap();

    // Run with --config pointing to non-existent file
    let (code, stdout) = run_doctor(dir, &["--config", "nonexistent_custom.toml"]);

    assert_eq!(
        code, 1,
        "Should FAIL when explicit config is missing: {}",
        stdout
    );
    assert!(stdout.contains("FAIL"), "Should show FAIL: {}", stdout);
}
