// Red Test: Clippy uninlined_format_args compliance for server.rs
// Issue #467: Convert positional format args to inline format args
//
// These tests verify that the format! calls in server.rs use inline format
// arguments (e.g., {err}) instead of positional placeholders (e.g., {}).
//
// RUNNING: These tests invoke clippy as a subprocess and parse its output.
// They will FAIL if clippy reports uninlined_format_args warnings at the
// scoped lines (299, 320, 326, 368, 438, 494).
//
// The tests will PASS once all 6 scoped format! calls are converted to use
// inline format arguments.

use std::process::Command;

#[test]
fn test_clippy_uninlined_format_args_at_line_299() {
    // Line 299: format!("invalid CodeActionParams: {}", err)
    // Expected after fix: format!("invalid CodeActionParams: {err}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    // Check that line 299 does NOT appear in clippy warnings
    assert!(
        !combined.contains("server.rs:299"),
        "Clippy warns at server.rs:299 - format! call should use inline format args: {{err}}\n\
         Clippy output:\n{}",
        combined
    );
}

#[test]
fn test_clippy_uninlined_format_args_at_line_320() {
    // Line 320: format!("Explain {}", rule_id)
    // Expected after fix: format!("Explain {rule_id}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("server.rs:320"),
        "Clippy warns at server.rs:320 - format! call should use inline format args: {{rule_id}}\n\
         Clippy output:\n{}",
        combined
    );
}

#[test]
fn test_clippy_uninlined_format_args_at_line_326() {
    // Line 326: format!("diffguard: Explain {}", rule_id)
    // Expected after fix: format!("diffguard: Explain {rule_id}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("server.rs:326"),
        "Clippy warns at server.rs:326 - format! call should use inline format args: {{rule_id}}\n\
         Clippy output:\n{}",
        combined
    );
}

#[test]
fn test_clippy_uninlined_format_args_at_line_368() {
    // Line 368: format!("invalid ExecuteCommandParams: {}", err)
    // Expected after fix: format!("invalid ExecuteCommandParams: {err}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("server.rs:368"),
        "Clippy warns at server.rs:368 - format! call should use inline format args: {{err}}\n\
         Clippy output:\n{}",
        combined
    );
}

#[test]
fn test_clippy_uninlined_format_args_at_line_438() {
    // Line 438: format!("diffguard rule {}", rule_id)
    // Expected after fix: format!("diffguard rule {rule_id}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("server.rs:438"),
        "Clippy warns at server.rs:438 - format! call should use inline format args: {{rule_id}}\n\
         Clippy output:\n{}",
        combined
    );
}

#[test]
fn test_clippy_uninlined_format_args_at_line_494() {
    // Line 494: format!("invalid didOpen params: {}", err)
    // Expected after fix: format!("invalid didOpen params: {err}")
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        !combined.contains("server.rs:494"),
        "Clippy warns at server.rs:494 - format! call should use inline format args: {{err}}\n\
         Clippy output:\n{}",
        combined
    );
}

/// Integration test: verify ALL 6 scoped lines are clippy-clean
#[test]
fn test_clippy_uninlined_format_args_all_scoped_lines() {
    // This test verifies that NONE of the 6 scoped lines appear in clippy warnings
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("failed to run clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    let scoped_lines = ["299", "320", "326", "368", "438", "494"];
    let mut failing_lines = Vec::new();

    for line in &scoped_lines {
        if combined.contains(&format!("server.rs:{}", line)) {
            failing_lines.push(*line);
        }
    }

    assert!(
        failing_lines.is_empty(),
        "Clippy warns at the following scoped lines (should use inline format args): {}\n\
         All clippy output:\n{}",
        failing_lines.join(", "),
        combined
    );
}
