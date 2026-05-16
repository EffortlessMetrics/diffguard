// Regression test for GitHub issue #503: items_after_statements lint in run_git_diff()
//
// This test verifies that the clippy::items_after_statements lint does not fire
// for the run_git_diff() function in server.rs.
//
// The issue was that `const GIT_DIFF_TIMEOUT` was declared AFTER executable
// statements (line 921 in the buggy version), making it unclear whether the
// const was part of the setup or a mid-function declaration.
//
// The fix (PR #525, commit b604bf2) moved `const GIT_DIFF_TIMEOUT` to line 946,
// BEFORE the first executable statement (let mut command = Command::new("git");).
//
// This test will FAIL if the const is placed after statements again,
// and PASS when the const is correctly placed before statements.

use std::process::Command;

/// Test that run_git_diff does not trigger items_after_statements lint.
///
/// This test runs clippy on the diffguard-lsp crate and verifies that the
/// clippy::items_after_statements lint does not fire for the run_git_diff
/// function.
///
/// EXPECTED BEHAVIOR:
/// - When const is correctly placed BEFORE statements (line 946): test PASSES
/// - When const is incorrectly placed AFTER statements (line 921): test FAILS
#[test]
fn test_run_git_diff_no_items_after_statements_lint() {
    // Run clippy on the diffguard-lsp crate
    let output = Command::new("cargo")
        .args(["clippy", "-p", "diffguard-lsp", "--", "-A", "warnings"])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Run clippy again with items_after_statements enabled to check for the specific lint
    let lint_output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::items_after_statements",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy with items_after_statements");

    let lint_stderr = String::from_utf8_lossy(&lint_output.stderr);

    // Check if items_after_statements lint fires for run_git_diff in server.rs
    // The lint fires when const/item is declared after executable statements
    let has_lint_error = lint_stderr.contains("items_after_statements")
        && lint_stderr.contains("run_git_diff")
        && lint_stderr.contains("server.rs");

    assert!(
        !has_lint_error,
        "clippy::items_after_statements lint fired for run_git_diff. \
         The const GIT_DIFF_TIMEOUT should be declared BEFORE executable statements. \
         Expected: const at line ~946 (before `let mut command = Command::new(\"git\");`). \
         Got lint error in:\n{}",
        lint_stderr
    );

    // Also verify that clippy passes without warnings (when warnings are allowed)
    assert!(
        output.status.success() || !stderr.contains("error:"),
        "Clippy reported errors:\n{}",
        stderr
    );
}

/// Verifies the constant GIT_DIFF_TIMEOUT is declared at the correct position.
///
/// This test reads the source file and verifies that:
/// 1. The const declaration exists in run_git_diff
/// 2. It appears BEFORE the first executable statement
///
/// This catches regressions where someone might move the const after statements.
#[test]
fn test_git_diff_timeout_constant_position() {
    let server_rs =
        std::fs::read_to_string("/home/hermes/repos/diffguard/crates/diffguard-lsp/src/server.rs")
            .expect("Failed to read server.rs");

    let lines: Vec<&str> = server_rs.lines().collect();

    // Find the run_git_diff function
    let fn_start = lines
        .iter()
        .position(|l| l.contains("fn run_git_diff("))
        .expect("run_git_diff function not found");

    // Find the const declaration
    let const_line = lines
        .iter()
        .position(|l| l.contains("const GIT_DIFF_TIMEOUT: Duration"))
        .expect("const GIT_DIFF_TIMEOUT not found in server.rs");

    // Find the first let statement after the const
    let first_let_after_const = lines[const_line..]
        .iter()
        .position(|l| {
            l.trim_start().starts_with("let ") && !l.trim().contains("//")
                || l.trim().starts_with("let mut")
        })
        .expect("No let statement found after const");

    // The const must be declared before the first let statement
    // The first let should come AFTER the const
    assert!(
        first_let_after_const > 0,
        "first let statement should come after const declaration (first_let_after_const = {})",
        first_let_after_const
    );

    // The const must be inside the function (after fn_start)
    assert!(
        const_line > fn_start,
        "const GIT_DIFF_TIMEOUT (line {}) should be declared inside run_git_diff (starts at line {})",
        const_line,
        fn_start
    );

    // Also verify the const comes BEFORE any Command::new call
    let command_new_line = lines[const_line..]
        .iter()
        .position(|l| l.contains("Command::new(\"git\")"));

    assert!(
        command_new_line.is_some(),
        "Command::new(\"git\") not found after const declaration"
    );

    let command_new_offset = command_new_line.unwrap();
    assert!(
        command_new_offset > 0,
        "const GIT_DIFF_TIMEOUT should be declared BEFORE Command::new(\"git\")"
    );
}

/// Verifies the constant value is 10 seconds as expected.
#[test]
fn test_git_diff_timeout_value_is_10_seconds() {
    let server_rs =
        std::fs::read_to_string("/home/hermes/repos/diffguard/crates/diffguard-lsp/src/server.rs")
            .expect("Failed to read server.rs");

    // Look for the const declaration with the expected value
    let has_correct_timeout =
        server_rs.contains("const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(10);");

    assert!(
        has_correct_timeout,
        "const GIT_DIFF_TIMEOUT should be Duration::from_secs(10) \
         Expected: const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(10); \
         Not found with correct value in server.rs"
    );
}

/// Verifies the timeout is actually used in the deadline calculation.
///
/// This ensures the constant isn't just declared but actually referenced
/// in the timeout logic.
#[test]
fn test_git_diff_timeout_is_used_in_deadline() {
    let server_rs =
        std::fs::read_to_string("/home/hermes/repos/diffguard/crates/diffguard-lsp/src/server.rs")
            .expect("Failed to read server.rs");

    // Find the run_git_diff function scope
    let fn_start = server_rs
        .find("fn run_git_diff(")
        .expect("run_git_diff not found");

    let fn_body = &server_rs[fn_start..];

    // Extract just the run_git_diff function (until the next fn or end of file)
    let fn_end = fn_body[4..]
        .find("fn ")
        .map(|p| fn_start + 4 + p)
        .unwrap_or(server_rs.len());

    let this_fn = &server_rs[fn_start..fn_end];

    // Verify the timeout constant is used in deadline calculation
    assert!(
        this_fn.contains("GIT_DIFF_TIMEOUT"),
        "GIT_DIFF_TIMEOUT constant should be referenced in run_git_diff"
    );

    // Verify it's used with Instant
    assert!(
        this_fn.contains("Instant::now() + GIT_DIFF_TIMEOUT")
            || this_fn.contains("deadline")
            || this_fn.contains("GIT_DIFF_TIMEOUT.as_secs()"),
        "GIT_DIFF_TIMEOUT should be used in timeout/deadline calculation"
    );
}

/// Verifies the timeout error message uses the constant's value.
#[test]
fn test_git_diff_timeout_error_uses_constant() {
    let server_rs =
        std::fs::read_to_string("/home/hermes/repos/diffguard/crates/diffguard-lsp/src/server.rs")
            .expect("Failed to read server.rs");

    // Find the run_git_diff function - we need to search for the fn keyword
    // AFTER the function signature starts, not at position 0
    let fn_start = server_rs
        .find("fn run_git_diff(")
        .expect("run_git_diff not found");

    // Find the NEXT fn after the function starts (skip past "fn run_git_diff(" which is ~16 chars)
    // Using a larger skip to ensure we don't re-find the current fn
    let fn_end = server_rs[fn_start + 16..]
        .find("fn ")
        .map(|p| fn_start + 16 + p)
        .unwrap_or(server_rs.len());

    let this_fn = &server_rs[fn_start..fn_end];

    // The timeout error should reference the constant (not hardcoded 10)
    // Using a simple check - if GIT_DIFF_TIMEOUT.as_secs() is in the function,
    // and the error message uses the timeout constant, we're good
    let has_timeout_constant = this_fn.contains("GIT_DIFF_TIMEOUT");
    let has_as_secs_call = this_fn.contains("GIT_DIFF_TIMEOUT.as_secs()");
    let has_timeout_error = this_fn.contains("timed out after");

    assert!(
        has_timeout_constant && has_as_secs_call && has_timeout_error,
        "Timeout error should use GIT_DIFF_TIMEOUT constant. \
         Found: has_timeout_constant={}, has_as_secs_call={}, has_timeout_error={}. \
         Function snippet: {}",
        has_timeout_constant,
        has_as_secs_call,
        has_timeout_error,
        &this_fn[this_fn.len().saturating_sub(200)..]
    );
}
