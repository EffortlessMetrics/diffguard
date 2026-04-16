//! Tests for clippy::uninlined_format_args lint compliance in server.rs
//!
//! These tests verify that all format! macro calls in server.rs use named
//! arguments (e.g., `format!("{var}", var=var)`) instead of positional
//! arguments (e.g., `format!("{}", var)`).
//!
//! The clippy::uninlined_format_args lint detects format strings that could
//! use named arguments for better readability.
//!
//! These tests are RED tests - they fail when the lint warnings exist and
//! pass once the code is fixed.

use std::path::Path;
use std::process::Command;

/// Tests that server.rs has no uninlined_format_args clippy warnings.
///
/// This test enables the clippy::uninlined_format_args lint and verifies
/// that running clippy on diffguard-lsp produces zero warnings.
///
/// Lines that should use named format arguments:
/// - Line 140: config_label, err
/// - Line 299: err
/// - Line 320: rule_id
/// - Line 326: rule_id
/// - Line 368: err
/// - Line 438: rule_id
/// - Line 443: label, url
/// - Line 470: rule_id
/// - Line 474: suggestion
/// - Line 494: err
/// - Line 519: err
/// - Line 546: err
/// - Line 581: err
/// - Line 599: err
/// - Line 639-641: rules
/// - Line 647-649: err
/// - Line 702-704: err
/// - Line 728: err
/// - Line 760: relative_path, err
#[test]
fn test_server_rs_no_uninlined_format_args_warnings() {
    let _manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let _stdout = String::from_utf8_lossy(&output.stdout);

    // Extract server.rs warnings - they span multiple lines, so we need to
    // find all "server.rs:LINE:" patterns and then check if the warning block
    // contains uninlined_format_args
    let server_rs_warnings: Vec<String> = stderr
        .lines()
        .filter(|line| {
            // Check if this line mentions server.rs with a line number
            if line.contains("server.rs:") && line.contains(':') {
                // Extract the line number part (e.g., "server.rs:299:")
                let after_server = line.split("server.rs:").nth(1).unwrap_or("");
                let line_part = after_server.split(':').next().unwrap_or("");
                // Check if this looks like a line number
                line_part.chars().all(|c| c.is_ascii_digit())
            } else {
                false
            }
        })
        .map(|l| l.to_string())
        .collect();

    let server_rs_warning_count = server_rs_warnings.len();

    if server_rs_warning_count > 0 {
        eprintln!(
            "Found {count} uninlined_format_args warnings in server.rs:",
            count = server_rs_warning_count
        );
        for warning in &server_rs_warnings {
            eprintln!("  {warning}", warning = warning);
        }
        eprintln!("\nTo fix, replace positional format args with named args:");
        eprintln!("  format!(\"{{}}\", var)  ->  format!(\"{{var}}\", var=var)");
    }

    // Assert zero warnings for server.rs
    assert_eq!(
        server_rs_warning_count,
        0,
        "server.rs should have 0 uninlined_format_args warnings, but found {count}.\n\
         All format! macro calls should use named arguments instead of positional.\n\
         Example: format!(\"error: {{}}\", err) -> format!(\"error: {{err}}\")\n\
         \n\
         Warnings found:\n{warnings}",
        count = server_rs_warning_count,
        warnings = server_rs_warnings.join("\n")
    );
}

/// Tests that the specific format! call at line 299 uses named arguments.
///
/// Before fix: format!("invalid CodeActionParams: {}", err)
/// After fix:  format!("invalid CodeActionParams: {err}")
#[test]
fn test_server_rs_line_299_named_format_args() {
    test_file_has_named_format_args_at_line(299, "invalid CodeActionParams", "err");
}

/// Tests that the specific format! call at line 320 uses named arguments.
///
/// Before fix: format!("Explain {}", rule_id)
/// After fix:  format!("Explain {rule_id}")
#[test]
fn test_server_rs_line_320_named_format_args() {
    test_file_has_named_format_args_at_line(320, "Explain", "rule_id");
}

/// Tests that the specific format! call at line 326 uses named arguments.
///
/// Before fix: format!("diffguard: Explain {}", rule_id)
/// After fix:  format!("diffguard: Explain {rule_id}")
#[test]
fn test_server_rs_line_326_named_format_args() {
    test_file_has_named_format_args_at_line(326, "diffguard: Explain", "rule_id");
}

/// Tests that the specific format! call at line 368 uses named arguments.
///
/// Before fix: format!("invalid ExecuteCommandParams: {}", err)
/// After fix:  format!("invalid ExecuteCommandParams: {err}")
#[test]
fn test_server_rs_line_368_named_format_args() {
    test_file_has_named_format_args_at_line(368, "invalid ExecuteCommandParams", "err");
}

/// Tests that the specific format! call at line 438 uses named arguments.
///
/// Before fix: format!("diffguard rule {}", rule_id)
/// After fix:  format!("diffguard rule {rule_id}")
#[test]
fn test_server_rs_line_438_named_format_args() {
    test_file_has_named_format_args_at_line(438, "diffguard rule", "rule_id");
}

/// Tests that the specific format! call at line 443 uses named arguments.
///
/// Before fix: format!("{}: {}", label, url)
/// After fix:  format!("{label}: {url}")
#[test]
fn test_server_rs_line_443_named_format_args() {
    test_file_has_named_format_args_at_line(443, ":", "url");
}

/// Tests that the specific format! call at line 470 uses named arguments.
///
/// Before fix: format!("Rule '{}' not found.", rule_id)
/// After fix:  format!("Rule '{rule_id}' not found.")
#[test]
fn test_server_rs_line_470_named_format_args() {
    test_file_has_named_format_args_at_line(470, "not found", "rule_id");
}

/// Tests that the specific format! call at line 474 uses named arguments.
///
/// Before fix: format!("\n- {}", suggestion)
/// After fix:  format!("\n- {suggestion}")
#[test]
fn test_server_rs_line_474_named_format_args() {
    test_file_has_named_format_args_at_line(474, "-", "suggestion");
}

/// Tests that the specific format! call at line 494 uses named arguments.
///
/// Before fix: format!("invalid didOpen params: {}", err)
/// After fix:  format!("invalid didOpen params: {err}")
#[test]
fn test_server_rs_line_494_named_format_args() {
    test_file_has_named_format_args_at_line(494, "invalid didOpen params", "err");
}

/// Tests that the specific format! call at line 519 uses named arguments.
///
/// Before fix: format!("invalid didChange params: {}", err)
/// After fix:  format!("invalid didChange params: {err}")
#[test]
fn test_server_rs_line_519_named_format_args() {
    test_file_has_named_format_args_at_line(519, "invalid didChange params", "err");
}

/// Tests that the specific format! call at line 546 uses named arguments.
///
/// Before fix: format!("invalid didSave params: {}", err)
/// After fix:  format!("invalid didSave params: {err}")
#[test]
fn test_server_rs_line_546_named_format_args() {
    test_file_has_named_format_args_at_line(546, "invalid didSave params", "err");
}

/// Tests that the specific format! call at line 581 uses named arguments.
///
/// Before fix: format!("invalid didClose params: {}", err)
/// After fix:  format!("invalid didClose params: {err}")
#[test]
fn test_server_rs_line_581_named_format_args() {
    test_file_has_named_format_args_at_line(581, "invalid didClose params", "err");
}

/// Tests that the specific format! call at line 599 uses named arguments.
///
/// Before fix: format!("invalid didChangeConfiguration params: {}", err)
/// After fix:  format!("invalid didChangeConfiguration params: {err}")
#[test]
fn test_server_rs_line_599_named_format_args() {
    test_file_has_named_format_args_at_line(599, "invalid didChangeConfiguration params", "err");
}

/// Tests that the specific format! call at line 639-641 uses named arguments.
///
/// Before fix: format!("diffguard-lsp: config reloaded ({} rule(s)).", rules)
/// After fix:  format!("diffguard-lsp: config reloaded ({rules} rule(s)).")
#[test]
fn test_server_rs_line_639_named_format_args() {
    test_file_has_named_format_args_at_line(639, "config reloaded", "rules");
}

/// Tests that the specific format! call at line 647-649 uses named arguments.
///
/// Before fix: format!("diffguard-lsp: failed to reload config (using built-in rules): {}", err)
/// After fix:  format!("diffguard-lsp: failed to reload config (using built-in rules): {err}")
#[test]
fn test_server_rs_line_647_named_format_args() {
    test_file_has_named_format_args_at_line(647, "failed to reload config", "err");
}

/// Tests that the specific format! call at line 702-704 uses named arguments.
///
/// Before fix: format!("diffguard-lsp: git diff unavailable (falling back to in-memory changes only): {}", err)
/// After fix:  format!("diffguard-lsp: git diff unavailable (falling back to in-memory changes only): {err}")
#[test]
fn test_server_rs_line_702_named_format_args() {
    test_file_has_named_format_args_at_line(702, "git diff unavailable", "err");
}

/// Tests that the specific format! call at line 728 uses named arguments.
///
/// Before fix: format!("diffguard-lsp: failed to load directory overrides: {}", err)
/// After fix:  format!("diffguard-lsp: failed to load directory overrides: {err}")
#[test]
fn test_server_rs_line_728_named_format_args() {
    test_file_has_named_format_args_at_line(728, "failed to load directory overrides", "err");
}

/// Tests that the specific format! call at line 760 uses named arguments.
///
/// Before fix: format!("diffguard-lsp: check failed for {}: {}", relative_path, err)
/// After fix:  format!("diffguard-lsp: check failed for {relative_path}: {err}")
#[test]
fn test_server_rs_line_760_named_format_args() {
    test_file_has_named_format_args_at_line(760, "check failed for", "err");
}

/// Helper function to check that a specific line in server.rs uses named format args.
///
/// This parses the clippy output to verify that a specific line has no warnings
/// about uninlined format args.
fn test_file_has_named_format_args_at_line(line: usize, _context: &str, _var_name: &str) {
    let _manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-lsp",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if this specific line has a warning
    let line_warning_pattern = format!("server.rs:{line}:");
    let has_line_warning = stderr.contains(&line_warning_pattern);

    assert!(
        !has_line_warning,
        "server.rs:{line} should NOT have uninlined_format_args warnings after fix.\n\
         The format string should use named argument (e.g., {{var}}) instead of positional ({{}}).\n\
         \n\
         Clippy output:\n{clippy_output}",
        line = line,
        clippy_output = stderr
    );
}
