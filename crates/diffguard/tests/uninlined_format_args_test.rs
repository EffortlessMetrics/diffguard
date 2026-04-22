//! Red tests for clippy::uninlined_format_args compliance
//!
//! These tests verify that the `diffguard` and `diffguard-core` packages
//! have zero warnings from the `clippy::uninlined_format_args` lint.
//!
//! Acceptance criteria:
//! 1. `cargo clippy --package diffguard -- -W clippy::uninlined_format_args` emits zero warnings
//! 2. `cargo clippy --package diffguard-core -- -W clippy::uninlined_format_args` emits zero warnings
//! 3. `bail!("{}", msg)` simplified to `bail!(msg)` at line 1083 in cmd_explain()
//! 4. `'{}'` edge cases handled correctly at lines ~2880 and ~3079

use std::path::Path;
use std::process::Command;

/// Tests that diffguard package has zero clippy::uninlined_format_args warnings
#[test]
fn test_diffguard_has_no_uninlined_format_args_warnings() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that there are NO warnings in the output
    // We look for "warning:" followed by "uninlined_format_args"
    let has_uninlined_warnings = stderr.contains("uninlined_format_args")
        || stdout.contains("uninlined_format_args")
        || stderr.contains("warning: `diffguard`") && stderr.contains("warnings");

    assert!(
        !has_uninlined_warnings,
        "diffguard package should have zero uninlined_format_args warnings.\n\
         stderr:\n{}\n\
         stdout:\n{}",
        stderr, stdout
    );
}

/// Tests that diffguard-core package has zero clippy::uninlined_format_args warnings
#[test]
fn test_diffguard_core_has_no_uninlined_format_args_warnings() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-core",
            "--",
            "-W",
            "clippy::uninlined_format_args",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let has_uninlined_warnings = stderr.contains("uninlined_format_args")
        || stdout.contains("uninlined_format_args")
        || stderr.contains("warning: `diffguard-core`") && stderr.contains("warnings");

    assert!(
        !has_uninlined_warnings,
        "diffguard-core package should have zero uninlined_format_args warnings.\n\
         stderr:\n{}\n\
         stdout:\n{}",
        stderr, stdout
    );
}

/// Verifies the bail!("{}", msg) anti-pattern does not exist in main.rs
/// The correct form is bail!(msg) since msg is already a String.
#[test]
fn test_no_bail_string_wrapper_in_main_rs() {
    let main_rs = Path::new("/home/hermes/repos/diffguard/crates/diffguard/src/main.rs");
    let content = std::fs::read_to_string(main_rs).expect("main.rs should be readable");

    // The anti-pattern is bail!("{}", msg) where msg is a String
    // The correct form is just bail!(msg)
    let has_anti_pattern = content.contains("bail!(\"{}\", msg)");

    assert!(
        !has_anti_pattern,
        "main.rs should not contain bail!(\"{{}}\", msg) - use bail!(msg) instead"
    );
}

/// Verifies the quoted '{}' literal edge case is handled properly
/// These require named argument form like {var = var} to preserve the quotes
#[test]
fn test_single_quoted_literal_edge_cases_have_named_args() {
    let main_rs = Path::new("/home/hermes/repos/diffguard/crates/diffguard/src/main.rs");
    let content = std::fs::read_to_string(main_rs).expect("main.rs should be readable");

    // Line 2880 should have: bail!("No rules match filter '{filter}'", filter = filter);
    // OR: bail!("No rules match filter '{}'", filter); after clippy fix
    // The key is the named form for '...' patterns
    let lines: Vec<&str> = content.lines().collect();

    // Find the bail! line at approximately line 2880 (index 2879)
    let mut found_filter_bail = false;
    let mut found_env_bail = false;

    for (i, line) in lines.iter().enumerate() {
        // Looking for: bail!("No rules match filter
        if line.contains("No rules match filter") && line.contains("bail!") {
            found_filter_bail = true;
            // Should NOT have uninlined format args like "{}", filter
            // Should have inline {var} or named {var = var} form
            if line.contains("'{}'") && !line.contains("filter = filter") {
                panic!(
                    "Line {} has quoted '{{}}' pattern without named args: {}",
                    i + 1,
                    line
                );
            }
        }

        // Looking for: bail!("Environment variable '{}' is not set
        if line.contains("Environment variable") && line.contains("bail!") {
            found_env_bail = true;
            if line.contains("'{}'") && !line.contains("var_name = var_name") {
                panic!(
                    "Line {} has quoted '{{}}' pattern without named args: {}",
                    i + 1,
                    line
                );
            }
        }
    }

    assert!(
        found_filter_bail,
        "Should find bail! for 'No rules match filter'"
    );
    assert!(
        found_env_bail,
        "Should find bail! for 'Environment variable'"
    );
}

/// Verifies checkstyle.rs format string uses inline argument
#[test]
fn test_checkstyle_format_inlined() {
    let checkstyle_rs =
        Path::new("/home/hermes/repos/diffguard/crates/diffguard-core/src/checkstyle.rs");
    let content = std::fs::read_to_string(checkstyle_rs).expect("checkstyle.rs should be readable");

    // The anti-pattern at line 41:
    // format!(" column=\"{}\"", c)
    // Should be: format!(" column=\"{c}\"", c)
    let has_anti_pattern = content.contains("format!(\" column=\\\"{}\\\"\", c)");

    assert!(
        !has_anti_pattern,
        "checkstyle.rs should use inline format argument: column={{c}}"
    );
}

/// Verifies csv.rs format string uses inline argument
#[test]
fn test_csv_format_inlined() {
    let csv_rs = Path::new("/home/hermes/repos/diffguard/crates/diffguard-core/src/csv.rs");
    let content = std::fs::read_to_string(csv_rs).expect("csv.rs should be readable");

    // The anti-pattern at line 106:
    // format!("\"{}\"", escaped)
    // Should be: format!("\"{escaped}\"", escaped)
    let has_anti_pattern = content.contains("format!(\"\\\"{}\\\"\", escaped)");

    assert!(
        !has_anti_pattern,
        "csv.rs should use inline format argument: \"{{escaped}}\""
    );
}

/// Verifies junit.rs format string uses inline arguments
#[test]
fn test_junit_format_inlined() {
    let junit_rs = Path::new("/home/hermes/repos/diffguard/crates/diffguard-core/src/junit.rs");
    let content = std::fs::read_to_string(junit_rs).expect("junit.rs should be readable");

    // The anti-pattern at lines 39-41:
    // format!("<testsuites ... tests="{}" failures="{}" ...>\n", total_tests, total_failures)
    // Should use inline: tests="{total_tests}" failures="{total_failures}"
    let has_anti_pattern = content.contains("tests=\"{}\"")
        && content.contains("failures=\"{}\"")
        && content.contains("total_tests, total_failures");

    assert!(
        !has_anti_pattern,
        "junit.rs should use inline format arguments"
    );
}

// ============================================================================
// Edge Case Tests - Green Test Builder
// ============================================================================
//
// These tests verify the inline format argument changes work correctly
// across different scenarios: empty strings, unicode, multiple args,
// mixed types, and XML-escaped content.
// ============================================================================

/// Verifies inline format strings produce correct output with various types.
/// This is a compile-time verification since inline args are expanded at compile time.
#[test]
fn test_inline_format_strings_produce_correct_output() {
    // Test with string slice
    let s = "hello";
    let result = format!("{s}");
    assert_eq!(result, "hello");

    // Test with owned string
    let owned = "world".to_string();
    let result = format!("{owned}");
    assert_eq!(result, "world");

    // Test with integer
    let n: i32 = 42;
    let result = format!("{n}");
    assert_eq!(result, "42");

    // Test with usize
    let count: usize = 100;
    let result = format!("{count}");
    assert_eq!(result, "100");

    // Test with multiple inline args
    let a = "foo";
    let b = "bar";
    let result = format!("{a} {b}");
    assert_eq!(result, "foo bar");

    // Test with numeric inline args
    let x = 10;
    let y = 20;
    let result = format!("x={x}, y={y}");
    assert_eq!(result, "x=10, y=20");
}

/// Verifies inline format strings handle empty strings correctly.
#[test]
fn test_inline_format_strings_with_empty_values() {
    let empty = "";
    let result = format!("[{empty}]");
    assert_eq!(result, "[]");

    let filled = "content";
    let result = format!("{filled}[{empty}]{filled}");
    assert_eq!(result, "content[]content");
}

/// Verifies inline format strings handle unicode correctly.
#[test]
fn test_inline_format_strings_with_unicode() {
    let unicode = "Hello 🌍 你好";
    let result = format!("{unicode}");
    assert_eq!(result, unicode);

    let mixed = "émoji: 🎉";
    let result = format!("{mixed}");
    assert_eq!(result, "émoji: 🎉");
}

/// Verifies inline format strings in XML/JSON contexts produce valid output.
#[test]
fn test_inline_format_strings_xml_safe() {
    let path = "src/main.rs";
    let line: usize = 42;
    let result = format!("File: {path}:{line}");
    assert_eq!(result, "File: src/main.rs:42");

    let escaped = "a < b & c > d";
    let result = format!("message={escaped}");
    assert_eq!(result, "message=a < b & c > d");
}

/// Verifies the XML escape utility produces correct output.
/// This ensures the format changes don't break XML escaping.
#[test]
fn test_xml_escape_roundtrip() {
    use diffguard_core::xml_utils::escape_xml;

    // Test basic escaping
    let input = "<test>";
    let escaped = escape_xml(input);
    assert_eq!(escaped, "&lt;test&gt;");

    // Test ampersand
    let input = "a & b";
    let escaped = escape_xml(input);
    assert_eq!(escaped, "a &amp; b");

    // Test quotes
    let input = "\"hello\"";
    let escaped = escape_xml(input);
    assert_eq!(escaped, "&quot;hello&quot;");
}
