//! Green tests: Edge case coverage for fingerprint functions.
//!
//! These tests verify the fingerprint functions handle edge cases correctly:
//! - Empty strings
//! - Unicode characters
//! - Special characters (colons, newlines, etc.)
//! - Very long inputs
//! - Column None vs Some
//! - Zero/boundary values
//!
//! Issue: GitHub #518

use diffguard_core::{compute_fingerprint, compute_fingerprint_raw};
use diffguard_types::Finding;
use diffguard_types::Severity;

/// Helper to create a minimal finding with customizable fields.
fn make_finding(
    rule_id: &str,
    path: &str,
    line: u32,
    match_text: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: "Test message".to_string(),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: match_text.to_string(),
        snippet: match_text.to_string(),
    }
}

// =============================================================================
// Empty string edge cases
// =============================================================================

#[test]
fn test_fingerprint_empty_rule_id() {
    let f = make_finding("", "src/lib.rs", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_empty_path() {
    let f = make_finding("rust.no_unwrap", "", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_empty_match_text() {
    let f = make_finding("rust.no_unwrap", "src/lib.rs", 1, "");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_empty_string() {
    let fp = compute_fingerprint_raw("");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

// =============================================================================
// Zero and boundary values
// =============================================================================

#[test]
fn test_fingerprint_line_zero() {
    let f = make_finding("rust.no_unwrap", "src/lib.rs", 0, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_column_none() {
    let mut f = make_finding("rust.no_unwrap", "src/lib.rs", 1, ".unwrap()");
    f.column = None;
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_column_some_vs_none_affects_fingerprint() {
    // Column is NOT part of the fingerprint (only rule_id, path, line, match_text)
    let mut f_with_column = make_finding("rust.no_unwrap", "src/lib.rs", 1, ".unwrap()");
    f_with_column.column = Some(10);

    let mut f_without_column = make_finding("rust.no_unwrap", "src/lib.rs", 1, ".unwrap()");
    f_without_column.column = None;

    // Both should produce the same fingerprint since column is not part of the hash input
    let fp_with = compute_fingerprint(&f_with_column);
    let fp_without = compute_fingerprint(&f_without_column);
    assert_eq!(fp_with, fp_without);
}

// =============================================================================
// Special characters in input
// =============================================================================

#[test]
fn test_fingerprint_raw_colons_in_input() {
    // Colons are used as separators in the format! string
    // but compute_fingerprint_raw takes arbitrary strings
    let fp = compute_fingerprint_raw("a:b:c:d:e:f");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_newlines_in_input() {
    let fp = compute_fingerprint_raw("line1\nline2\nline3");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_tabs_in_input() {
    let fp = compute_fingerprint_raw("col1\tcol2\tcol3");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_carriage_return_in_input() {
    let fp = compute_fingerprint_raw("line1\r\nline2");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_null_byte_in_input() {
    let fp = compute_fingerprint_raw("hello\0world");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

// =============================================================================
// Unicode edge cases
// =============================================================================

#[test]
fn test_fingerprint_unicode_in_rule_id() {
    let f = make_finding("rust.no_ünwrap", "src/lib.rs", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_unicode_in_path() {
    let f = make_finding("rust.no_unwrap", "src/üniçodé.rs", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_unicode_in_match_text() {
    let f = make_finding("rust.no_unwrap", "src/lib.rs", 1, ".ünwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_unicode_full_width_chars() {
    let fp = compute_fingerprint_raw("中文русскийالعربية");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_unicode_emoji() {
    let fp = compute_fingerprint_raw("Hello 👋 World 🌍");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

// =============================================================================
// Long input edge cases
// =============================================================================

#[test]
fn test_fingerprint_raw_very_long_input() {
    let long_input = "a".repeat(100_000);
    let fp = compute_fingerprint_raw(&long_input);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_long_rule_id() {
    let long_rule_id = "a".repeat(10_000);
    let f = make_finding(&long_rule_id, "src/lib.rs", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_long_path() {
    let long_path = "src/".to_string() + &"a".repeat(10_000) + "/lib.rs";
    let f = make_finding("rust.no_unwrap", &long_path, 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_long_match_text() {
    let long_match = "x".repeat(10_000);
    let f = make_finding("rust.no_unwrap", "src/lib.rs", 1, &long_match);
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

// =============================================================================
// Very large line numbers
// =============================================================================

#[test]
fn test_fingerprint_large_line_number() {
    let f = make_finding("rust.no_unwrap", "src/lib.rs", u32::MAX, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_line_number_one() {
    // Line 1 is a common boundary case (first line of a file)
    let f = make_finding("rust.no_unwrap", "src/lib.rs", 1, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

// =============================================================================
// ASCII boundary characters
// =============================================================================

#[test]
fn test_fingerprint_raw_all_hex_chars() {
    // Input that is already valid hex should still produce hex output
    let fp = compute_fingerprint_raw("0123456789abcdefABCDEF");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_special_chars_only() {
    let fp = compute_fingerprint_raw("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_raw_backslash_and_escape() {
    let fp = compute_fingerprint_raw("path\\with\\backslashes\nand\tescape\tchars");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

// =============================================================================
// Single character inputs
// =============================================================================

#[test]
fn test_fingerprint_raw_single_char() {
    let fp = compute_fingerprint_raw("a");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_fingerprint_single_char_match_text() {
    let f = make_finding("r", "p", 1, "x");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

// =============================================================================
// Different findings produce different fingerprints
// =============================================================================

#[test]
fn test_fingerprint_different_columns_same_fingerprint() {
    // Column is NOT part of the fingerprint - this confirms the behavior
    let mut f1 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.column = Some(5);
    f2.column = Some(100);

    assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
}

#[test]
fn test_fingerprint_different_message_same_fingerprint() {
    // Message is NOT part of the fingerprint
    let mut f1 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.message = "First message".to_string();
    f2.message = "Completely different message".to_string();

    assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
}

#[test]
fn test_fingerprint_different_snippet_same_fingerprint() {
    // Snippet is NOT part of the fingerprint
    let mut f1 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.snippet = "let x = foo.unwrap();".to_string();
    f2.snippet = "let y = bar.expect();".to_string();

    assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
}

#[test]
fn test_fingerprint_different_severity_same_fingerprint() {
    // Severity is NOT part of the fingerprint
    let mut f1 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.severity = Severity::Error;
    f2.severity = Severity::Warn;

    assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
}

// =============================================================================
// Consistency: compute_fingerprint uses compute_fingerprint_raw internally
// =============================================================================

#[test]
fn test_compute_fingerprint_matches_raw_format() {
    let finding = make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let fp = compute_fingerprint(&finding);

    // Manually compute what the raw input would be
    let expected_raw_input = format!(
        "{}:{}:{}:{}",
        finding.rule_id, finding.path, finding.line, finding.match_text
    );
    let fp_raw = compute_fingerprint_raw(&expected_raw_input);

    assert_eq!(fp, fp_raw);
}

// =============================================================================
// Hex output validation
// =============================================================================

#[test]
fn test_fingerprint_raw_output_is_valid_hex() {
    let fp = compute_fingerprint_raw("test");
    // SHA-256 hex output should be valid hexadecimal characters
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    // Should be exactly 64 characters for 32 bytes
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_all_zero_input_produces_valid_fingerprint() {
    // SHA-256 of empty string produces known output
    let fp = compute_fingerprint_raw("");
    // This is the SHA-256 hash of empty string - verify it's valid hex
    assert_eq!(fp, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn test_fingerprint_known_input_produces_known_output() {
    // SHA-256 of "hello" is known
    let fp = compute_fingerprint_raw("hello");
    assert_eq!(fp.len(), 64);
    // Verify it's the correct SHA-256 hash of "hello"
    assert_eq!(fp, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}
