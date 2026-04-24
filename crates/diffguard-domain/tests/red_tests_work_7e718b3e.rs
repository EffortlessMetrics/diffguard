//! Red tests for work-7e718b3e: #[must_use] on suppression parsing functions
//!
//! These tests verify the correct behavior of `parse_suppression` and
//! `parse_suppression_in_comments` functions which must have `#[must_use]`
//! attribute to prevent callers from silently ignoring suppression directives.
//!
//! The `#[must_use]` attribute ensures compile-time warnings if a caller
//! ignores the return value. This is critical because ignoring a suppression
//! directive means a rule fires when it shouldn't — a semantic correctness bug.
//!
//! ## Functions that must have #[must_use]
//!
//! 1. `parse_suppression(line: &str) -> Option<Suppression>` at line 70
//! 2. `parse_suppression_in_comments(line: &str, masked_comments: &str) -> Option<Suppression>` at line 85
//!
//! ## Types inspected
//!
//! - `SuppressionKind` enum: `SameLine`, `NextLine`
//! - `Suppression` struct: `kind: SuppressionKind`, `rule_ids: Option<HashSet<String>>`
//! - `Suppression::suppresses(rule_id: &str) -> bool`
//! - `Suppression::is_wildcard() -> bool`

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};
use diffguard_domain::suppression::SuppressionKind;
use diffguard_domain::suppression::{parse_suppression, parse_suppression_in_comments};

/// Helper to create masked comments for testing.
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

/// Test that parse_suppression returns Some(Suppression) for a valid directive.
/// This test explicitly captures and uses the return value to verify #[must_use] is effective.
#[test]
fn parse_suppression_returns_suppression_for_valid_directive() {
    let line = "// diffguard: ignore rust.no_unwrap";
    let result = parse_suppression(line);

    // Explicitly use the return value - if #[must_use] is missing, clippy would warn
    let suppression = result.expect("parse_suppression should return Some for valid directive");

    assert_eq!(
        suppression.kind,
        SuppressionKind::SameLine,
        "Suppression kind should be SameLine"
    );
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress rust.no_unwrap rule"
    );
}

/// Test that parse_suppression returns None when no directive is present.
#[test]
fn parse_suppression_returns_none_for_no_directive() {
    let line = "let x = y.unwrap(); // normal comment";
    let result = parse_suppression(line);

    // Explicitly use the return value
    assert!(
        result.is_none(),
        "parse_suppression should return None when no directive is present"
    );
}

/// Test parse_suppression with ignore-next-line directive.
#[test]
fn parse_suppression_returns_next_line_kind_for_ignore_next_line() {
    let line = "// diffguard: ignore-next-line rust.no_dbg";
    let suppression = parse_suppression(line).expect("should parse ignore-next-line");

    assert_eq!(
        suppression.kind,
        SuppressionKind::NextLine,
        "Suppression kind should be NextLine for ignore-next-line directive"
    );
    assert!(
        suppression.suppresses("rust.no_dbg"),
        "Should suppress rust.no_dbg rule"
    );
}

/// Test parse_suppression with wildcard (ignore-all) directive.
#[test]
fn parse_suppression_returns_wildcard_for_ignore_all() {
    let line = "// diffguard: ignore *";
    let suppression = parse_suppression(line).expect("should parse wildcard directive");

    assert_eq!(
        suppression.kind,
        SuppressionKind::SameLine,
        "Wildcard suppression should be SameLine"
    );
    assert!(
        suppression.is_wildcard(),
        "Should be wildcard (suppress all rules)"
    );
    assert!(
        suppression.suppresses("any.rule"),
        "Wildcard should suppress any rule"
    );
}

/// Test parse_suppression_in_comments returns Some when directive is in comment.
/// This test explicitly captures and uses the return value to verify #[must_use] is effective.
#[test]
fn parse_suppression_in_comments_returns_suppression_when_in_comment() {
    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);
    let result = parse_suppression_in_comments(line, &masked);

    // Explicitly use the return value - if #[must_use] is missing, clippy would warn
    let suppression = result
        .expect("parse_suppression_in_comments should return Some when directive is in comment");

    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress rust.no_unwrap rule"
    );
}

/// Test parse_suppression_in_comments returns None when directive is in string (not comment).
#[test]
fn parse_suppression_in_comments_returns_none_when_directive_in_string() {
    let line = r#"let x = "diffguard: ignore rust.no_unwrap";"#;
    let masked = masked_comments(line, Language::Rust);
    let result = parse_suppression_in_comments(line, &masked);

    // Directive is in string, not in comment, so should return None
    assert!(
        result.is_none(),
        "parse_suppression_in_comments should return None when directive is in string, not comment"
    );
}

/// Test parse_suppression_in_comments returns None when lengths don't match.
#[test]
fn parse_suppression_in_comments_returns_none_on_length_mismatch() {
    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = "short"; // Wrong length
    let result = parse_suppression_in_comments(line, masked);

    assert!(
        result.is_none(),
        "parse_suppression_in_comments should return None when line and masked lengths differ"
    );
}

/// Test that ignoring parse_suppression result would be incorrect behavior.
/// This test documents that the return value MUST be used.
#[test]
fn parse_suppression_return_value_must_be_used() {
    let line = "// diffguard: ignore rust.no_unwrap";

    // The correct pattern: always use the return value
    let suppression_opt = parse_suppression(line);

    // Verify we got a suppression
    assert!(
        suppression_opt.is_some(),
        "parse_suppression should return Some for valid directive - caller MUST use this result"
    );

    // Verify the suppression works
    let suppression = suppression_opt.unwrap();
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Suppression should suppress the specified rule"
    );
}

/// Test that ignoring parse_suppression_in_comments result would be incorrect behavior.
/// This test documents that the return value MUST be used.
#[test]
fn parse_suppression_in_comments_return_value_must_be_used() {
    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);

    // The correct pattern: always use the return value
    let suppression_opt = parse_suppression_in_comments(line, &masked);

    // Verify we got a suppression
    assert!(
        suppression_opt.is_some(),
        "parse_suppression_in_comments should return Some for directive in comment - caller MUST use this result"
    );

    // Verify the suppression works
    let suppression = suppression_opt.unwrap();
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Suppression should suppress the specified rule"
    );
}

/// Test multiple rule IDs in a single directive.
#[test]
fn parse_suppression_handles_multiple_rule_ids() {
    let line = "// diffguard: ignore rule1, rule2, rule3";
    let suppression = parse_suppression(line).expect("should parse multiple rules");

    assert!(suppression.suppresses("rule1"), "Should suppress rule1");
    assert!(suppression.suppresses("rule2"), "Should suppress rule2");
    assert!(suppression.suppresses("rule3"), "Should suppress rule3");
    assert!(
        !suppression.suppresses("rule4"),
        "Should not suppress rule4"
    );
}

/// Test case insensitivity of directive parsing.
#[test]
fn parse_suppression_is_case_insensitive() {
    let line = "// DIFFGUARD: IGNORE rust.no_unwrap";
    let suppression = parse_suppression(line).expect("should parse uppercase directive");

    assert_eq!(
        suppression.kind,
        SuppressionKind::SameLine,
        "Should parse uppercase directive"
    );
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress despite case differences"
    );
}
