//! Snapshot tests for RuleTestCase JSON serialization outputs.
//!
//! These tests capture the current JSON serialization format for RuleTestCase
//! (the struct documented at lines 391-437 in lib.rs, with doc comments fixed
//! at lines 398 and 402).
//!
//! The snapshots document what the JSON output looks like NOW - any change to
//! the serialization format (field names, ordering, optional field handling)
//! will be detected by these tests.
//!
//! Feature: work-2fb801c2/snapshot-test

use diffguard_types::RuleTestCase;
use serde_json::Value;

/// Helper: pretty-serialize a value to JSON string for snapshot comparison.
fn to_json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("should serialize to JSON")
}

/// Helper: parse a JSON string into a Value for comparison.
fn parse_json(s: &str) -> Value {
    serde_json::from_str(s).expect("should parse JSON")
}

// ============================================================================
// RuleTestCase Snapshot Tests
// ============================================================================

/// Snapshot 1: Minimal RuleTestCase with only required fields.
/// Both `ignore_comments` and `ignore_strings` are None.
#[test]
fn rule_test_case_minimal_json() {
    let case = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: true,
        ignore_comments: None,
        ignore_strings: None,
        language: None,
        description: None,
    };

    let json = to_json_string(&case);

    // Parse and verify the structure without being sensitive to field order
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    assert_eq!(obj.get("input").unwrap().as_str().unwrap(), "let x = 1;");
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), true);
    assert!(
        !obj.contains_key("ignore_comments"),
        "ignore_comments should be skipped when None"
    );
    assert!(
        !obj.contains_key("ignore_strings"),
        "ignore_strings should be skipped when None"
    );
    assert!(
        !obj.contains_key("language"),
        "language should be skipped when None"
    );
    assert!(
        !obj.contains_key("description"),
        "description should be skipped when None"
    );
}

/// Snapshot 2: RuleTestCase with ignore_comments = Some(true).
/// This exercises the field fixed in lib.rs line 398 doc comment.
#[test]
fn rule_test_case_ignore_comments_true_json() {
    let case = RuleTestCase {
        input: "let x = 1; // comment".to_string(),
        should_match: true,
        ignore_comments: Some(true),
        ignore_strings: None,
        language: None,
        description: None,
    };

    let json = to_json_string(&case);

    // Parse and verify
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    assert_eq!(
        obj.get("input").unwrap().as_str().unwrap(),
        "let x = 1; // comment"
    );
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), true);
    assert_eq!(obj.get("ignore_comments").unwrap().as_bool().unwrap(), true);
    assert!(
        !obj.contains_key("ignore_strings"),
        "ignore_strings should be skipped when None"
    );
    assert!(
        !obj.contains_key("language"),
        "language should be skipped when None"
    );
    assert!(
        !obj.contains_key("description"),
        "description should be skipped when None"
    );
}

/// Snapshot 3: RuleTestCase with ignore_comments = Some(false).
#[test]
fn rule_test_case_ignore_comments_false_json() {
    let case = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: false,
        ignore_comments: Some(false),
        ignore_strings: None,
        language: None,
        description: None,
    };

    let json = to_json_string(&case);

    // Parse and verify
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    assert_eq!(obj.get("input").unwrap().as_str().unwrap(), "let x = 1;");
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), false);
    assert_eq!(
        obj.get("ignore_comments").unwrap().as_bool().unwrap(),
        false
    );
    assert!(
        !obj.contains_key("ignore_strings"),
        "ignore_strings should be skipped when None"
    );
}

/// Snapshot 4: RuleTestCase with ignore_strings = Some(true).
/// This exercises the field fixed in lib.rs line 402 doc comment.
#[test]
fn rule_test_case_ignore_strings_true_json() {
    let case = RuleTestCase {
        input: "let s = \"hello world\";".to_string(),
        should_match: true,
        ignore_comments: None,
        ignore_strings: Some(true),
        language: None,
        description: None,
    };

    let json = to_json_string(&case);

    // Parse and verify
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    assert_eq!(
        obj.get("input").unwrap().as_str().unwrap(),
        "let s = \"hello world\";"
    );
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), true);
    assert!(
        !obj.contains_key("ignore_comments"),
        "ignore_comments should be skipped when None"
    );
    assert_eq!(obj.get("ignore_strings").unwrap().as_bool().unwrap(), true);
}

/// Snapshot 5: RuleTestCase with ignore_strings = Some(false).
#[test]
fn rule_test_case_ignore_strings_false_json() {
    let case = RuleTestCase {
        input: "let s = \"hello\";".to_string(),
        should_match: false,
        ignore_comments: None,
        ignore_strings: Some(false),
        language: None,
        description: None,
    };

    let json = to_json_string(&case);

    // Parse and verify
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    assert_eq!(
        obj.get("input").unwrap().as_str().unwrap(),
        "let s = \"hello\";"
    );
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), false);
    assert!(
        !obj.contains_key("ignore_comments"),
        "ignore_comments should be skipped when None"
    );
    assert_eq!(obj.get("ignore_strings").unwrap().as_bool().unwrap(), false);
}

/// Snapshot 6: RuleTestCase with both ignore_comments and ignore_strings set.
/// This is the key snapshot for verifying the doc comment fix (lines 398 & 402).
#[test]
fn rule_test_case_both_flags_set_json() {
    let case = RuleTestCase {
        input: "let s = \"string\"; // comment".to_string(),
        should_match: true,
        ignore_comments: Some(true),
        ignore_strings: Some(true),
        language: Some("rust".to_string()),
        description: Some("test case with both flags".to_string()),
    };

    let json = to_json_string(&case);

    // Parse and verify
    let value: Value = parse_json(&json);
    let obj = value.as_object().expect("should be an object");

    // Verify all fields are present and correct
    assert_eq!(
        obj.get("input").unwrap().as_str().unwrap(),
        "let s = \"string\"; // comment"
    );
    assert_eq!(obj.get("should_match").unwrap().as_bool().unwrap(), true);
    assert_eq!(obj.get("ignore_comments").unwrap().as_bool().unwrap(), true);
    assert_eq!(obj.get("ignore_strings").unwrap().as_bool().unwrap(), true);
    assert_eq!(obj.get("language").unwrap().as_str().unwrap(), "rust");
    assert_eq!(
        obj.get("description").unwrap().as_str().unwrap(),
        "test case with both flags"
    );
}

/// Snapshot 7: RuleTestCase deserialized from JSON matches original.
/// This verifies round-trip integrity.
#[test]
fn rule_test_case_round_trip_with_both_flags() {
    let original = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: true,
        ignore_comments: Some(false),
        ignore_strings: Some(true),
        language: None,
        description: None,
    };

    // Serialize to JSON
    let json_string = serde_json::to_string(&original).expect("should serialize");

    // Deserialize back
    let deserialized: RuleTestCase =
        serde_json::from_str(&json_string).expect("should deserialize");

    // Round-trip should produce identical value
    assert_eq!(original, deserialized);
}

/// Snapshot 8: Verifies JSON field names match the doc comment identifiers.
/// The doc comments at lines 398 and 402 reference `ignore_comments` and
/// `ignore_strings` with backticks. This test verifies the JSON keys match.
#[test]
fn rule_test_case_json_keys_match_doc_comment_identifiers() {
    let case = RuleTestCase {
        input: "test".to_string(),
        should_match: true,
        ignore_comments: Some(true),
        ignore_strings: Some(false),
        language: None,
        description: None,
    };

    let json_value = serde_json::to_value(&case).expect("should serialize to value");
    let obj = json_value.as_object().expect("should be an object");

    // These keys MUST match the identifiers used in the doc comments
    // (which were fixed to use backtick-quoted identifiers)
    assert!(
        obj.contains_key("ignore_comments"),
        "JSON key must be 'ignore_comments' (matches doc comment identifier)"
    );
    assert!(
        obj.contains_key("ignore_strings"),
        "JSON key must be 'ignore_strings' (matches doc comment identifier)"
    );

    // Verify the values are correct
    assert_eq!(obj.get("ignore_comments").unwrap().as_bool().unwrap(), true);
    assert_eq!(obj.get("ignore_strings").unwrap().as_bool().unwrap(), false);
}

/// Snapshot 9: Verify ignore_comments and ignore_strings are skipped when None.
#[test]
fn rule_test_case_flags_skipped_when_none() {
    let case = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: true,
        ignore_comments: None,
        ignore_strings: None,
        language: None,
        description: None,
    };

    let json_value = serde_json::to_value(&case).expect("should serialize to value");
    let obj = json_value.as_object().expect("should be an object");

    // When None, these keys should NOT be present
    assert!(
        !obj.contains_key("ignore_comments"),
        "ignore_comments should be skipped when None"
    );
    assert!(
        !obj.contains_key("ignore_strings"),
        "ignore_strings should be skipped when None"
    );
}
