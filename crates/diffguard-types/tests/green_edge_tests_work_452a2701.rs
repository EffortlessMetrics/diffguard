//! Edge case tests verifying the `clippy::doc_markdown` fix for RuleTestCase.
//!
//! These tests verify that the doc comments for `ignore_comments` and
//! `ignore_strings` fields in RuleTestCase are properly formatted with backticks.
//!
//! Implementation note: The actual line numbers are 402 and 406 (not 398 and 402
//! as stated in the original issue). The red tests have incorrect line numbers.

use std::path::Path;

/// Verify the doc comment for `ignore_comments` is at line 402 and has backticks.
///
/// This tests the edge case that the doc comment:
/// - Is at the correct line (402)
/// - Contains the field name `ignore_comments`
/// - Has the field name wrapped in backticks (`ignore_comments`)
#[test]
fn test_doc_comment_ignore_comments_at_line_402_has_backticks() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 402 (1-indexed) = index 401 (0-indexed)
    let line_402 = lines.get(401).expect("Line 402 should exist");

    // Verify the line contains the doc comment for ignore_comments with backticks
    assert!(
        line_402.contains("`ignore_comments`"),
        "Line 402 should contain backtick-formatted `ignore_comments`, got: {}",
        line_402
    );

    // Verify it's the doc comment for the ignore_comments field
    assert!(
        line_402.contains("override"),
        "Line 402 should be the doc comment about overriding ignore_comments, got: {}",
        line_402
    );
}

/// Verify the doc comment for `ignore_strings` is at line 406 and has backticks.
///
/// This tests the edge case that the doc comment:
/// - Is at the correct line (406)
/// - Contains the field name `ignore_strings`
/// - Has the field name wrapped in backticks (`ignore_strings`)
#[test]
fn test_doc_comment_ignore_strings_at_line_406_has_backticks() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 406 (1-indexed) = index 405 (0-indexed)
    let line_406 = lines.get(405).expect("Line 406 should exist");

    // Verify the line contains the doc comment for ignore_strings with backticks
    assert!(
        line_406.contains("`ignore_strings`"),
        "Line 406 should contain backtick-formatted `ignore_strings`, got: {}",
        line_406
    );

    // Verify it's the doc comment for the ignore_strings field
    assert!(
        line_406.contains("override"),
        "Line 406 should be the doc comment about overriding ignore_strings, got: {}",
        line_406
    );
}

/// Verify the RuleTestCase struct fields still work correctly.
///
/// This tests the edge case that the documentation change didn't break
/// the struct functionality - fields serialize and deserialize correctly.
#[test]
fn test_rule_test_case_serialization_round_trip() {
    use diffguard_types::{RuleTestCase, Severity};

    let test_case = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: true,
        ignore_comments: Some(true),
        ignore_strings: Some(false),
        language: Some("rust".to_string()),
        description: Some("Test case for doc_markdown fix".to_string()),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&test_case).expect("RuleTestCase should serialize to JSON");

    // Deserialize back
    let deserialized: RuleTestCase =
        serde_json::from_str(&json).expect("RuleTestCase should deserialize from JSON");

    // Verify all fields round-trip correctly
    assert_eq!(test_case.input, deserialized.input);
    assert_eq!(test_case.should_match, deserialized.should_match);
    assert_eq!(test_case.ignore_comments, deserialized.ignore_comments);
    assert_eq!(test_case.ignore_strings, deserialized.ignore_strings);
    assert_eq!(test_case.language, deserialized.language);
    assert_eq!(test_case.description, deserialized.description);
}

/// Verify RuleTestCase with None values for optional fields serializes correctly.
///
/// This tests the edge case that optional fields set to None are properly
/// skipped during serialization (as per serde attributes).
#[test]
fn test_rule_test_case_optional_fields_none_skipped() {
    use diffguard_types::RuleTestCase;

    let test_case = RuleTestCase {
        input: "let x = 1;".to_string(),
        should_match: true,
        ignore_comments: None,
        ignore_strings: None,
        language: None,
        description: None,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&test_case).expect("RuleTestCase should serialize to JSON");

    // Verify the optional fields are NOT present in JSON (skip_serializing_if)
    assert!(
        !json.contains("ignore_comments"),
        "ignore_comments should be skipped when None"
    );
    assert!(
        !json.contains("ignore_strings"),
        "ignore_strings should be skipped when None"
    );
    assert!(
        !json.contains("language"),
        "language should be skipped when None"
    );
    assert!(
        !json.contains("description"),
        "description should be skipped when None"
    );

    // Verify essential fields ARE present
    assert!(json.contains("input"));
    assert!(json.contains("should_match"));
}

/// Verify RuleTestCase deserialization works with missing optional fields.
///
/// This tests the edge case that deserialization succeeds when optional
/// fields are missing from the JSON (they should default to None).
#[test]
fn test_rule_test_case_deserialization_missing_optional_fields() {
    use diffguard_types::RuleTestCase;

    // JSON without optional fields
    let json = r#"{"input":"let x = 1;","should_match":true}"#;

    let deserialized: RuleTestCase = serde_json::from_str(json)
        .expect("RuleTestCase should deserialize without optional fields");

    assert_eq!(deserialized.input, "let x = 1;");
    assert_eq!(deserialized.should_match, true);
    assert_eq!(deserialized.ignore_comments, None);
    assert_eq!(deserialized.ignore_strings, None);
    assert_eq!(deserialized.language, None);
    assert_eq!(deserialized.description, None);
}

/// Verify multiple RuleTestCase instances can be created and serialized.
///
/// This tests the edge case of creating multiple test cases (as would happen
/// in a real test suite) and ensures no interference between instances.
#[test]
fn test_multiple_rule_test_cases_independent() {
    use diffguard_types::RuleTestCase;

    let test_case_1 = RuleTestCase {
        input: "// comment".to_string(),
        should_match: false,
        ignore_comments: Some(true),
        ignore_strings: None,
        language: None,
        description: None,
    };

    let test_case_2 = RuleTestCase {
        input: "\"string\"".to_string(),
        should_match: true,
        ignore_comments: None,
        ignore_strings: Some(true),
        language: None,
        description: None,
    };

    // Serialize both
    let json_1 = serde_json::to_string(&test_case_1).unwrap();
    let json_2 = serde_json::to_string(&test_case_2).unwrap();

    // Deserialize both
    let round_trip_1: RuleTestCase = serde_json::from_str(&json_1).unwrap();
    let round_trip_2: RuleTestCase = serde_json::from_str(&json_2).unwrap();

    // Verify they are independent
    assert_eq!(round_trip_1.ignore_comments, Some(true));
    assert_eq!(round_trip_1.ignore_strings, None);
    assert_eq!(round_trip_2.ignore_comments, None);
    assert_eq!(round_trip_2.ignore_strings, Some(true));
}
