//! Tests verifying `clippy::doc_markdown` compliance for RuleTestCase doc comments.
//!
//! These tests ensure that identifiers in doc comments are wrapped in backticks
//! so that clippy::doc_markdown does not trigger warnings.
//!
//! RED STATE: Lines 398 and 402 contain bare identifiers (ignore_comments, ignore_strings)
//! GREEN STATE: Lines 398 and 402 contain backtick-formatted identifiers (`ignore_comments`, `ignore_strings`)

use std::path::Path;

/// Test that doc comments on line 398 have backtick-formatted `ignore_comments` identifier.
///
/// RED: `/// Optional: override ignore_comments for this test case.`
/// GREEN: `/// Optional: override \`ignore_comments\` for this test case.`
#[test]
fn test_doc_comment_line_398_has_backtick_formatted_ignore_comments() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 398 (1-indexed) = index 397 (0-indexed)
    let line_398 = lines.get(397).expect("Line 398 should exist");

    assert!(
        line_398.contains("`ignore_comments`"),
        "Line 398 doc comment should contain backtick-formatted `ignore_comments`, got: {}",
        line_398
    );
}

/// Test that doc comments on line 402 have backtick-formatted `ignore_strings` identifier.
///
/// RED: `/// Optional: override ignore_strings for this test case.`
/// GREEN: `/// Optional: override \`ignore_strings\` for this test case.`
#[test]
fn test_doc_comment_line_402_has_backtick_formatted_ignore_strings() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 402 (1-indexed) = index 401 (0-indexed)
    let line_402 = lines.get(401).expect("Line 402 should exist");

    assert!(
        line_402.contains("`ignore_strings`"),
        "Line 402 doc comment should contain backtick-formatted `ignore_strings`, got: {}",
        line_402
    );
}

/// Test that the doc comment for ignore_comments does NOT contain bare identifier.
///
/// This is the negation test - it verifies the bare identifier is NOT present.
#[test]
fn test_doc_comment_line_398_does_not_have_bare_ignore_comments() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 398 (1-indexed) = index 397 (0-indexed)
    let line_398 = lines.get(397).expect("Line 398 should exist");

    // The bare identifier pattern (not wrapped in backticks)
    // This regex looks for "ignore_comments" NOT preceded by a backtick
    let bare_identifier_present = line_398.contains(" ignore_comments")
        || line_398.contains("\tignore_comments")
        || (line_398.contains("override ignore_comments")
            && !line_398.contains("`ignore_comments`"));

    assert!(
        !bare_identifier_present,
        "Line 398 should NOT contain bare identifier ignore_comments (should be wrapped in backticks), got: {}",
        line_398
    );
}

/// Test that the doc comment for ignore_strings does NOT contain bare identifier.
///
/// This is the negation test - it verifies the bare identifier is NOT present.
#[test]
fn test_doc_comment_line_402_does_not_have_bare_ignore_strings() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");

    let source = std::fs::read_to_string(&source_path).expect("Failed to read source file");

    let lines: Vec<&str> = source.lines().collect();

    // Line 402 (1-indexed) = index 401 (0-indexed)
    let line_402 = lines.get(401).expect("Line 402 should exist");

    // The bare identifier pattern (not wrapped in backticks)
    let bare_identifier_present = line_402.contains(" ignore_strings")
        || line_402.contains("\tignore_strings")
        || (line_402.contains("override ignore_strings") && !line_402.contains("`ignore_strings`"));

    assert!(
        !bare_identifier_present,
        "Line 402 should NOT contain bare identifier ignore_strings (should be wrapped in backticks), got: {}",
        line_402
    );
}
