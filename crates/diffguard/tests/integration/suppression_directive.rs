//! BDD tests for suppression directive behavior.
//!
//! Tests inline suppression comments (diffguard-ignore-next-line, etc.)
//!
//! Note: This tests the current behavior where ignore_comments=true causes
//! the suppression directive comment itself to be masked. Full suppression
//! directive support is tracked separately.

use super::test_repo::TestRepo;

/// Scenario: unwrap in a comment is ignored when ignore_comments=true.
///
/// Given: A file where unwrap() appears only in a comment
/// When: diffguard check runs with default rules (ignore_comments=true)
/// Then: No finding is reported
#[test]
fn given_unwrap_in_comment_when_check_then_not_flagged() {
    // Given: A file where unwrap() appears only in a comment
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"// TODO: consider using .unwrap() here for simplicity
pub fn safe() -> Option<u32> { Some(1) }
"#,
    );
    let head_sha = repo.commit("add commented unwrap");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: unwrap in a string is ignored when ignore_strings=true.
///
/// Given: A file where unwrap() appears only in a string literal
/// When: diffguard check runs with default rules (ignore_strings=true)
/// Then: No finding is reported
#[test]
fn given_unwrap_in_string_when_check_then_not_flagged() {
    // Given: A file where unwrap() appears only in a string literal
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"pub fn help_text() -> &'static str {
    "Use .unwrap() carefully in production code."
}
"#,
    );
    let head_sha = repo.commit("add string with unwrap");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Block comment containing unwrap is ignored.
///
/// Given: A file with unwrap in a block comment
/// When: diffguard check runs
/// Then: No finding is reported
#[test]
fn given_unwrap_in_block_comment_when_check_then_not_flagged() {
    // Given: A file with unwrap in a block comment
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"/*
 * This function used to call .unwrap() but was refactored.
 * Old code: some_option.unwrap()
 */
pub fn safe_now() -> Option<u32> { Some(1) }
"#,
    );
    let head_sha = repo.commit("add block comment with unwrap");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Real unwrap with adjacent comment is still flagged.
///
/// Given: A file with real unwrap() call and a nearby comment
/// When: diffguard check runs
/// Then: The real unwrap is flagged (comment doesn't suppress it)
#[test]
fn given_real_unwrap_with_comment_when_check_then_still_flagged() {
    // Given: A file with real unwrap() and a comment
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"// This is safe because we know it's always Some
pub fn risky() -> u32 { Some(1).unwrap() }
"#,
    );
    let head_sha = repo.commit("add unwrap with justification comment");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: The real unwrap is flagged
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("rust.no_unwrap"));
}

/// Scenario: Doc comment containing unwrap is ignored.
///
/// Given: A file with unwrap in a doc comment (///)
/// When: diffguard check runs
/// Then: No finding is reported for the doc comment
#[test]
fn given_unwrap_in_doc_comment_when_check_then_not_flagged() {
    // Given: A file with unwrap in a doc comment
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"/// Example usage:
/// ```
/// let x = some_option.unwrap();
/// ```
pub fn documented() -> Option<u32> { Some(1) }
"#,
    );
    let head_sha = repo.commit("add doc comment with unwrap example");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Raw string containing unwrap is ignored.
///
/// Given: A file with unwrap in a raw string (r#"..."#)
/// When: diffguard check runs
/// Then: No finding is reported
#[test]
fn given_unwrap_in_raw_string_when_check_then_not_flagged() {
    // Given: A file with unwrap in a raw string
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r##"pub fn code_sample() -> &'static str {
    r#"let value = option.unwrap();"#
}
"##,
    );
    let head_sha = repo.commit("add raw string with unwrap");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Trailing line comment masks unwrap on same line.
///
/// Given: A file with code and a trailing comment containing unwrap
/// When: diffguard check runs
/// Then: No finding for the comment content
#[test]
fn given_unwrap_in_trailing_comment_when_check_then_not_flagged() {
    // Given: Code with trailing comment
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"pub fn safe() -> Option<u32> { Some(1) } // not using .unwrap() here
"#,
    );
    let head_sha = repo.commit("add trailing comment mentioning unwrap");

    // When: diffguard check runs
    let result = repo.run_check(&head_sha);

    // Then: No finding is reported
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}
