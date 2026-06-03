//! Integration tests for column calculation flow in diffguard CLI.
//!
//! These tests verify that the column value produced by `byte_to_column()`
//! flows correctly through:
//! 1. Rule compilation (compile_rules)
//! 2. Line evaluation (evaluate_lines)
//! 3. JSON receipt output (Finding.column)
//! 4. Output formatters (SARIF, Checkstyle, GitLab Quality)
//!
//! The key integration point being tested is evaluate.rs:298 where
//! `byte_to_column` returns `usize` but the Finding stores `Option<u32>`.

use super::test_repo::TestRepo;

/// Helper to parse finding from receipt JSON by rule_id, path, and line.
fn get_finding(
    receipt_json: &serde_json::Value,
    rule_id: &str,
    path: &str,
    line: u32,
) -> serde_json::Value {
    let findings = receipt_json["findings"]
        .as_array()
        .expect("findings should be array");
    findings
        .iter()
        .find(|f| {
            f["rule_id"].as_str() == Some(rule_id)
                && f["path"].as_str() == Some(path)
                && f["line"].as_u64() == Some(line as u64)
        })
        .expect(&format!(
            "Finding not found for rule_id={}, path={}, line={}",
            rule_id, path, line
        ))
        .clone()
}

/// Scenario: Column value flows from evaluate_lines to JSON receipt correctly.
/// Given a rule matches at a specific column position,
/// When the check is run and receipt is generated,
/// Then the column field in the receipt matches the expected value.
#[test]
fn given_match_at_column_when_check_then_receipt_has_correct_column() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.debug"
severity = "error"
message = "debug print found"
patterns = ["print"]
"#,
    );

    // "let print x" - 'print' is at column 5 (1-indexed)
    // "let " = 4 chars, then "print" starts at column 5
    repo.write_file("src/lib.rs", "let print x\n");
    let head_sha = repo.commit("add print statement");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(2);

    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().expect("receipt should exist"))
            .expect("valid JSON");
    let finding = get_finding(&receipt_json, "custom.debug", "src/lib.rs", 1);
    assert!(
        finding["column"].is_number(),
        "column should be a number, got: {}",
        finding["column"]
    );
    assert_eq!(finding["column"].as_u64().unwrap(), 5, "print at column 5");
}

/// Scenario: Column calculation handles UTF-8 multi-byte characters correctly.
/// Given a line with emoji characters,
/// When evaluated,
/// Then column is counted by characters, not bytes.
#[test]
fn given_emoji_in_content_when_check_then_column_counts_chars_not_bytes() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.thumbs"
severity = "error"
message = "found thumbs up"
patterns = ["👍"]
"#,
    );

    // "a👍b" - bytes: a(1) + 👍(4) + b(1) = 6 bytes
    // But characters: a(1) + 👍(1) + b(1) = 3 chars
    // '👍' is at character index 2 (1-indexed = column 2)
    repo.write_file("src/lib.rs", "a👍b\n");
    let head_sha = repo.commit("add emoji");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().expect("receipt should exist"))
            .expect("valid JSON");
    let finding = get_finding(&receipt_json, "custom.thumbs", "src/lib.rs", 1);
    assert_eq!(
        finding["column"].as_u64().unwrap(),
        2,
        "emoji should count as 1 character, not 4 bytes"
    );
}

/// Scenario: Match at start of line reports column 1.
/// Given a pattern matches at position 0,
/// When evaluated,
/// Then column is 1 (not 0).
#[test]
fn given_match_at_start_when_check_then_column_is_one() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.start"
severity = "error"
message = "found at start"
patterns = ["abc"]
"#,
    );

    repo.write_file("src/lib.rs", "abcdef\n");
    let head_sha = repo.commit("add abc at start");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().expect("receipt should exist"))
            .expect("valid JSON");
    let finding = get_finding(&receipt_json, "custom.start", "src/lib.rs", 1);
    assert_eq!(
        finding["column"].as_u64().unwrap(),
        1,
        "match at start should have column 1"
    );
}

/// Scenario: Tab character counts as single column.
/// Given a line with a tab,
/// When the pattern matches after the tab,
/// Then column counts the tab as 1 character.
#[test]
fn given_tab_in_content_when_check_then_tab_counts_as_one_column() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.after_tab"
severity = "error"
message = "found b"
patterns = ["b"]
"#,
    );

    // "a\tb" - 'b' is at column 3 (tab counts as 1 char)
    repo.write_file("src/lib.rs", "a\tb\n");
    let head_sha = repo.commit("add tab then b");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().expect("receipt should exist"))
            .expect("valid JSON");
    let finding = get_finding(&receipt_json, "custom.after_tab", "src/lib.rs", 1);
    assert_eq!(
        finding["column"].as_u64().unwrap(),
        3,
        "tab counts as 1 character in column calculation"
    );
}

/// Scenario: Very long lines still produce correct column values.
/// Given a line with 1000 characters,
/// When a pattern matches near the end,
/// Then column value is correctly calculated.
#[test]
fn given_long_line_when_check_then_column_is_correct() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.end"
severity = "error"
message = "found at end"
patterns = ["xyz"]
"#,
    );

    // 1000 char line with "xyz" near the end
    let content = format!("{:0>997}xyz\n", "");
    repo.write_file("src/lib.rs", &content);
    let head_sha = repo.commit("add long line with xyz at end");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().expect("receipt should exist"))
            .expect("valid JSON");
    let finding = get_finding(&receipt_json, "custom.end", "src/lib.rs", 1);
    assert_eq!(
        finding["column"].as_u64().unwrap(),
        998,
        "xyz at column 998 (1000 - 3 + 1)"
    );
}
