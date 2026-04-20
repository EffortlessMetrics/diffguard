//! Edge case tests for evaluate_lines column calculation
//!
//! These tests verify edge cases in the byte_to_column usize→u32 conversion
//! and column reporting in evaluate_lines.
//!
//! Edge cases covered:
//! - Match at column 1 (start of line)
//! - Empty content lines
//! - Lines with only whitespace
//! - Tab character column calculation
//! - Multiple rules matching same line with correct columns
//! - Very long lines approaching u32::MAX (without exceeding)
//! - Lines with complex UTF-8 (emojis, combining characters)
//! - Lines with control characters
//! - Finding truncation behavior
//! - Multiple rules: each gets its own finding

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Helper to create a RuleConfig for testing
fn make_rule(id: &str, severity: Severity, pattern: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: format!("found: {}", pattern),
        languages: vec![],
        patterns: vec![pattern.to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::Any,
        multiline: false,
        multiline_window: None,
        context_patterns: vec![],
        context_window: None,
        escalate_patterns: vec![],
        escalate_window: None,
        escalate_to: None,
        depends_on: vec![],
        help: None,
        url: None,
        tags: vec![],
        test_cases: vec![],
    }
}

// =============================================================================
// Edge Case: Match at column 1 (start of line)
// =============================================================================

/// Test that a match at the very start of a line reports column 1.
#[test]
fn test_match_at_column_one() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "abc")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abc def".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(
        finding.column.is_some(),
        "Column should be Some for match at start"
    );
    assert_eq!(
        finding.column.unwrap(),
        1,
        "Match at start should have column 1"
    );
}

// =============================================================================
// Edge Case: Empty content line
// =============================================================================

/// Test that evaluate_lines handles empty content gracefully.
#[test]
fn test_empty_content_line() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "pattern")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: String::new(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    // No match should be found in empty content
    assert!(
        eval.findings.is_empty(),
        "No findings expected for empty content"
    );
}

// =============================================================================
// Edge Case: Whitespace-only line
// =============================================================================

/// Test that whitespace-only lines don't produce spurious matches.
#[test]
fn test_whitespace_only_line() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "abc")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "      ".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    // No match for "abc" in whitespace-only content
    assert!(eval.findings.is_empty());
}

// =============================================================================
// Edge Case: Tab character column calculation
// =============================================================================

/// Test that tabs are treated as single characters in column count.
///
/// Tabs in source code typically render as 8 spaces, but byte_to_column
/// counts them as 1 character. This test verifies the behavior is consistent.
#[test]
fn test_tab_character_column() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "b")]).unwrap();

    // "\t" is 1 byte, 1 char. "a\tb" is 3 bytes, 3 chars.
    // 'b' is at byte index 2, which is character index 2 (0-indexed).
    // So column should be 3 (1-indexed).
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "a\tb".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(finding.column.unwrap(), 3, "Tab counts as 1 character");
}

// =============================================================================
// Edge Case: Multiple rules matching same line - each gets its own finding
// =============================================================================

/// Test that multiple rules matching the same line produce multiple findings.
#[test]
fn test_multiple_rules_same_line_multiple_findings() {
    let rules = compile_rules(&[
        make_rule("rule1", Severity::Error, "abc"),
        make_rule("rule2", Severity::Warn, "def"),
    ])
    .unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abcdef".to_string(), // Both "abc" and "def" match here
    };

    let eval = evaluate_lines([line], &rules, 100);

    // Should have 2 findings (one per rule)
    assert_eq!(eval.findings.len(), 2);
    assert_eq!(eval.counts.error, 1);
    assert_eq!(eval.counts.warn, 1);

    // Find the columns for each finding
    let mut columns: Vec<u32> = eval.findings.iter().map(|f| f.column.unwrap()).collect();
    columns.sort();
    assert_eq!(columns, vec![1, 4], "abc at col 1, def at col 4");
}

// =============================================================================
// Edge Case: Match spans entire line
// =============================================================================

/// Test that a match spanning the entire line reports column 1.
#[test]
fn test_match_spans_entire_line() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "hello")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "hello".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(
        finding.column.unwrap(),
        1,
        "Full-line match should have column 1"
    );
}

// =============================================================================
// Edge Case: Line with only the match
// =============================================================================

/// Test single-character line with match.
#[test]
fn test_single_char_line_match() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "x")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "x".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(finding.column.unwrap(), 1);
}

// =============================================================================
// Edge Case: Emoji and complex UTF-8
// =============================================================================

/// Test column calculation with emoji characters (4 bytes each in UTF-8).
#[test]
fn test_emoji_column_calculation() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "👍")]).unwrap();

    // "a👍b" - bytes: [a, 👍(4bytes), b] = 6 bytes, but 3 characters
    // '👍' starts at byte 1, so column should be 2 (chars 0..1 = 1 char + 1 = 2)
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "a👍b".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(
        finding.column.unwrap(),
        2,
        "Emoji should count as 1 character"
    );
}

// =============================================================================
// Edge Case: Combining characters
// =============================================================================

/// Test column calculation with combining characters.
///
/// Combining characters like 'e' + combining acute accent (é) appear as
/// two unicode codepoints but may render as a single visual character.
#[test]
fn test_combining_character_column() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "café")]).unwrap();

    // "café" with combining accent: bytes > chars due to combining char
    // But match "café" starts at column 1
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "café test".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(
        finding.column.unwrap(),
        1,
        "Match at start should be column 1"
    );
}

// =============================================================================
// Edge Case: Control characters in content
// =============================================================================

/// Test that control characters (0x00-0x1F) are handled gracefully.
#[test]
fn test_control_characters_handled() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "test")]).unwrap();

    // Content with embedded null and control characters
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "test\x00with\x1Fcontrol".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    // Should still find "test" - control chars don't prevent matching
    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(
        finding.column.unwrap(),
        1,
        "Match at start should be column 1"
    );
}

// =============================================================================
// Edge Case: Finding truncation with max_findings
// =============================================================================

/// Test that max_findings correctly truncates findings while counting all.
///
/// Note: evaluate_lines only returns first match per line per rule, so
/// 5 lines with 1 rule = 5 findings max, not 10.
#[test]
fn test_max_findings_truncation() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Warn, "x")]).unwrap();

    // 5 lines each with "x" = 5 potential findings, cap at 3
    let lines: Vec<InputLine> = (0..5)
        .map(|i| InputLine {
            path: "test.txt".to_string(),
            line: i as u32,
            content: "x".to_string(),
        })
        .collect();

    let eval = evaluate_lines(lines, &rules, 3);

    // Should have only 3 findings (truncated)
    assert_eq!(
        eval.findings.len(),
        3,
        "Findings should be truncated to max"
    );
    // But counts should reflect all 5 matches
    assert_eq!(eval.counts.warn, 5, "Counts should track all matches");
    assert_eq!(eval.truncated_findings, 2, "2 findings should be truncated");
}

// =============================================================================
// Edge Case: Large column value near u32::MAX
// =============================================================================

/// Test that column values are correctly preserved for large column values.
///
/// We cannot actually test u32::MAX overflow without ~4GB strings,
/// but we can verify that values up to a reasonable large size work correctly.
#[test]
fn test_large_column_value_preservation() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "X")]).unwrap();

    // Create a string with 10000 'X' characters
    // First match is at column 1, which easily fits in u32
    let content = "X".repeat(10000);
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    };

    let eval = evaluate_lines([line], &rules, 100);

    // First finding should be at column 1
    assert!(!eval.findings.is_empty());
    let first_finding = &eval.findings[0];
    assert!(
        first_finding.column.is_some(),
        "Column should be present for large string"
    );
    assert_eq!(
        first_finding.column.unwrap(),
        1,
        "First match should be at column 1"
    );
}

// =============================================================================
// Edge Case: Column is Some for normal ASCII
// =============================================================================

/// Verify that column is always Some for normal short strings.
#[test]
fn test_column_always_some_for_normal_strings() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "test")]).unwrap();

    let test_cases = vec![
        "test at start",
        "start test",
        "te st",    // match not at boundary
        "testtest", // first match at start
        " a test ", // with leading/trailing space
    ];

    for content in test_cases {
        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.to_string(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        if !eval.findings.is_empty() {
            for finding in &eval.findings {
                assert!(
                    finding.column.is_some(),
                    "Column should be Some for content: '{}'",
                    content
                );
                // Column should always be >= 1
                assert!(
                    finding.column.unwrap() >= 1,
                    "Column should be >= 1 for content: '{}'",
                    content
                );
            }
        }
    }
}

// =============================================================================
// Edge Case: Rule with no matches
// =============================================================================

/// Test that rules with no matches produce empty findings.
#[test]
fn test_no_matches_produces_empty_findings() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "xyz123")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "this is a normal line with no special patterns".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert!(
        eval.findings.is_empty(),
        "No matches should produce empty findings"
    );
    assert_eq!(eval.counts.error, 0);
}

// =============================================================================
// Edge Case: Zero max_findings
// =============================================================================

/// Test that max_findings=0 produces no findings but still counts.
#[test]
fn test_zero_max_findings_counts_but_no_findings() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "test")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "test pattern".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 0);

    assert!(
        eval.findings.is_empty(),
        "max_findings=0 should produce no findings"
    );
    assert_eq!(
        eval.counts.error, 1,
        "But the count should still be tracked"
    );
    assert_eq!(eval.truncated_findings, 1, "One finding was truncated");
}

// =============================================================================
// Edge Case: Newline characters in content
// =============================================================================

/// Test that newlines embedded in content are handled as part of the line.
#[test]
fn test_newline_in_content_not_split() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "test")]).unwrap();

    // A line with an embedded newline - this is a single "line" with literal \n
    let content = "before\nafter"; // This is one InputLine with embedded newline
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: content.to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    // "test" doesn't appear in "before\nafter", so no findings
    assert!(eval.findings.is_empty());
}

// =============================================================================
// Edge Case: Verifies byte_to_column integration with evaluate_lines
// =============================================================================

/// Integration test: verify byte_to_column result flows correctly to Finding.column.
#[test]
fn test_byte_to_column_flows_to_finding_column() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "def")]).unwrap();

    // "abc def" - 'd' is at byte index 4, which is character index 4 (0-indexed)
    // byte_to_column returns 4 + 1 = 5
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abc def".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    // "def" starts at character index 4 (0-indexed), so column is 5 (1-indexed)
    assert_eq!(
        finding.column.unwrap(),
        5,
        "Column should be 5 (def starts at char position 4, 1-indexed)"
    );
}

// =============================================================================
// Edge Case: Match not at start of line
// =============================================================================

/// Test that matches not at the start of line get correct column values.
#[test]
fn test_match_in_middle_of_line() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "xyz")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 42,
        content: "abc xyz def".to_string(), // "xyz" starts at column 5 (1-indexed)
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(finding.column.unwrap(), 5, "Match at column 5");
    assert_eq!(finding.line, 42);
}

// =============================================================================
// Edge Case: Two rules with different patterns on same line
// =============================================================================

/// Test two rules with different patterns both matching same line.
#[test]
fn test_two_rules_different_patterns_same_line() {
    let rules = compile_rules(&[
        make_rule("alpha", Severity::Error, "alpha"),
        make_rule("beta", Severity::Warn, "beta"),
    ])
    .unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "alpha and beta".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 2);
    assert_eq!(eval.counts.error, 1);
    assert_eq!(eval.counts.warn, 1);

    // alpha is at column 1, beta is at column 11
    // "alpha and beta" - beta starts at char index 10 (0-indexed), column 11 (1-indexed)
    let mut columns: Vec<u32> = eval.findings.iter().map(|f| f.column.unwrap()).collect();
    columns.sort();
    assert_eq!(columns, vec![1, 11]);
}

// =============================================================================
// Edge Case: Very long line (but well under u32::MAX)
// =============================================================================

/// Test evaluate_lines with a very long line (1 million characters).
#[test]
fn test_very_long_line() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "M")]).unwrap();

    // Create a 1 million character string with 'M' at the very end
    let content = format!("{}M", "x".repeat(999_999));
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    };

    let eval = evaluate_lines([line], &rules, 100);

    // Should find the 'M' at column 1_000_000 (1-indexed)
    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert!(finding.column.is_some());
    assert_eq!(
        finding.column.unwrap(),
        1_000_000,
        "Match at the very end should have column 1_000_000"
    );
}

// =============================================================================
// Edge Case: ASCII-only content (byte == char)
// =============================================================================

/// Test that ASCII-only content has straightforward byte==char mapping.
#[test]
fn test_ascii_column_mapping() {
    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "d")]).unwrap();

    // "abcd" - 'd' is at byte index 3, char index 3, column 4
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abcd".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);

    assert_eq!(eval.findings.len(), 1);
    let finding = &eval.findings[0];
    assert_eq!(finding.column.unwrap(), 4, "d is at column 4");
}
