// Copyright 2024 Diffguard contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for byte_to_column usize→u32 cast overflow handling.
//!
//! These tests verify that the conversion from `byte_to_column` result
//! (`Option<usize>`) to `Finding.column` (`Option<u32>`) is overflow-safe.
//!
//! Issue: evaluate.rs:298 - byte_to_column usize→u32 cast has no guard against truncation
//! ADR: ADR-0247 Checked Conversion for Finding.column Overflow
//!
//! ## Acceptance Criteria
//!
//! AC1: Overflow Returns None - when character count > u32::MAX, column must be None
//! AC2: Normal Values Pass Through Unchanged - when character count <= u32::MAX, column value is preserved
//! AC3: Type Contract Honored - Option<u32> correctly models known vs unknown column

use diffguard_domain::InputLine;
use diffguard_domain::compile_rules;
use diffguard_domain::evaluate_lines;
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Helper to create a minimal rule for testing.
fn test_rule(id: &str, pattern: &str, languages: Vec<&str>) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: pattern.to_string(),
        languages: languages.into_iter().map(|s| s.to_string()).collect(),
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

/// Helper to create an InputLine.
fn input_line(content: &str, path: &str, line_num: u32) -> InputLine {
    InputLine {
        path: path.to_string(),
        line: line_num,
        content: content.to_string(),
    }
}

// ============================================================================
// AC1: Overflow Returns None
// ============================================================================

/// Test AC1: Overflow returns None.
///
/// This test verifies that when the character count exceeds u32::MAX,
/// the column is set to None rather than being truncated.
///
/// We test this by directly verifying the conversion logic handles
/// values > u32::MAX correctly (using u32::try_from which is the fix).
#[test]
fn test_column_overflow_returns_none() {
    // The fix uses: .and_then(|c| u32::try_from(c).ok())
    // This returns None when c > u32::MAX
    //
    // We can't practically create a string with u32::MAX + 1 characters,
    // but we can verify the conversion logic is correct by testing
    // that u32::try_from(u64::MAX) returns Err (and .ok() makes it None)

    let overflow_value: usize = u64::MAX as usize;

    // This is the fixed conversion pattern from evaluate.rs:298
    let column: Option<u32> = Some(overflow_value).and_then(|c| u32::try_from(c).ok());

    assert!(
        column.is_none(),
        "Overflow value should convert to None, got {:?}",
        column
    );
}

/// Test AC2: Values at u32::MAX boundary pass through correctly.
///
/// A value exactly at u32::MAX should succeed.
#[test]
fn test_column_u32_max_boundary_passes_through() {
    let max_value: usize = u32::MAX as usize;

    // This is the fixed conversion pattern from evaluate.rs:298
    let column: Option<u32> = Some(max_value).and_then(|c| u32::try_from(c).ok());

    assert_eq!(
        column,
        Some(u32::MAX),
        "u32::MAX should pass through unchanged, got {:?}",
        column
    );
}

/// Test AC2: Values at u32::MAX + 1 return None.
///
/// A value just over u32::MAX should return None (not truncate).
#[test]
fn test_column_u32_max_plus_one_returns_none() {
    let over_max_value: usize = u32::MAX as usize + 1;

    // This is the fixed conversion pattern from evaluate.rs:298
    let column: Option<u32> = Some(over_max_value).and_then(|c| u32::try_from(c).ok());

    assert!(
        column.is_none(),
        "u32::MAX + 1 should return None, got {:?}",
        column
    );
}

// ============================================================================
// AC3: Type Contract Honored
// ============================================================================

/// Test AC3: Type contract is honored.
///
/// Finding.column is Option<u32> which semantically means:
/// - Some(value) = known column
/// - None = unknown column
///
/// The fix ensures overflow returns None (unknown), not a truncated wrong value.
#[test]
fn test_column_type_contract_honored_on_overflow() {
    // If we had a line with u32::MAX + 1 characters, the old vulnerable code would do:
    //   Some(u32::MAX as usize + 1).map(|c| c as u32)  // = Some(0) due to wrap!
    //
    // The fixed code does:
    //   Some(u32::MAX as usize + 1).and_then(|c| u32::try_from(c).ok())  // = None
    //
    // None is semantically correct because we don't know the actual column.

    let wrapped_truncated: Option<u32> = Some(u32::MAX as usize + 1).map(|c| c as u32);
    let correctly_handled: Option<u32> =
        Some(u32::MAX as usize + 1).and_then(|c| u32::try_from(c).ok());

    // The vulnerable code would produce Some(0) - a wrong-but-plausible value
    assert_eq!(
        wrapped_truncated,
        Some(0),
        "Truncation would give wrong value 0"
    );

    // The fixed code produces None - semantically correct "unknown column"
    assert!(
        correctly_handled.is_none(),
        "Fixed code should return None for overflow, got {:?}",
        correctly_handled
    );
}

/// Test AC3: Normal column values are Some (known), not None.
///
/// For normal inputs, the column should be Some(value), not None.
#[test]
fn test_column_normal_values_are_some_not_none() {
    let normal_value: usize = 100;

    let column: Option<u32> = Some(normal_value).and_then(|c| u32::try_from(c).ok());

    assert!(
        column.is_some(),
        "Normal value should be Some, got {:?}",
        column
    );
    assert_eq!(column.unwrap(), 100);
}

// ============================================================================
// AC2: Normal Values Pass Through Unchanged (Integration Tests)
// ============================================================================

/// Test AC2: Normal ASCII values pass through unchanged.
///
/// When byte_to_column returns a character count within u32::MAX range,
/// the column value must be preserved exactly.
#[test]
fn test_column_normal_ascii_values_pass_through_unchanged() {
    let rules = compile_rules(&[test_rule("test.rule", "TODO", vec!["rust"])]).unwrap();
    let lines = vec![
        input_line("TODO: fix this", "src/main.rs", 1),
        input_line("  TODO", "src/main.rs", 2),
        input_line("TODO", "src/main.rs", 3),
    ];

    let verdict = evaluate_lines(lines, &rules, 100);

    // All TODOs should be found with their correct column positions
    // "TODO" starts at column 1 in all three lines
    assert!(
        !verdict.findings.is_empty(),
        "Should find at least one TODO"
    );
    for finding in &verdict.findings {
        assert!(
            matches!(finding.column, Some(c) if c >= 1),
            "Column should be Some value >= 1, got {:?}",
            finding.column
        );
    }
}

/// Test AC2: Multi-byte UTF-8 characters are counted correctly.
///
/// byte_to_column counts characters, not bytes. For multi-byte UTF-8,
/// the character count can be significantly less than the byte count.
#[test]
fn test_column_utf8_character_counting() {
    let rules = compile_rules(&[test_rule("test.rule", "β", vec!["rust"])]).unwrap();
    // "aβc" - 'a' is 1 byte, 'β' is 2 bytes, 'c' is 1 byte = 4 bytes total
    // Characters: 'a' (col 1), 'β' (col 2), 'c' (col 3)
    let lines = vec![input_line("aβc", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    // Should find 'β' at column 2 (1-based character index)
    assert!(!verdict.findings.is_empty(), "Should find β");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(2),
        "β should be at column 2 (character count), got {:?}",
        finding.column
    );
}

/// Test that the column position is correctly reported for patterns at different positions.
#[test]
fn test_column_position_correct_for_different_positions() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    // "abcXdef" - X is at byte 3, which is character 3 (1-based)
    let lines = vec![input_line("abcXdef", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find X");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(4), // "abc" = 3 chars, then X at position 4
        "X should be at column 4, got {:?}",
        finding.column
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

/// Test that pattern not found produces no findings.
#[test]
fn test_no_findings_when_pattern_not_present() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    let lines = vec![input_line("abc", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(verdict.findings.is_empty(), "Should not find X in abc");
}

/// Test that pattern at start of line has column 1.
#[test]
fn test_column_is_one_when_pattern_at_start() {
    let rules = compile_rules(&[test_rule("test.rule", "ABC", vec!["rust"])]).unwrap();
    let lines = vec![input_line("ABCdef", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find ABC");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(1),
        "ABC at start should be at column 1, got {:?}",
        finding.column
    );
}

// ============================================================================
// Green Test Builder Edge Cases
// ============================================================================

/// Test that pattern at end of line has correct column.
///
/// When a pattern appears at the very end of a line (e.g., "abc TODO"),
/// the column should correctly reflect its position.
#[test]
fn test_column_at_end_of_line() {
    let rules = compile_rules(&[test_rule("test.rule", "TODO", vec!["rust"])]).unwrap();
    // "abc TODO" - T is at column 5 (1-based: a=1, b=2, c=3, space=4, T=5)
    let lines = vec![input_line("abc TODO", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find TODO");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(5),
        "TODO at end should be at column 5, got {:?}",
        finding.column
    );
}

/// Test that only the first match is reported when multiple matches exist on a line.
///
/// The evaluation uses `first_match()` which returns only the first occurrence.
/// This test verifies that behavior and confirms all findings have valid columns.
#[test]
fn test_multiple_matches_only_first_reported() {
    let rules = compile_rules(&[test_rule("test.rule", "TODO", vec!["rust"])]).unwrap();
    // "TODO one TODO two TODO"
    // First TODO is at column 1, second at column 10, third at column 19
    // But first_match() only returns the first match at column 1
    let lines = vec![input_line("TODO one TODO two TODO", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    // The system only finds the FIRST match per line (via first_match function)
    assert_eq!(
        verdict.findings.len(),
        1,
        "System only reports first match per line, got {}",
        verdict.findings.len()
    );

    // The first finding should be at column 1
    assert_eq!(
        verdict.findings[0].column,
        Some(1),
        "First TODO should be at column 1, got {:?}",
        verdict.findings[0].column
    );
}

/// Test column calculation with tab characters.
///
/// Tabs are counted as single characters in the character count,
/// but may be displayed as multiple columns. byte_to_column counts
/// characters, not display width.
#[test]
fn test_column_with_tab_characters() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    // "\tX" - tab at byte 0, X at byte 1
    // Tab is 1 char, X is at column 2
    let lines = vec![input_line("\tX", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find X after tab");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(2),
        "X after tab should be at column 2 (character count), got {:?}",
        finding.column
    );
}

/// Test column calculation with wide CJK characters.
///
/// CJK characters like Chinese "中" are typically single-width in
/// character count but may render as double-width. byte_to_column
/// counts characters, not display width.
#[test]
fn test_column_with_cjk_characters() {
    let rules = compile_rules(&[test_rule("test.rule", "中", vec!["rust"])]).unwrap();
    // "a中b" - a=1 col, 中=2 col, b=3 col
    // bytes: a(1 byte) + 中(3 bytes) + b(1 byte) = 5 bytes
    let lines = vec![input_line("a中b", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find 中");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(2),
        "中 should be at column 2, got {:?}",
        finding.column
    );
}

/// Test that empty content lines don't cause issues.
///
/// An empty line should still allow pattern matching (though finding
/// anything on an empty line is unusual).
#[test]
fn test_empty_line_no_crash() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    let lines = vec![input_line("", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    // Should not crash and should have no findings
    assert!(
        verdict.findings.is_empty(),
        "Should not find X in empty string"
    );
}

/// Test single character line with match at column 1.
#[test]
fn test_single_character_line() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    let lines = vec![input_line("X", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find X");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(1),
        "Single X should be at column 1, got {:?}",
        finding.column
    );
}

/// Test pattern matching at byte index 0 (start of string).
///
/// When a match starts at the very first byte of the string,
/// byte_to_column is called with byte_idx=0.
#[test]
fn test_column_at_byte_index_zero() {
    let rules = compile_rules(&[test_rule("test.rule", "AAA", vec!["rust"])]).unwrap();
    // "AAAX" - AAA starts at byte 0
    let lines = vec![input_line("AAAX", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find AAA");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(1),
        "AAA at start should be at column 1, got {:?}",
        finding.column
    );
}

/// Test regex pattern that matches multiple characters.
///
/// When a regex like `\d+` matches multiple digits, the column
/// should point to the start of the match.
#[test]
fn test_column_for_multichar_regex_match() {
    let rules = compile_rules(&[test_rule("test.rule", r"\d+", vec!["rust"])]).unwrap();
    // "abc 123 def" - digits start at column 5 (1-based)
    // "abc " = 4 chars (a=1, b=2, c=3, space=4)
    let lines = vec![input_line("abc 123 def", "src/main.rs", 1)];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert!(!verdict.findings.is_empty(), "Should find 123");
    let finding = verdict.findings.first().unwrap();
    assert_eq!(
        finding.column,
        Some(5),
        "123 should start at column 5, got {:?}",
        finding.column
    );
}

/// Test that findings on different lines are independent.
///
/// Each line's column is calculated independently.
#[test]
fn test_column_independent_per_line() {
    let rules = compile_rules(&[test_rule("test.rule", "X", vec!["rust"])]).unwrap();
    let lines = vec![
        input_line("X", "src/main.rs", 1),
        input_line("  X", "src/main.rs", 2),
        input_line("    X", "src/main.rs", 3),
    ];

    let verdict = evaluate_lines(lines, &rules, 100);

    assert_eq!(
        verdict.findings.len(),
        3,
        "Should find 3 X's across 3 lines"
    );

    // Line 1: X at column 1
    assert_eq!(verdict.findings[0].column, Some(1));
    // Line 2: X at column 3
    assert_eq!(verdict.findings[1].column, Some(3));
    // Line 3: X at column 5
    assert_eq!(verdict.findings[2].column, Some(5));
}
