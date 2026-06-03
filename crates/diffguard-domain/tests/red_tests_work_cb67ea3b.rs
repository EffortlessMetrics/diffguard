//! Red tests for work-cb67ea3b: trim_snippet hardcodes MAX_CHARS while safe_slice end param is unused
//!
//! These tests verify the target behavior after fixing `trim_snippet` to use match bounds
//! via `safe_slice` instead of hardcoding `MAX_CHARS = 240` and truncating from line start.
//!
//! The fix requires:
//! 1. `trim_snippet(s: &str, start: usize, end: usize) -> String` - accepts bounds parameters
//! 2. `RawMatchEvent` has `match_end: Option<usize>` field
//! 3. `MatchEvent` has `match_end: Option<usize>` field
//! 4. `match_end` is propagated through single-line and multiline match paths
//! 5. `Finding.snippet` is the bounded matched region (same as `match_text`), not first 240 chars of line
//!
//! Key test scenario:
//! - A line contains "AAAAAAAAAA...AAAAAA xxx YYYYYYYYY...YYYYY" where xxx is the match at position 250
//! - The current `trim_snippet(&full_line)` returns first 240 chars (wrong)
//! - After fix, `trim_snippet(&full_line, start, end)` returns "xxx" (the bounded match region)
//!
//! NOTE: These tests focus on the PUBLIC API behavior (`evaluate_lines` -> `Finding.snippet`).
//! The private function `trim_snippet` and private structs cannot be tested directly.

use diffguard_domain::evaluate::{InputLine, evaluate_lines};
use diffguard_domain::rules::compile_rules;
use diffguard_types::{MatchMode, RuleConfig, Severity};

// ============================================================================
// Test 1: Finding.snippet is bounded match region, not first 240 chars
// ============================================================================

/// Test that `Finding.snippet` is the bounded match region, not first N chars of line.
///
/// Scenario:
/// - Line content is 298 chars: "A".repeat(250) + "MATCH" + "B".repeat(43)
/// - The pattern "MATCH" occurs at byte position 250
/// - After the fix, `snippet` should be "MATCH" (bounded extraction)
/// - Current behavior: `snippet` is first 240 chars = "A".repeat(240) + "…"
#[test]
fn snippet_is_bounded_match_region_not_first_n_chars() {
    let rules = compile_rules(&[test_rule(
        "test.rule",
        Severity::Error,
        "found match",
        vec!["rust"],
        vec!["MATCH"],
        vec!["*.rs"],
    )])
    .expect("valid rules");

    // Create a line where the match is at position 250 (not at the start)
    // Line: 250 A's + "MATCH" (5 chars) + 43 B's = 298 chars total
    let line_content = format!("{}{}{}", "A".repeat(250), "MATCH", "B".repeat(43));
    assert_eq!(line_content.len(), 298, "line should be 298 chars total");

    let lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: line_content.clone(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    // Should find exactly one match
    assert!(!eval.findings.is_empty(), "Expected at least one finding");
    let finding = &eval.findings[0];

    // match_text should be "MATCH"
    assert_eq!(
        finding.match_text, "MATCH",
        "match_text should be the bounded matched text"
    );

    // CRITICAL ASSERTION: snippet should ALSO be "MATCH" (bounded extraction)
    // Current buggy behavior: snippet is first 240 chars = "A".repeat(240) + "…"
    assert_eq!(
        finding.snippet, "MATCH",
        "snippet should be bounded match region 'MATCH', not first 240 chars of line"
    );
}

// ============================================================================
// Test 2: ellipsis appended ONLY when bounded region exceeds 240 chars
// ============================================================================

/// Test that ellipsis is appended ONLY when bounded region exceeds 240 chars.
///
/// Scenario:
/// - Matched region is 298 chars (exceeds MAX_CHARS=240)
/// - Ellipsis should be appended to indicate truncation
#[test]
fn snippet_truncates_with_ellipsis_when_bounded_region_exceeds_max_chars() {
    let rules = compile_rules(&[test_rule(
        "test.rule",
        Severity::Error,
        "found long match",
        vec!["rust"],
        vec![".*"], // Match the entire line
        vec!["*.rs"],
    )])
    .expect("valid rules");

    // Create a line with 298 chars of all 'X'
    let line_content = "X".repeat(298);
    assert_eq!(line_content.len(), 298);

    let lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: line_content.clone(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert!(!eval.findings.is_empty(), "Expected at least one finding");
    let finding = &eval.findings[0];

    // match_text should be the full 298 chars (the entire line matched)
    assert_eq!(
        finding.match_text.len(),
        298,
        "match_text should be the full 298 char matched region"
    );

    // snippet should be truncated to 240 chars + ellipsis
    // because the bounded region (298 chars) exceeds MAX_CHARS (240)
    assert!(
        finding.snippet.ends_with('…'),
        "snippet should end with ellipsis when bounded region exceeds MAX_CHARS=240"
    );
    assert_eq!(
        finding.snippet.chars().count(),
        241, // 240 chars + ellipsis
        "snippet should have 241 chars (240 + ellipsis) when truncated"
    );
}

// ============================================================================
// Test 3: NO ellipsis when bounded region is within MAX_CHARS
// ============================================================================

/// Test that NO ellipsis is appended when bounded region is within MAX_CHARS.
///
/// Scenario:
/// - Matched region is 5 chars "MATCH" (within MAX_CHARS=240)
/// - No truncation needed, no ellipsis
#[test]
fn snippet_no_ellipsis_when_bounded_region_within_max_chars() {
    let rules = compile_rules(&[test_rule(
        "test.rule",
        Severity::Error,
        "found short match",
        vec!["rust"],
        vec!["MATCH"],
        vec!["*.rs"],
    )])
    .expect("valid rules");

    // Line with "MATCH" at position 0
    let line_content = "MATCH extra content here".to_string();

    let lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: line_content.clone(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert!(!eval.findings.is_empty(), "Expected at least one finding");
    let finding = &eval.findings[0];

    // snippet should be exactly "MATCH" with no ellipsis
    assert_eq!(
        finding.snippet, "MATCH",
        "snippet should be exact match when within MAX_CHARS limit"
    );
    assert!(
        !finding.snippet.ends_with('…'),
        "snippet should NOT end with ellipsis when bounded region is within MAX_CHARS"
    );
}

// ============================================================================
// Test 4: match_end propagated in single-line match path
// ============================================================================

/// Test that match_end is properly propagated through the single-line match path.
///
/// This is verified indirectly by checking that the Finding's snippet field
/// correctly reflects the bounded match region.
#[test]
fn single_line_match_propagates_match_end_to_snippet() {
    let rules = compile_rules(&[test_rule(
        "test.rule",
        Severity::Error,
        "pattern at position 100",
        vec!["rust"],
        vec!["MATCH"],
        vec!["*.rs"],
    )])
    .expect("valid rules");

    // Line: 100 A's + "MATCH" + rest
    // Match is at byte position 100-105
    let line_content = format!("{}{}", "a".repeat(100), "MATCH extra");
    // 100 + 11 = 111 chars
    assert_eq!(line_content.len(), 111);

    let lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: line_content.clone(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert!(!eval.findings.is_empty(), "Expected at least one finding");
    let finding = &eval.findings[0];

    // snippet should be "MATCH" (bounded extraction)
    assert_eq!(
        finding.snippet, "MATCH",
        "snippet should be bounded region 'MATCH', not 'a'.repeat(100) + 'M...'"
    );
}

// ============================================================================
// Test 5: safe_slice used internally for Unicode-safe bounds extraction
// ============================================================================

/// Test that `safe_slice` is used by `trim_snippet` for Unicode-safe bounds extraction.
///
/// This test uses a line with multi-byte Unicode characters to verify
/// that byte-index bounds are handled correctly.
#[test]
fn trim_snippet_handles_unicode_correctly_with_bounds() {
    let rules = compile_rules(&[test_rule(
        "test.rule",
        Severity::Error,
        "found unicode pattern",
        vec!["rust"],
        vec!["ζ"], // Greek zeta - multi-byte in UTF-8
        vec!["*.rs"],
    )])
    .expect("valid rules");

    // Line with Greek zeta at position 50 (byte position, but chars before it)
    // "aaaa...aaaaζ" - 50 'a' chars + Greek zeta
    let line_content = format!("{}{}", "a".repeat(50), "ζ");
    // Note: 'ζ' is 2 bytes in UTF-8

    let lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: line_content.clone(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert!(!eval.findings.is_empty(), "Expected at least one finding");
    let finding = &eval.findings[0];

    // snippet should be exactly "ζ" - the bounded match
    assert_eq!(
        finding.snippet, "ζ",
        "snippet should be bounded to 'ζ' (Unicode handled correctly)"
    );
}

// ============================================================================
// Helper function
// ============================================================================

/// Helper to create a RuleConfig for testing.
fn test_rule(
    id: &str,
    severity: Severity,
    message: &str,
    languages: Vec<&str>,
    patterns: Vec<&str>,
    paths: Vec<&str>,
) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: message.to_string(),
        languages: languages.into_iter().map(|s| s.to_string()).collect(),
        patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
        paths: paths.into_iter().map(|s| s.to_string()).collect(),
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
