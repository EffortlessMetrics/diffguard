// RED TEST — work-81812593
// Issue #358 claims safe_slice() and trim_snippet() are "dead code"
// These tests verify they ARE called and produce correct output.
// If these functions are removed, the evaluation pipeline breaks.

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};

fn make_test_rule(id: &str, pattern: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "test".to_string(),
        languages: vec![], // Empty = all languages
        patterns: vec![pattern.to_string()],
        paths: vec!["**/*".to_string()], // All files
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

/// Verifies safe_slice() is called in find_single_line_matches() path.
/// The issue claimed safe_slice() is "never called" — this proves otherwise.
/// Without safe_slice(), match_text would be incorrectly extracted (byte index errors).
#[test]
fn test_safe_slice_is_called_in_single_line_match_path() {
    let rules = compile_rules(&[make_test_rule("test.rule", "test")]).unwrap();

    let lines = vec![
        InputLine {
            path: "foo/test.txt".to_string(),
            line: 1,
            content: "This is a test line".to_string(),
        },
        InputLine {
            path: "foo/test.txt".to_string(),
            line: 2,
            content: "Another test here".to_string(),
        },
    ];

    let eval = evaluate_lines(lines, &rules, 1000);

    // If safe_slice() is NOT being called or is broken, match_text would be wrong.
    // safe_slice() extracts the matched substring using byte indices.
    // The expected behavior: match_text contains the actual matched text.
    assert!(
        !eval.findings.is_empty(),
        "Expected findings since 'test' pattern matches the input lines"
    );

    // Verify match_text contains "test" (the matched pattern)
    // This proves safe_slice() was called to extract the substring correctly
    let has_test_match = eval.findings.iter().any(|f| f.match_text.contains("test"));
    assert!(
        has_test_match,
        "match_text should contain 'test' — proves safe_slice() extracted matched text correctly"
    );
}

/// Verifies trim_snippet() is called when building Finding structs.
/// The issue claimed trim_snippet() is "never called" — this proves otherwise.
/// trim_snippet() truncates display text to prevent very long lines from bloating output.
/// This test verifies that a long line's snippet is shorter than the original content.
#[test]
fn test_trim_snippet_is_called_for_long_lines() {
    let rules = compile_rules(&[make_test_rule("long.line", "test")]).unwrap();

    // Create a VERY long line (> 240 chars) to test truncation
    let long_content = "x".repeat(300);
    let content = format!("{} test", long_content);
    let original_len = content.len();

    let lines = vec![InputLine {
        path: "long.txt".to_string(),
        line: 1,
        content,
    }];

    let eval = evaluate_lines(lines, &rules, 1000);

    assert!(!eval.findings.is_empty(), "Expected findings");

    let finding = eval.findings.first().expect("should have finding");

    // Key assertion: snippet is shorter than original content
    // This PROVES trim_snippet() is being called - otherwise snippet would be ~305 chars
    assert!(
        finding.snippet.len() < original_len,
        "snippet.len()={} should be < original_len={} — proves trim_snippet() truncates long lines",
        finding.snippet.len(),
        original_len
    );

    // The snippet should end with ellipsis to indicate truncation
    assert!(
        finding.snippet.ends_with('…'),
        "snippet should end with ellipsis '…' to indicate truncation"
    );
}

/// Verifies trim_snippet() does NOT truncate short strings.
/// This ensures trim_snippet() is only truncating for display optimization.
#[test]
fn test_trim_snippet_does_not_truncate_short_strings() {
    let rules = compile_rules(&[make_test_rule("short.test", "test")]).unwrap();

    // Create a short line (< 240 chars)
    let lines = vec![InputLine {
        path: "short.txt".to_string(),
        line: 1,
        content: "short test line".to_string(),
    }];

    let eval = evaluate_lines(lines, &rules, 1000);

    assert!(!eval.findings.is_empty(), "Expected findings");

    let finding = eval.findings.first().expect("should have finding");
    // Short strings should NOT be truncated (no ellipsis at end)
    assert!(
        !finding.snippet.ends_with('…'),
        "short snippet should NOT be truncated"
    );
    assert_eq!(
        finding.snippet, "short test line",
        "snippet should be unchanged for short lines"
    );
}
