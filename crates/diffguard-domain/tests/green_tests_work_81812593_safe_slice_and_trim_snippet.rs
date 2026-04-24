// GREEN TESTS — work-81812593
// Edge case tests for safe_slice() and trim_snippet().
// These verify the implementation handles edge cases correctly.

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};

fn make_test_rule(id: &str, pattern: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "test".to_string(),
        languages: vec![],
        patterns: vec![pattern.to_string()],
        paths: vec!["**/*".to_string()],
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

/// Edge case: short string should NOT be truncated.
#[test]
fn test_trim_snippet_short_string_not_truncated() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let content = "This is a test line".to_string();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        !finding.snippet.ends_with('…'),
        "Short snippet should NOT be truncated"
    );
}

/// Edge case: very long line should be truncated with ellipsis.
#[test]
fn test_trim_snippet_very_long_line_truncates() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let content = format!("{} test", "x".repeat(300));
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.snippet.ends_with('…'),
        "Very long line should be truncated"
    );
}

/// Edge case: Unicode short string should NOT truncate.
#[test]
fn test_trim_snippet_unicode_short_not_truncated() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let content = format!("{} test", "😀".repeat(60));
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        !finding.snippet.ends_with('…'),
        "64 Unicode chars should not be truncated"
    );
}

/// Edge case: very long Unicode line should truncate.
#[test]
fn test_trim_snippet_unicode_long_truncates() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let content = format!("{} test", "😀".repeat(250));
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.snippet.ends_with('…'),
        "254 Unicode chars should be truncated"
    );
}

/// Edge case: empty string should not panic.
#[test]
fn test_trim_snippet_empty_string_no_panic() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "".to_string(),
    }];
    let _eval = evaluate_lines(lines, &rules, 1000);
}

/// Edge case: match at the very start of a string.
#[test]
fn test_safe_slice_match_at_start() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "test at the beginning".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.match_text.contains("test"),
        "Should find 'test' at start"
    );
}

/// Edge case: match at the very end of a string.
#[test]
fn test_safe_slice_match_at_end() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "at the end of test".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.match_text.contains("test"),
        "Should find 'test' at end"
    );
}

/// Edge case: single character match.
#[test]
fn test_safe_slice_single_char_match() {
    let rules = compile_rules(&[make_test_rule("x", "x")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "a x b".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert_eq!(finding.match_text, "x", "Should match single 'x'");
}

/// Edge case: entire string is the match.
#[test]
fn test_safe_slice_entire_string_match() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "test".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert_eq!(finding.match_text, "test", "Should match entire string");
}

/// Edge case: Unicode string with match in middle.
#[test]
fn test_safe_slice_unicode_in_match() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "Hello 世界 test 你好".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.match_text.contains("test"),
        "Should find 'test' in Unicode string"
    );
}

/// Edge case: CRLF line endings.
#[test]
fn test_safe_slice_crlf_line_endings() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "test\r\n".to_string(),
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.match_text.contains("test"),
        "Should handle CRLF line endings"
    );
}

/// Edge case: empty content should not panic.
#[test]
fn test_safe_slice_empty_content_no_panic() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "".to_string(),
    }];
    let _eval = evaluate_lines(lines, &rules, 1000);
}

/// Edge case: long Unicode line with match.
#[test]
fn test_safe_slice_long_unicode_line() {
    let rules = compile_rules(&[make_test_rule("test", "test")]).unwrap();
    let content = format!("{} test", "😀".repeat(300));
    let lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content,
    }];
    let eval = evaluate_lines(lines, &rules, 1000);
    assert!(!eval.findings.is_empty(), "Expected finding");
    let finding = eval.findings.first().unwrap();
    assert!(
        finding.match_text.contains("test"),
        "Should find 'test' in long Unicode line"
    );
    assert!(
        finding.snippet.ends_with('…'),
        "Long Unicode line should be truncated"
    );
}
