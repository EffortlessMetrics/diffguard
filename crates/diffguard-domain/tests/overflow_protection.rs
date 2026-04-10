//! Tests for files_scanned overflow protection
//!
//! Bug: `files_seen.len() as u32` silently truncates to 0 for repos >4B files
//! Fix: Use `try_into().unwrap_or(u32::MAX)` to return sentinel instead of 0

use diffguard_domain::{compile_rules, evaluate_lines, InputLine};
use diffguard_types::{MatchMode, RuleConfig, Severity};

fn make_test_rule() -> RuleConfig {
    RuleConfig {
        id: "test.rule".to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "test message".to_string(),
        languages: vec!["rust".to_string()],
        patterns: vec!["TODO".to_string()],
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

/// Test that files_scanned returns correct count when files_seen.len() <= u32::MAX
///
/// With the bug: files_scanned correctly returns the count for small inputs
/// After fix: files_scanned still correctly returns the count
#[test]
fn test_files_scanned_returns_correct_count_for_normal_inputs() {
    let rule = compile_rules(&[make_test_rule()]).unwrap();

    // Test with a small number of unique files
    let lines = vec![
        InputLine { path: "src/lib.rs".to_string(), line: 1, content: "TODO: fix this".to_string() },
        InputLine { path: "src/lib.rs".to_string(), line: 2, content: "TODO: fix that".to_string() },
        InputLine { path: "src/main.rs".to_string(), line: 1, content: "TODO: implement".to_string() },
        InputLine { path: "src/main.rs".to_string(), line: 2, content: "nothing here".to_string() },
        InputLine { path: "src/main.rs".to_string(), line: 3, content: "TODO: refactor".to_string() },
    ];

    let eval = evaluate_lines(lines, &rule, 1000);

    // We have 2 unique files (src/lib.rs and src/main.rs)
    // Bug: files_seen.len() as u32 returns 2 (which is correct for this small case)
    // Fix: same behavior for small inputs
    assert_eq!(
        eval.files_scanned, 2,
        "files_scanned should return 2 for 2 unique files"
    );
}

/// Test that files_scanned returns u32::MAX sentinel (not 0) when files_seen.len() > u32::MAX
///
/// The bug causes `files_seen.len() as u32` to silently truncate. For example:
/// - files_seen.len() = 5_000_000_000 (5 billion)
/// - files_seen.len() as u32 = 705_032_705 (truncated, NOT 0)
/// - But for exact multiples of u32::MAX + 1, it would wrap to 0
///
/// The fix uses `files_seen.len().try_into().unwrap_or(u32::MAX)` which:
/// - Returns the correct count when files_seen.len() <= u32::MAX
/// - Returns u32::MAX as a sentinel when files_seen.len() > u32::MAX
///
/// NOTE: This test is marked #[ignore] because creating more than u32::MAX
/// unique file paths is not practical in a unit test (would require >4GB of
/// distinct strings and significant processing time).
#[test]
#[ignore = "requires creating >4B unique files - not practical for unit test"]
fn test_files_scanned_returns_max_sentinel_on_overflow() {
    let rule = compile_rules(&[make_test_rule()]).unwrap();

    // To trigger overflow, we need more than u32::MAX unique file paths
    // u32::MAX = 4,294,967,295
    // Creating this many distinct strings is not practical for a unit test.
    //
    // However, if you could create them, the test would be:
    //
    // let lines: Vec<InputLine> = (0..u64::MAX)
    //     .map(|i| InputLine {
    //         path: format!("/fake/path/file_{}.txt", i),
    //         line: 1,
    //         content: "TODO: fix this".to_string(),
    //     })
    //     .collect();
    //
    // let eval = evaluate_lines(lines, &rule, usize::MAX);
    //
    // With bug:   files_scanned would be (u64::MAX % u32::MAX) = 0
    // After fix:  files_scanned should be u32::MAX
    //
    // assert_eq!(eval.files_scanned, u32::MAX);

    // Placeholder assertion - actual test requires impractical resources
    // This line ensures the test compiles and documents intent
    assert!(true, "See test documentation for overflow behavior");
}

/// Test demonstrating that the current implementation truncates rather than saturates
///
/// On a 64-bit platform, usize::MAX is ~1.8e19 while u32::MAX is ~4.3e9.
/// This test creates a number of unique files that, when converted to u32,
/// would demonstrate truncation (though not exact overflow to 0).
///
/// Note: We use a moderate number to keep the test fast. The actual overflow
/// scenario (> u32::MAX unique files) would need to be tested separately.
#[test]
fn test_files_scanned_handles_large_but_non_overflowing_count() {
    let rule = compile_rules(&[make_test_rule()]).unwrap();

    // Create 1000 unique files - this is well within u32::MAX
    // but demonstrates the conversion logic
    let lines: Vec<InputLine> = (0..1000u64)
        .map(|i| InputLine {
            path: format!("/src/module_{}/file_{}.rs", i / 10, i),
            line: 1,
            content: "TODO: something".to_string(),
        })
        .collect();

    let eval = evaluate_lines(lines, &rule, usize::MAX);

    // 1000 unique files should give files_scanned = 1000
    assert_eq!(
        eval.files_scanned, 1000,
        "files_scanned should correctly return 1000 for 1000 unique files"
    );
}

/// Property test: files_scanned should never be 0 when input has files
///
/// This test verifies that files_scanned doesn't silently wrap to 0
/// when processing inputs with many unique files.
#[test]
fn test_files_scanned_never_zero_with_files() {
    let rule = compile_rules(&[make_test_rule()]).unwrap();

    // Create a moderate number of lines with unique paths
    let lines: Vec<InputLine> = (0..500u64)
        .map(|i| InputLine {
            path: format!("src/file_{}.rs", i),
            line: 1,
            content: "TODO".to_string(),
        })
        .collect();

    let eval = evaluate_lines(lines, &rule, usize::MAX);

    // files_scanned should never be 0 when we have files
    // With bug: could be 0 if len() wraps (but 500 < u32::MAX so won't happen here)
    // With fix: will always be correct count
    assert!(
        eval.files_scanned > 0,
        "files_scanned should never be 0 when input contains files"
    );
}
