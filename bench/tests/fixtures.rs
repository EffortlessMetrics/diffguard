//! Edge case tests for benchmark fixtures
//!
//! These tests verify that the fixture generators in `bench/fixtures.rs`
//! handle edge cases correctly: empty inputs, boundary conditions,
//! unicode content, special characters, and state management.

use diffguard_diff::{DiffLine, parse_unified_diff};
use diffguard_types::Scope;

// Import fixtures under test
use diffguard_bench::fixtures::preprocessor_helpers::{fresh_preprocessor, reset_preprocessor};
use diffguard_bench::fixtures::{
    convert_diff_line_to_input_line, convert_diff_lines_to_input_lines, generate_input_lines,
    generate_lines_with_comment_density, generate_mixed_unified_diff,
    generate_receipt_with_findings, generate_unified_diff,
};
use diffguard_domain::preprocess::Language;

// =============================================================================
// generate_unified_diff edge cases
// =============================================================================

#[test]
fn test_generate_unified_diff_empty() {
    let result = generate_unified_diff(0, "src/main.rs");
    assert_eq!(result, "", "Empty diff should return empty string");
}

#[test]
fn test_generate_unified_diff_single_line() {
    let result = generate_unified_diff(1, "a.rs");
    assert!(result.contains("diff --git a/a.rs b/a.rs"));
    assert!(result.contains("@@ -1,1 +1,1 @@"));
    assert!(result.contains("+line 1 content here"));
    // Should have no extra lines after the single content line
    let lines: Vec<&str> = result.lines().collect();
    // diff header (4 lines) + hunk header (1 line) + content (1 line) = 6 lines
    assert_eq!(
        lines.len(),
        6,
        "Single line diff should have exactly 6 lines total"
    );
}

#[test]
fn test_generate_unified_diff_large() {
    // Test with 100K lines - verify it doesn't panic and produces correct line count
    let result = generate_unified_diff(100_000, "large_file.rs");
    let lines: Vec<&str> = result.lines().collect();
    // 4 header lines + 1 hunk header + 100K content lines = 100005
    assert_eq!(
        lines.len(),
        100_005,
        "100K line diff should have exactly 100005 lines"
    );
}

#[test]
fn test_generate_unified_diff_unicode_content() {
    let result = generate_unified_diff(3, "src/日本語.rs");
    assert!(result.contains("src/日本語.rs"));
    assert!(result.contains("+line 1 content here"));
}

#[test]
fn test_generate_unified_diff_special_chars_in_path() {
    // Test paths with spaces, underscores, hyphens, numbers
    let result = generate_unified_diff(1, "src/my-file_2.rs");
    assert!(result.contains("src/my-file_2.rs"));
}

#[test]
fn test_generate_unified_diff_parsed_correctly() {
    // Verify the generated diff can be parsed by the actual parser
    let diff_text = generate_unified_diff(100, "src/main.rs");
    let (diff_lines, stats) =
        parse_unified_diff(&diff_text, Scope::Added).expect("Generated diff should be parseable");

    assert_eq!(diff_lines.len(), 100, "Should parse 100 diff lines");
    assert_eq!(stats.lines, 100, "Stats should report 100 lines");
}

#[test]
fn test_generate_unified_diff_parsed_with_scope_added() {
    // Added scope should return all + lines
    let diff_text = generate_unified_diff(50, "src/main.rs");
    let (diff_lines, _) =
        parse_unified_diff(&diff_text, Scope::Added).expect("Should parse with Added scope");
    assert_eq!(diff_lines.len(), 50);
}

#[test]
fn test_generate_unified_diff_parsed_empty_with_zero_lines() {
    let diff_text = generate_unified_diff(0, "src/main.rs");
    let (diff_lines, stats) = parse_unified_diff(&diff_text, Scope::Added)
        .expect("Empty diff should parse without error");
    assert_eq!(diff_lines.len(), 0, "Empty diff should produce 0 lines");
    assert_eq!(stats.lines, 0, "Empty diff stats should report 0 lines");
}

// =============================================================================
// generate_mixed_unified_diff edge cases
// =============================================================================

#[test]
fn test_generate_mixed_unified_diff_empty() {
    let result = generate_mixed_unified_diff(0, "src/main.rs");
    assert_eq!(result, "", "Empty mixed diff should return empty string");
}

#[test]
fn test_generate_mixed_unified_diff_single_line() {
    let result = generate_mixed_unified_diff(1, "x.rs");
    // Single line could be added, deleted, or context depending on modulo
    let lines: Vec<&str> = result.lines().collect();
    // At minimum: 4 header + 1 hunk + 1 content = 6 lines
    assert!(lines.len() >= 6);
}

#[test]
fn test_generate_mixed_unified_diff_produces_all_change_types() {
    let diff_text = generate_mixed_unified_diff(30, "src/main.rs");
    let (diff_lines, _) =
        parse_unified_diff(&diff_text, Scope::Added).expect("Mixed diff should be parseable");

    // With 30 lines and modulo 3, we expect ~10 added lines (when i % 3 == 0)
    assert!(
        diff_lines.len() >= 10,
        "Should have added lines in mixed diff"
    );
}

#[test]
fn test_generate_mixed_unified_diff_multiple_hunks() {
    // With chunk_size=10, 100 lines should produce multiple hunks
    let result = generate_mixed_unified_diff(100, "src/main.rs");
    let hunk_count = result.matches("@@").count();
    assert!(
        hunk_count >= 10,
        "100 lines with chunk_size=10 should produce multiple hunks"
    );
}

// =============================================================================
// convert_diff_line_to_input_line tests
// =============================================================================

#[test]
fn test_convert_diff_line_preserves_path() {
    let diff_line = DiffLine {
        path: "src/main.rs".to_string(),
        line: 42,
        content: "let x = 1;".to_string(),
        kind: diffguard_diff::ChangeKind::Added,
    };

    let input_line = convert_diff_line_to_input_line(diff_line.clone());

    assert_eq!(input_line.path, diff_line.path);
    assert_eq!(input_line.line, diff_line.line);
    assert_eq!(input_line.content, diff_line.content);
}

#[test]
fn test_convert_diff_line_strips_kind() {
    // DiffLine has kind, InputLine doesn't
    let diff_line = DiffLine {
        path: "test.rs".to_string(),
        line: 1,
        content: "content".to_string(),
        kind: diffguard_diff::ChangeKind::Deleted,
    };

    let input_line = convert_diff_line_to_input_line(diff_line);

    // InputLine should not have a 'kind' field at all
    // This is verified by the type system - we just verify the conversion works
    assert_eq!(input_line.path, "test.rs");
    assert_eq!(input_line.line, 1);
    assert_eq!(input_line.content, "content");
}

#[test]
fn test_convert_diff_lines_batch() {
    let diff_lines = vec![
        DiffLine {
            path: "a.rs".to_string(),
            line: 1,
            content: "line 1".to_string(),
            kind: diffguard_diff::ChangeKind::Added,
        },
        DiffLine {
            path: "a.rs".to_string(),
            line: 2,
            content: "line 2".to_string(),
            kind: diffguard_diff::ChangeKind::Added,
        },
        DiffLine {
            path: "a.rs".to_string(),
            line: 3,
            content: "line 3".to_string(),
            kind: diffguard_diff::ChangeKind::Added,
        },
    ];

    let input_lines = convert_diff_lines_to_input_lines(&diff_lines);

    assert_eq!(input_lines.len(), 3);
    assert_eq!(input_lines[0].line, 1);
    assert_eq!(input_lines[1].line, 2);
    assert_eq!(input_lines[2].line, 3);
}

#[test]
fn test_convert_diff_lines_empty() {
    let diff_lines: Vec<DiffLine> = vec![];
    let input_lines = convert_diff_lines_to_input_lines(&diff_lines);
    assert!(input_lines.is_empty());
}

// =============================================================================
// generate_input_lines edge cases
// =============================================================================

#[test]
fn test_generate_input_lines_empty() {
    let result = generate_input_lines(0, "src/main.rs");
    assert!(result.is_empty());
}

#[test]
fn test_generate_input_lines_single() {
    let result = generate_input_lines(1, "x.rs");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].line, 1);
    assert!(result[0].content.contains("line 1"));
}

#[test]
fn test_generate_input_lines_preserves_path() {
    let result = generate_input_lines(5, "my/path/to/file.rs");
    for line in &result {
        assert_eq!(line.path, "my/path/to/file.rs");
    }
}

#[test]
fn test_generate_input_lines_sequential_line_numbers() {
    let result = generate_input_lines(100, "test.rs");
    for (i, line) in result.iter().enumerate() {
        assert_eq!(line.line, (i + 1) as u32);
    }
}

#[test]
fn test_generate_input_lines_large() {
    let result = generate_input_lines(10_000, "large.rs");
    assert_eq!(result.len(), 10_000);
    assert_eq!(result.last().unwrap().line, 10_000);
}

// =============================================================================
// generate_lines_with_comment_density edge cases
// =============================================================================

#[test]
fn test_generate_lines_zero_density() {
    let lines = generate_lines_with_comment_density(100, 0.0, "rust");
    // All lines should be plain code (not comments)
    for line in &lines {
        assert!(
            !line.starts_with("// "),
            "Zero density should produce no comments: {}",
            line
        );
        assert!(
            !line.starts_with("/* "),
            "Zero density should produce no block comments: {}",
            line
        );
    }
}

#[test]
fn test_generate_lines_full_density() {
    let lines = generate_lines_with_comment_density(20, 1.0, "rust");
    // With full density and modulo 5 for block comments, most lines should be comments
    let comment_count = lines
        .iter()
        .filter(|l| l.starts_with("// ") || l.starts_with("/* "))
        .count();
    assert!(comment_count > 0, "Full density should produce comments");
}

#[test]
fn test_generate_lines_partial_density() {
    // Test 25%, 50%, 75% densities
    for &density in &[0.25, 0.50, 0.75] {
        let lines = generate_lines_with_comment_density(1000, density, "rust");
        // Due to the algorithm, we expect approximately density fraction to be comments
        // This is not exact due to integer division, so we use a tolerance
        let comment_count = lines
            .iter()
            .filter(|l| {
                l.starts_with("// ") || l.starts_with("/* ") || l.contains(" block comment ")
            })
            .count();
        let actual_density = comment_count as f32 / 1000.0;
        // Allow 10% tolerance
        assert!(
            (actual_density - density).abs() < 0.10,
            "Density {} produced {}% comments, expected ~{}%",
            density,
            actual_density * 100.0,
            density * 100.0
        );
    }
}

#[test]
fn test_generate_lines_multiple_languages() {
    // Rust
    let rust_lines = generate_lines_with_comment_density(10, 0.5, "rust");
    assert!(rust_lines.iter().any(|l| l.contains("// ")));

    // Python
    let python_lines = generate_lines_with_comment_density(10, 0.5, "python");
    assert!(python_lines.iter().any(|l| l.contains("# ")));

    // JavaScript
    let js_lines = generate_lines_with_comment_density(10, 0.5, "javascript");
    assert!(js_lines.iter().any(|l| l.contains("// ")));
}

#[test]
fn test_generate_lines_unknown_language_defaults_to_cstyle() {
    // Unknown language should default to // comments
    let lines = generate_lines_with_comment_density(10, 0.5, "unknown_lang");
    assert!(lines.iter().any(|l| l.contains("// ")));
}

#[test]
fn test_generate_lines_preserves_line_count() {
    for num_lines in [0, 1, 10, 100, 1000] {
        let lines = generate_lines_with_comment_density(num_lines, 0.5, "rust");
        assert_eq!(
            lines.len(),
            num_lines,
            "Line count should match for num_lines={}",
            num_lines
        );
    }
}

// =============================================================================
// generate_receipt_with_findings edge cases
// =============================================================================

#[test]
fn test_generate_receipt_empty_findings() {
    let receipt = generate_receipt_with_findings(0, vec![]);
    assert_eq!(receipt.findings.len(), 0);
    assert_eq!(receipt.verdict.counts.error, 0);
    assert_eq!(receipt.verdict.counts.warn, 0);
    assert_eq!(receipt.verdict.counts.info, 0);
}

#[test]
fn test_generate_receipt_single_finding() {
    let finding = diffguard_types::Finding {
        rule_id: "test_rule".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Test finding".to_string(),
        path: "src/main.rs".to_string(),
        line: 10,
        column: Some(5),
        match_text: "test".to_string(),
        snippet: "context".to_string(),
    };

    let receipt = generate_receipt_with_findings(1, vec![finding.clone()]);
    assert_eq!(receipt.findings.len(), 1);
    assert_eq!(receipt.findings[0].rule_id, "test_rule");
}

#[test]
fn test_generate_receipt_multiple_findings_severity_distribution() {
    // Generate 30 findings - with modulo 3, expect ~10 of each severity
    let findings: Vec<diffguard_types::Finding> = (0..30)
        .map(|i| diffguard_types::Finding {
            rule_id: format!("rule_{}", i),
            severity: match i % 3 {
                0 => diffguard_types::Severity::Error,
                1 => diffguard_types::Severity::Warn,
                _ => diffguard_types::Severity::Info,
            },
            message: format!("Finding {}", i),
            path: format!("src/file{}.rs", i % 10),
            line: i as u32,
            column: Some(1),
            match_text: format!("match_{}", i),
            snippet: "snippet".to_string(),
        })
        .collect();

    let receipt = generate_receipt_with_findings(30, findings);

    assert_eq!(receipt.findings.len(), 30);
    // Verify all findings are present with correct rule_ids
    for i in 0..30 {
        assert!(receipt.findings[i].rule_id == format!("rule_{}", i));
    }
    // Note: verdict.counts are hardcoded to 0 in the fixture - they don't derive from findings
    assert_eq!(receipt.verdict.counts.error, 0);
    assert_eq!(receipt.verdict.counts.warn, 0);
    assert_eq!(receipt.verdict.counts.info, 0);
}

// =============================================================================
// Preprocessor helper edge cases
// =============================================================================

#[test]
fn test_fresh_preprocessor_has_clean_state() {
    let mut preprocessor = fresh_preprocessor(Language::Rust);
    // Fresh preprocessor should produce unmodified output for plain code
    let result = preprocessor.sanitize_line("let x = 1;");
    // With comments_and_strings mode, strings might be masked, but plain code should pass through
    assert_eq!(result.len(), "let x = 1;".len());
}

#[test]
fn test_reset_clears_state_after_multiline_comment() {
    let mut preprocessor = fresh_preprocessor(Language::Rust);

    // Process a line that starts a block comment (but doesn't end it)
    let line1 = "    /* start of block comment";
    let result1 = preprocessor.sanitize_line(line1);

    // Reset the preprocessor
    reset_preprocessor(&mut preprocessor);

    // After reset, a new line that looks like it would be inside a block comment
    // should NOT be treated as inside a block comment
    let line2 = "    regular code after reset";
    let result2 = preprocessor.sanitize_line(line2);

    // The reset should have cleared the in-block-comment state
    // Both lines should have their original length (no masking)
    assert_eq!(result1.len(), line1.len());
    assert_eq!(result2.len(), line2.len());
}

#[test]
fn test_reset_works_on_fresh_instance() {
    let mut preprocessor = fresh_preprocessor(Language::Python);

    // Reset on a fresh instance should be a no-op (already in initial state)
    reset_preprocessor(&mut preprocessor);

    let result = preprocessor.sanitize_line("let x = 1;");
    assert_eq!(result.len(), "let x = 1;".len());
}

#[test]
fn test_preprocessor_different_languages() {
    for lang in [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::Go,
    ] {
        let mut preprocessor = fresh_preprocessor(lang);
        let result = preprocessor.sanitize_line("let x = 1;");
        assert_eq!(
            result.len(),
            "let x = 1;".len(),
            "Preprocessor for {:?} should handle plain code",
            lang
        );
    }
}

// =============================================================================
// Integration: generated fixtures work with actual parsing/evaluation
// =============================================================================

#[test]
fn test_full_pipeline_generate_diff_parse_convert_evaluate() {
    use diffguard_domain::evaluate::evaluate_lines;
    use diffguard_domain::rules::compile_rules;
    use diffguard_types::{MatchMode, RuleConfig, Severity};

    // Generate a diff
    let diff_text = generate_unified_diff(100, "src/main.rs");

    // Parse it
    let (diff_lines, _) =
        parse_unified_diff(&diff_text, Scope::Added).expect("Should parse generated diff");

    // Convert to InputLines
    let input_lines = convert_diff_lines_to_input_lines(&diff_lines);
    assert_eq!(input_lines.len(), 100);

    // Compile a simple rule that matches "line"
    let rule_configs = vec![RuleConfig {
        id: "test_rule".to_string(),
        severity: Severity::Warn,
        message: "Found 'line'".to_string(),
        description: String::new(),
        languages: vec![],
        patterns: vec!["line".to_string()],
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
    }];

    let rules = compile_rules(&rule_configs).expect("Should compile rules");

    // Evaluate
    let evaluation = evaluate_lines(input_lines, &rules, 1000);

    // Should find matches since content contains "line"
    assert!(
        !evaluation.findings.is_empty(),
        "Should find 'line' in generated content"
    );
}

#[test]
fn test_fixtures_are_deterministic() {
    // Running the same generator twice should produce the same output
    let diff1 = generate_unified_diff(100, "test.rs");
    let diff2 = generate_unified_diff(100, "test.rs");
    assert_eq!(diff1, diff2, "Generator should be deterministic");

    let lines1 = generate_lines_with_comment_density(50, 0.5, "rust");
    let lines2 = generate_lines_with_comment_density(50, 0.5, "rust");
    assert_eq!(lines1, lines2, "Line generator should be deterministic");
}

#[test]
fn test_unicode_paths_and_content() {
    // Unicode in paths
    let diff_unicode_path = generate_unified_diff(5, "src/путь/файл.rs");
    assert!(diff_unicode_path.contains("путь"));
    assert!(diff_unicode_path.contains("файл.rs"));

    // Unicode content
    let input_lines = generate_input_lines(3, "test.rs");
    // Content is ASCII, but the function itself should work with unicode paths
    assert_eq!(input_lines.len(), 3);
}

#[test]
fn test_empty_path_handling() {
    let diff_text = generate_unified_diff(1, "");
    assert!(diff_text.contains("diff --git a/ b/"));
    assert!(diff_text.contains("--- a/"));
    assert!(diff_text.contains("+++ b/"));
}
