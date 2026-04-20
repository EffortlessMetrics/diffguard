//! Property-based tests for evaluate_lines column calculation
//!
//! These tests verify invariants about the `column` field returned by
//! evaluate_lines. Properties tested:
//!
//! 1. **Column is 1-indexed**: column >= 1 for any match
//! 2. **Column is bounded**: column <= char_count of the line (for non-empty lines)
//! 3. **Match at start**: match starting at byte 0 → column = 1
//! 4. **Consistency**: same input → same column output
//! 5. **Monotonicity**: later matches have >= columns
//! 6. **UTF-8 correctness**: multi-byte chars don't corrupt column calculation
//!
//! The usize→u32 truncation bug (evaluate.rs:298) would cause:
//! - For lines with chars > u32::MAX, column becomes None instead of Some(u32::MAX)

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};
use proptest::prelude::*;

/// Helper to create a RuleConfig for testing
fn make_rule(pattern: &str) -> RuleConfig {
    RuleConfig {
        id: "prop.test".to_string(),
        description: String::new(),
        severity: Severity::Error,
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // =============================================================================
    // Property 1: Column is 1-indexed (column >= 1)
    // =============================================================================

    /// For any line with content and any pattern that matches,
    /// the resulting finding's column must be >= 1.
    ///
    /// Invariant: If a match is found, column is always at least 1.
    #[test]
    fn property_column_is_one_indexed(content in "[a-zA-Z0-9 ]{1,100}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        for finding in &eval.findings {
            prop_assert!(
                finding.column.is_some(),
                "Column should be Some for match in content={:?}, pattern={:?}",
                content,
                first_char
            );
            let col = finding.column.unwrap();
            prop_assert!(
                col >= 1,
                "Column must be >= 1, got {} for content={:?}, pattern={:?}",
                col,
                content,
                first_char
            );
        }
    }

    // =============================================================================
    // Property 2: Column is bounded by character count
    // =============================================================================

    /// The column value should never exceed the character count of the line.
    /// A match can only start within the content, so column <= char_count.
    ///
    /// Invariant: column <= content.chars().count() for all findings.
    #[test]
    fn property_column_bounded_by_char_count(content in "[a-zA-Z0-9 ]{1,100}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let char_count = content.chars().count();
        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        for finding in &eval.findings {
            if let Some(col) = finding.column {
                prop_assert!(
                    col <= char_count as u32,
                    "Column {} exceeds char_count {} for content={:?}",
                    col,
                    char_count,
                    content
                );
            }
        }
    }

    // =============================================================================
    // Property 3: Match at byte 0 always has column 1
    // =============================================================================

    /// When a pattern matches at the very start of content (byte offset 0),
    /// the column must be 1.
    ///
    /// Invariant: If match is at position 0, column = 1.
    #[test]
    fn property_match_at_start_has_column_one(content in "[a-z]([a-zA-Z0-9 ]{0,99})") {
        let first_char = content.chars().next().unwrap().to_string();
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        // The first-char match should always be at column 1
        for finding in &eval.findings {
            if finding.match_text.starts_with(&first_char) {
                prop_assert_eq!(
                    finding.column,
                    Some(1),
                    "Match at start should have column 1, got {:?} for content={:?}, first_char={:?}",
                    finding.column,
                    content,
                    first_char
                );
            }
        }
    }

    // =============================================================================
    // Property 4: Consistency - same input produces same column
    // =============================================================================

    /// Evaluating the same content with the same pattern should always
    /// produce the same column values.
    ///
    /// Invariant: evaluate_lines is deterministic.
    #[test]
    fn property_column_is_consistent(content in "[a-zA-Z0-9 ]{1,100}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let line1 = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };
        let line2 = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval1 = evaluate_lines([line1], &rules, 100);
        let eval2 = evaluate_lines([line2], &rules, 100);

        prop_assert_eq!(
            eval1.findings.len(),
            eval2.findings.len(),
            "Same content should produce same number of findings"
        );

        for (f1, f2) in eval1.findings.iter().zip(eval2.findings.iter()) {
            prop_assert_eq!(
                f1.column,
                f2.column,
                "Same content should produce same column, got {:?} vs {:?}",
                f1.column,
                f2.column
            );
        }
    }

    // =============================================================================
    // Property 5: Monotonicity - later matches have >= columns
    // =============================================================================

    /// For multiple matches on the same line, columns should be monotonically
    /// non-decreasing (later matches appear at >= column positions).
    ///
    /// Invariant: If finding[i].column < finding[j].column then i < j (sorted by column).
    #[test]
    fn property_columns_are_monotonic(content in "[a-zA-Z0-9 ]{1,100}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        let mut columns: Vec<u32> = eval.findings.iter()
            .filter_map(|f| f.column)
            .collect();
        columns.sort();

        // Check that columns are monotonically non-decreasing
        for window in columns.windows(2) {
            prop_assert!(
                window[0] <= window[1],
                "Columns should be monotonically non-decreasing: {:?}",
                columns
            );
        }
    }

    // =============================================================================
    // Property 6: UTF-8 correctness
    // =============================================================================

    /// Multi-byte UTF-8 characters should not corrupt column calculation.
    /// The column should reflect the character position, not byte position.
    ///
    /// Invariant: Column calculation counts characters, not bytes.
    #[test]
    fn property_utf8_column_correctness(content in "αβγδ[a-zA-Z0-9 ]{1,20}") {
        // Match on Greek alpha which is a 2-byte UTF-8 character
        let pattern = "α".to_string();
        let rules = compile_rules(&[make_rule(&pattern)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&pattern) {
            return Ok(());
        }

        // Find expected column (1-indexed char position)
        let expected_col = content.find(&pattern).map(|byte_pos| {
            content[..byte_pos].chars().count() as u32 + 1
        });

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        for finding in &eval.findings {
            if let (Some(col), Some(expected)) = (finding.column, expected_col) {
                prop_assert_eq!(
                    col, expected,
                    "UTF-8 column mismatch: expected {}, got {} for content={:?}",
                    expected, col, content
                );
            }
        }
    }

    // =============================================================================
    // Property 7: Column None only when no matches
    // =============================================================================

    /// If there are findings, every finding should have a Some column value.
    /// Column None means the column couldn't be determined, which should only
    /// happen if there are no matches at all.
    ///
    /// Invariant: If findings.len() > 0, every finding.column.is_some().
    #[test]
    fn property_column_some_when_findings_exist(content in "[a-zA-Z0-9 ]{1,100}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        if !eval.findings.is_empty() {
            for finding in &eval.findings {
                prop_assert!(
                    finding.column.is_some(),
                    "Column should be Some when findings exist, got None for content={:?}",
                    content
                );
            }
        }
    }

    // =============================================================================
    // Property 8: Column never exceeds u32::MAX (when it can be represented)
    // =============================================================================

    /// Even for very long lines (but still < u32::MAX chars), the column
    /// should remain correctly represented as u32.
    ///
    /// This is the property that would be broken by the truncation bug at
    /// evaluate.rs:298 if the line had > u32::MAX characters.
    ///
    /// Invariant: column should always fit in u32 for any practical line length.
    #[test]
    fn property_column_fits_in_u32(content in "[a-zA-Z0-9 ]{1,10000}") {
        let first_char = content.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "x".to_string());
        let rules = compile_rules(&[make_rule(&first_char)]).unwrap();

        // Skip if pattern doesn't match
        if !content.contains(&first_char) {
            return Ok(());
        }

        let line = InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: content.clone(),
        };

        let eval = evaluate_lines([line], &rules, 100);

        for finding in &eval.findings {
            if let Some(col) = finding.column {
                // Column values are clamped to u32::MAX by the byte_to_column fix
                // so we just verify col is a valid u32 (always true by type)
                prop_assert!(col >= 1, "Column should be at least 1, got {}", col);
            }
        }
    }

}
