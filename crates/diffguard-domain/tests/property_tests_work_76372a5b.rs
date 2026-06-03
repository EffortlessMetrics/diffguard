//! Property-based tests for `evaluate_lines_with_overrides_and_language` invariants
//!
//! These tests verify key invariants that should hold across all inputs:
//! 1. files_scanned equals distinct file count
//! 2. lines_scanned equals input line count
//! 3. RuleHitStat consistency (total = emitted + suppressed, emitted = info + warn + error)
//! 4. VerdictCounts consistency with rule_hits aggregation
//! 5. findings bounded by max_findings
//! 6. truncated_findings correctly tracks overflow

use proptest::prelude::*;
use std::collections::BTreeSet;

use diffguard_domain::{
    InputLine, RuleHitStat, evaluate_lines_with_overrides_and_language, rules::compile_rules,
};
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Strategy to generate valid file paths
fn file_path_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        "[a-zA-Z][a-zA-Z0-9_]{0,15}".prop_filter("no dots except extension", |s| !s.contains('.')),
        1..3,
    )
    .prop_map(|parts| parts.join("/"))
}

/// Strategy to generate file paths with extensions
fn file_path_with_ext_strategy() -> impl Strategy<Value = String> {
    (
        file_path_strategy(),
        "[a-z]+".prop_filter("not a common ext", |s| {
            ![
                "rs", "py", "js", "ts", "go", "java", "kt", "rb", "sh", "c", "cpp", "cs", "txt",
            ]
            .contains(&s.as_str())
        }),
    )
        .prop_map(|(path, ext)| format!("{}.{}", path, ext))
}

/// Strategy to generate input lines
fn input_line_strategy() -> impl Strategy<Value = InputLine> {
    (
        file_path_with_ext_strategy(),
        1u32..1000,
        "[^\x00-\x1f]{0,50}",
    )
        .prop_map(|(path, line, content)| InputLine {
            path,
            line,
            content,
        })
}

/// Helper to create a simple rule config
fn simple_rule_config(id: &str, severity: Severity, pattern: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: format!("Found: {}", pattern),
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

/// Verify rule_hit.total == rule_hit.emitted + rule_hit.suppressed
fn check_rule_hit_total_consistency(stat: &RuleHitStat) -> bool {
    stat.total == stat.emitted + stat.suppressed
}

/// Verify rule_hit.emitted == rule_hit.info + rule_hit.warn + rule_hit.error
fn check_rule_hit_emitted_breakdown_consistency(stat: &RuleHitStat) -> bool {
    stat.emitted == stat.info + stat.warn + stat.error
}

// =============================================================================
// Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property 1: files_scanned equals number of distinct files in input
    #[test]
    fn property_files_scanned_equals_distinct_files(
        lines in prop::collection::vec(input_line_strategy(), 1..50),
        max_findings in 0usize..100,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            max_findings,
            None,
            None,
        );

        let distinct_files: BTreeSet<_> = lines.iter().map(|l| l.path.clone()).collect();
        let expected_files = distinct_files.len() as u64;

        prop_assert_eq!(
            eval.files_scanned, expected_files,
            "files_scanned should equal number of distinct file paths in input"
        );
    }

    // Property 2: lines_scanned equals number of input lines
    #[test]
    fn property_lines_scanned_equals_input_count(
        lines in prop::collection::vec(input_line_strategy(), 1..100),
        max_findings in 0usize..200,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            max_findings,
            None,
            None,
        );

        let expected_lines = lines.len() as u32;

        prop_assert_eq!(
            eval.lines_scanned, expected_lines,
            "lines_scanned should equal the number of input lines"
        );
    }

    // Property 3: For each rule_hit, total == emitted + suppressed
    #[test]
    fn property_rule_hit_total_equals_emitted_plus_suppressed(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
        max_findings in 1usize..50,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule.warn", Severity::Warn, "warn"),
            simple_rule_config("rule.error", Severity::Error, "error"),
            simple_rule_config("rule.info", Severity::Info, "info"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            max_findings,
            None,
            None,
        );

        for stat in &eval.rule_hits {
            prop_assert!(
                check_rule_hit_total_consistency(stat),
                "Rule {}: total({}) should equal emitted({}) + suppressed({})",
                stat.rule_id, stat.total, stat.emitted, stat.suppressed
            );
        }
    }

    // Property 4: For each rule_hit, emitted == info + warn + error
    #[test]
    fn property_rule_hit_emitted_equals_severity_breakdown(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
        max_findings in 1usize..50,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule.warn", Severity::Warn, "warn"),
            simple_rule_config("rule.error", Severity::Error, "error"),
            simple_rule_config("rule.info", Severity::Info, "info"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            max_findings,
            None,
            None,
        );

        for stat in &eval.rule_hits {
            prop_assert!(
                check_rule_hit_emitted_breakdown_consistency(stat),
                "Rule {}: emitted({}) should equal info({}) + warn({}) + error({})",
                stat.rule_id, stat.emitted, stat.info, stat.warn, stat.error
            );
        }
    }

    // Property 5: VerdictCounts.info equals sum of rule_hits[*].info
    #[test]
    fn property_verdict_counts_info_matches_rule_hits(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule.info", Severity::Info, "info_pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            100,
            None,
            None,
        );

        let summed_info: u32 = eval.rule_hits.iter().map(|s| s.info).sum();
        prop_assert_eq!(
            eval.counts.info, summed_info,
            "VerdictCounts.info should equal sum of rule_hits[*].info"
        );
    }

    // Property 6: VerdictCounts.warn equals sum of rule_hits[*].warn
    #[test]
    fn property_verdict_counts_warn_matches_rule_hits(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule.warn", Severity::Warn, "warn_pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            100,
            None,
            None,
        );

        let summed_warn: u32 = eval.rule_hits.iter().map(|s| s.warn).sum();
        prop_assert_eq!(
            eval.counts.warn, summed_warn,
            "VerdictCounts.warn should equal sum of rule_hits[*].warn"
        );
    }

    // Property 7: VerdictCounts.error equals sum of rule_hits[*].error
    #[test]
    fn property_verdict_counts_error_matches_rule_hits(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule.error", Severity::Error, "error_pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            100,
            None,
            None,
        );

        let summed_error: u32 = eval.rule_hits.iter().map(|s| s.error).sum();
        prop_assert_eq!(
            eval.counts.error, summed_error,
            "VerdictCounts.error should equal sum of rule_hits[*].error"
        );
    }

    // Property 8: findings.len() <= max_findings
    #[test]
    fn property_findings_bounded_by_max_findings(
        lines in prop::collection::vec(input_line_strategy(), 1..50),
        max_findings in 0usize..20,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines,
            &rules,
            max_findings,
            None,
            None,
        );

        prop_assert!(
            eval.findings.len() <= max_findings,
            "findings.len() ({}) should be <= max_findings ({})",
            eval.findings.len(), max_findings
        );
    }

    // Property 9: findings.len() + truncated_findings = number of emitted (non-suppressed) events
    #[test]
    fn property_truncated_findings_correctly_counts_overflow(
        lines in prop::collection::vec(input_line_strategy(), 5..50),
        max_findings in 1usize..10,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines,
            &rules,
            max_findings,
            None,
            None,
        );

        // Total emitted (non-suppressed) events = sum of emitted across all rules
        let total_emitted: u32 = eval.rule_hits.iter().map(|s| s.emitted).sum();

        // findings.len() + truncated_findings should equal total_emitted
        let processed = eval.findings.len() as u32 + eval.truncated_findings;

        prop_assert_eq!(
            processed, total_emitted,
            "findings.len() ({}) + truncated_findings ({}) should equal total_emitted ({})",
            eval.findings.len(), eval.truncated_findings, total_emitted
        );
    }

    // Property 10: findings are sorted by line/column
    #[test]
    fn property_findings_sorted_by_location(
        lines in prop::collection::vec(input_line_strategy(), 5..30),
        max_findings in 10usize..50,
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pattern"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines,
            &rules,
            max_findings,
            None,
            None,
        );

        // Verify findings are in order by path, line, column
        for window in eval.findings.windows(2) {
            let a = &window[0];
            let b = &window[1];

            let a_loc = (a.path.as_str(), a.line, a.column.unwrap_or(0));
            let b_loc = (b.path.as_str(), b.line, b.column.unwrap_or(0));

            prop_assert!(
                a_loc <= b_loc,
                "Findings should be sorted by location: {:?} > {:?}",
                a_loc, b_loc
            );
        }
    }

    // Property 11: max_findings=0 still counts matches but emits none
    #[test]
    fn property_max_findings_zero_still_counts(
        lines in prop::collection::vec(input_line_strategy(), 1..20),
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pat"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines.clone(),
            &rules,
            0,
            None,
            None,
        );

        // findings should be empty
        prop_assert!(eval.findings.is_empty());

        // but counts should reflect actual matches
        let total_matches: u32 = eval.rule_hits.iter().map(|s| s.total).sum();
        let total_counts = eval.counts.warn + eval.counts.info + eval.counts.error;

        prop_assert_eq!(
            total_matches, total_counts + eval.counts.suppressed,
            "Total matches should equal counts + suppressed"
        );
    }

    // Property 12: Very large max_findings does not cause overflow
    #[test]
    fn property_large_max_findings_no_overflow(
        lines in prop::collection::vec(input_line_strategy(), 1..30),
    ) {
        let rules: Vec<_> = compile_rules(&[
            simple_rule_config("rule1", Severity::Warn, "pat"),
        ]).expect("rules should compile");

        let eval = evaluate_lines_with_overrides_and_language(
            lines,
            &rules,
            usize::MAX,
            None,
            None,
        );

        // With usize::MAX max_findings, nothing should be truncated
        prop_assert_eq!(eval.truncated_findings, 0);

        // All findings should be present
        let total_emitted: u32 = eval.rule_hits.iter().map(|s| s.emitted).sum();
        prop_assert_eq!(eval.findings.len() as u32, total_emitted);
    }
}

// Property 13: Empty input produces zero counts (regular test, not property-based)
#[test]
fn property_empty_input_produces_zero_counts() {
    let rule_config = simple_rule_config("rule", Severity::Warn, "x");
    let compiled = compile_rules(&[rule_config]);
    assert!(compiled.is_ok());
    let rules = compiled.unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        Vec::<InputLine>::new(),
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.info, 0);
    assert_eq!(eval.counts.warn, 0);
    assert_eq!(eval.counts.error, 0);
    assert_eq!(eval.counts.suppressed, 0);
    assert_eq!(eval.findings.len(), 0);
    assert_eq!(eval.truncated_findings, 0);
    assert_eq!(eval.files_scanned, 0);
    assert_eq!(eval.lines_scanned, 0);
}
