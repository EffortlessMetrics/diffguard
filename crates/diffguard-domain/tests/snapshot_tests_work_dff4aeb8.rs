//! Snapshot tests for suppression module output baselines.
//!
//! These tests capture the Debug representation of suppression-related types
//! to ensure any output changes are immediately detected.
//!
//! Key types snapshotted:
//! - `Suppression` - parsed suppression directive
//! - `EffectiveSuppressions` - combined suppressions for a line
//! - `SuppressionKind` - same-line vs next-line directive type
//!
//! NOTE: HashSet iteration order is non-deterministic, so we normalize
//! rule IDs by sorting them before creating snapshot strings.

use diffguard_domain::{
    Language, PreprocessOptions, Preprocessor,
    suppression::{
        self, EffectiveSuppressions, SuppressionTracker, parse_suppression,
        parse_suppression_in_comments,
    },
};

/// Helper: get masked comments for a line in a given language.
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

/// Helper: format Suppression debug output with sorted rule IDs for deterministic snapshots.
fn format_suppression(s: &Option<suppression::Suppression>) -> String {
    match s {
        None => "None".to_string(),
        Some(suppression) => {
            let kind = format!("{:?}", suppression.kind);
            match &suppression.rule_ids {
                None => format!("Suppression {{ kind: {}, rule_ids: None }}", kind),
                Some(ids) => {
                    // Sort rule IDs for deterministic output
                    let mut sorted: Vec<&String> = ids.iter().collect();
                    sorted.sort();
                    let ids_str = sorted
                        .iter()
                        .map(|s| format!("\"{}\"", s))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "Suppression {{ kind: {}, rule_ids: Some({{{}}}) }}",
                        kind, ids_str
                    )
                }
            }
        }
    }
}

/// Helper: format EffectiveSuppressions with sorted rule IDs for deterministic snapshots.
fn format_effective(e: &EffectiveSuppressions) -> String {
    if e.suppress_all {
        if e.suppressed_rules.is_empty() {
            "EffectiveSuppressions { suppress_all: true, suppressed_rules: {} }".to_string()
        } else {
            let mut sorted: Vec<&String> = e.suppressed_rules.iter().collect();
            sorted.sort();
            let ids_str = sorted
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "EffectiveSuppressions {{ suppress_all: true, suppressed_rules: {{{}}} }}",
                ids_str
            )
        }
    } else if e.suppressed_rules.is_empty() {
        "EffectiveSuppressions { suppress_all: false, suppressed_rules: {} }".to_string()
    } else {
        let mut sorted: Vec<&String> = e.suppressed_rules.iter().collect();
        sorted.sort();
        let ids_str = sorted
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "EffectiveSuppressions {{ suppress_all: false, suppressed_rules: {{{}}} }}",
            ids_str
        )
    }
}

// ==================== parse_suppression snapshots ====================

/// Snapshot test for parse_suppression with single rule on same line.
#[test]
fn test_parse_suppression_same_line_single_rule() {
    use insta::assert_snapshot;

    let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_same_line_single_rule", formatted);
}

/// Snapshot test for parse_suppression with multiple comma-separated rules.
#[test]
fn test_parse_suppression_multiple_rules() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore rule1, rule2, rule3";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_multiple_rules", formatted);
}

/// Snapshot test for parse_suppression with wildcard (*) on same line.
#[test]
fn test_parse_suppression_wildcard_star() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore *";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_wildcard_star", formatted);
}

/// Snapshot test for parse_suppression with ignore-all.
#[test]
fn test_parse_suppression_ignore_all() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore-all";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_ignore_all", formatted);
}

/// Snapshot test for parse_suppression with ignore-next-line directive.
#[test]
fn test_parse_suppression_next_line_directive() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore-next-line rust.no_dbg";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_next_line_directive", formatted);
}

/// Snapshot test for parse_suppression with next-line wildcard.
#[test]
fn test_parse_suppression_next_line_wildcard() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore-next-line *";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_next_line_wildcard", formatted);
}

/// Snapshot test for parse_suppression with empty ignore (wildcard).
#[test]
fn test_parse_suppression_empty_ignore_is_wildcard() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_empty_ignore_is_wildcard", formatted);
}

/// Snapshot test for parse_suppression with no directive returns None.
#[test]
fn test_parse_suppression_no_directive() {
    use insta::assert_snapshot;

    let line = "let x = y.unwrap();";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_no_directive", formatted);
}

/// Snapshot test for parse_suppression in block comment.
#[test]
fn test_parse_suppression_block_comment() {
    use insta::assert_snapshot;

    let line = "let x = y.unwrap(); /* diffguard: ignore rust.no_unwrap */";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_block_comment", formatted);
}

/// Snapshot test for parse_suppression in Python hash comment.
#[test]
fn test_parse_suppression_hash_comment() {
    use insta::assert_snapshot;

    let line = "x = 1  # diffguard: ignore python.no_print";
    let suppression = parse_suppression(line);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_suppression_hash_comment", formatted);
}

// ==================== parse_suppression_in_comments snapshots ====================

/// Snapshot test for parse_suppression_in_comments with valid comment directive.
#[test]
fn test_parse_in_comments_valid_directive() {
    use insta::assert_snapshot;

    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);
    let suppression = parse_suppression_in_comments(line, &masked);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_in_comments_valid_directive", formatted);
}

/// Snapshot test for parse_suppression_in_comments rejects string content.
#[test]
fn test_parse_in_comments_rejects_string() {
    use insta::assert_snapshot;

    let line = r#"let x = "diffguard: ignore rust.no_unwrap";"#;
    let masked = masked_comments(line, Language::Rust);
    let suppression = parse_suppression_in_comments(line, &masked);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_in_comments_rejects_string", formatted);
}

/// Snapshot test for parse_suppression_in_comments with length mismatch.
#[test]
fn test_parse_in_comments_length_mismatch() {
    use insta::assert_snapshot;

    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = "short"; // Wrong length
    let suppression = parse_suppression_in_comments(line, masked);
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_in_comments_length_mismatch", formatted);
}

/// Snapshot test: string then comment prefers comment directive.
#[test]
fn test_parse_in_comments_string_then_comment() {
    use insta::assert_snapshot;

    let line = r#"let x = "diffguard: ignore rust.no_unwrap"; // diffguard: ignore rust.no_dbg"#;
    let masked = masked_comments(line, Language::Rust);
    let suppression = parse_suppression_in_comments(line, &masked);
    // Should detect rust.no_dbg from the comment, NOT rust.no_unwrap from string
    let formatted = format_suppression(&suppression);

    assert_snapshot!("parse_in_comments_string_then_comment", formatted);
}

// ==================== SuppressionTracker snapshots ====================

/// Snapshot test for SuppressionTracker with same-line suppression.
#[test]
fn test_tracker_same_line_suppression_output() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();
    let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    let formatted = format_effective(&effective);

    assert_snapshot!("tracker_same_line_suppression_output", formatted);
}

/// Snapshot test for SuppressionTracker next-line directive flow.
#[test]
fn test_tracker_next_line_directive_flow() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();

    // Line 1: directive
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    let effective1 = tracker.process_line(line1, &masked1);

    // Line 2: should be suppressed
    let line2 = "actual code";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);

    // Line 3: suppression expired
    let line3 = "more code";
    let masked3 = masked_comments(line3, Language::Rust);
    let effective3 = tracker.process_line(line3, &masked3);

    let snapshot = format!(
        "line1_effective: {}\nline2_effective: {}\nline3_effective: {}",
        format_effective(&effective1),
        format_effective(&effective2),
        format_effective(&effective3)
    );

    assert_snapshot!("tracker_next_line_directive_flow", snapshot);
}

/// Snapshot test for SuppressionTracker with wildcard suppression.
#[test]
fn test_tracker_wildcard_suppression_output() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();
    let line = "// diffguard: ignore *";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    let formatted = format_effective(&effective);

    assert_snapshot!("tracker_wildcard_suppression_output", formatted);
}

/// Snapshot test for SuppressionTracker reset clears pending state.
#[test]
fn test_tracker_reset_clears_pending() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();

    // Set up pending next-line suppression
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    tracker.process_line(line1, &masked1);

    // Reset tracker
    tracker.reset();

    // Next line should NOT be suppressed
    let line2 = "some code";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective = tracker.process_line(line2, &masked2);
    let formatted = format_effective(&effective);

    assert_snapshot!("tracker_reset_clears_pending", formatted);
}

/// Snapshot test for SuppressionTracker with multiple consecutive next-line directives.
#[test]
fn test_tracker_multiple_next_line_directives() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();

    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    let effective1 = tracker.process_line(line1, &masked1);

    let line2 = "// diffguard: ignore-next-line rule2";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);

    let line3 = "actual code";
    let masked3 = masked_comments(line3, Language::Rust);
    let effective3 = tracker.process_line(line3, &masked3);

    let snapshot = format!(
        "after_line1: {}\nafter_line2: {}\nafter_line3: {}",
        format_effective(&effective1),
        format_effective(&effective2),
        format_effective(&effective3)
    );

    assert_snapshot!("tracker_multiple_next_line_directives", snapshot);
}

/// Snapshot test for SuppressionTracker combining same and next line suppressions.
#[test]
fn test_tracker_both_same_and_next_line() {
    use insta::assert_snapshot;

    let mut tracker = SuppressionTracker::new();

    // Line with next-line directive
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    let effective1 = tracker.process_line(line1, &masked1);

    // Line with same-line directive (should combine with pending rule1)
    let line2 = "x = 1 // diffguard: ignore rule2";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);

    let snapshot = format!(
        "after_next_line_directive: {}\nafter_same_line_with_pending: {}",
        format_effective(&effective1),
        format_effective(&effective2)
    );

    assert_snapshot!("tracker_both_same_and_next_line", snapshot);
}

// ==================== EffectiveSuppressions snapshots ====================

/// Snapshot test for EffectiveSuppressions default (empty).
#[test]
fn test_effective_suppressions_empty() {
    use insta::assert_snapshot;

    let effective = EffectiveSuppressions::default();
    let formatted = format_effective(&effective);

    assert_snapshot!("effective_suppressions_empty", formatted);
}

/// Snapshot test for EffectiveSuppressions with specific rules.
#[test]
fn test_effective_suppressions_specific_rules() {
    use insta::assert_snapshot;

    let mut effective = EffectiveSuppressions::default();
    effective.suppressed_rules.insert("rule1".to_string());
    effective.suppressed_rules.insert("rule2".to_string());
    let formatted = format_effective(&effective);

    assert_snapshot!("effective_suppressions_specific_rules", formatted);
}

/// Snapshot test for EffectiveSuppressions with suppress_all=true.
#[test]
fn test_effective_suppressions_wildcard() {
    use insta::assert_snapshot;

    let effective = EffectiveSuppressions {
        suppress_all: true,
        ..Default::default()
    };
    let formatted = format_effective(&effective);

    assert_snapshot!("effective_suppressions_wildcard", formatted);
}

// ==================== Suppression::suppresses() snapshots ====================

/// Snapshot test for Suppression::suppresses() with specific rule.
#[test]
fn test_suppression_suppresses_specific() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore rust.no_unwrap";
    let suppression = parse_suppression(line).expect("should parse");

    // Test various lookups
    let snapshot = format!(
        "suppresses_rust.no_unwrap: {}\nsuppresses_other: {}",
        suppression.suppresses("rust.no_unwrap"),
        suppression.suppresses("other.rule")
    );

    assert_snapshot!("suppression_suppresses_specific", snapshot);
}

/// Snapshot test for Suppression::suppresses() with wildcard.
#[test]
fn test_suppression_suppresses_wildcard() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore *";
    let suppression = parse_suppression(line).expect("should parse");

    let snapshot = format!(
        "suppresses_any_rule: {}\nsuppresses_other: {}",
        suppression.suppresses("any.rule"),
        suppression.suppresses("other.rule")
    );

    assert_snapshot!("suppression_suppresses_wildcard", snapshot);
}

/// Snapshot test for Suppression::suppresses() with multiple rules.
#[test]
fn test_suppression_suppresses_multiple_rules() {
    use insta::assert_snapshot;

    let line = "// diffguard: ignore rule1, rule2, rule3";
    let suppression = parse_suppression(line).expect("should parse");

    let snapshot = format!(
        "suppresses_rule1: {}\nsuppresses_rule2: {}\nsuppresses_rule3: {}\nsuppresses_rule4: {}",
        suppression.suppresses("rule1"),
        suppression.suppresses("rule2"),
        suppression.suppresses("rule3"),
        suppression.suppresses("rule4")
    );

    assert_snapshot!("suppression_suppresses_multiple_rules", snapshot);
}
