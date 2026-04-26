//! Snapshot tests for suppression module outputs
//!
//! Work item: work-ec9e1665
//! Feature: suppression #[must_use] annotation
//!
//! These snapshots verify the structured output of suppression parsing functions.
//! HashSet iteration order is normalized before snapshotting.

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};
use diffguard_domain::suppression::{
    parse_suppression, parse_suppression_in_comments, EffectiveSuppressions,
    SuppressionTracker,
};

/// Helper: normalize Suppression Debug output by sorting rule_ids
fn normalize_suppression_output(suppression: &diffguard_domain::suppression::Suppression) -> String {
    let rule_ids = match &suppression.rule_ids {
        None => "None (wildcard)".to_string(),
        Some(ids) => {
            let mut sorted: Vec<_> = ids.iter().collect();
            sorted.sort();
            let joined = sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            format!("Some({})", joined)
        }
    };
    
    format!("Suppression {{ kind: {:?}, rule_ids: {} }}", suppression.kind, rule_ids)
}

/// Helper: normalize EffectiveSuppressions output by sorting suppressed_rules
fn normalize_effective_suppressions(effective: &EffectiveSuppressions) -> String {
    let suppress_all = effective.suppress_all;
    let suppressed_rules: Vec<_> = effective.suppressed_rules.iter().collect();
    let suppressed_rules_sorted = {
        let mut sorted = suppressed_rules.clone();
        sorted.sort();
        let joined = sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        joined
    };
    
    format!(
        "EffectiveSuppressions {{ suppress_all: {}, suppressed_rules: {} }}",
        suppress_all,
        if suppressed_rules_sorted.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", suppressed_rules_sorted)
        }
    )
}

/// Helper: create masked comments string
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

// =============================================================================
// parse_suppression() snapshots
// =============================================================================

/// Snapshot: parse_suppression with single rule
#[test]
fn snapshot_parse_suppression_single_rule() {
    use insta::assert_snapshot;
    
    let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_single_rule", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_single_rule", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with multiple rules
#[test]
fn snapshot_parse_suppression_multiple_rules() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore rule1, rule2, rule3";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_multiple_rules", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_multiple_rules", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with wildcard (*)
#[test]
fn snapshot_parse_suppression_wildcard_star() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore *";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_wildcard_star", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_wildcard_star", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with ignore-all
#[test]
fn snapshot_parse_suppression_ignore_all() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore-all";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_ignore_all", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_ignore_all", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with ignore-next-line
#[test]
fn snapshot_parse_suppression_ignore_next_line() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore-next-line rust.no_dbg";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_ignore_next_line", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_ignore_next_line", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with ignore-next-line wildcard
#[test]
fn snapshot_parse_suppression_ignore_next_line_wildcard() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore-next-line *";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_ignore_next_line_wildcard", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_ignore_next_line_wildcard", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression empty (wildcard)
#[test]
fn snapshot_parse_suppression_empty_wildcard() {
    use insta::assert_snapshot;
    
    let line = "// diffguard: ignore";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_empty_wildcard", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_empty_wildcard", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression no directive
#[test]
fn snapshot_parse_suppression_no_directive() {
    use insta::assert_snapshot;
    
    let line = "let x = y.unwrap();";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_no_directive", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_no_directive", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression in block comment
#[test]
fn snapshot_parse_suppression_block_comment() {
    use insta::assert_snapshot;
    
    let line = "let x = y.unwrap(); /* diffguard: ignore rust.no_unwrap */";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_block_comment", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_block_comment", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression in Python hash comment
#[test]
fn snapshot_parse_suppression_python_hash_comment() {
    use insta::assert_snapshot;
    
    let line = "x = 1  # diffguard: ignore python.no_print";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_python_hash_comment", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_python_hash_comment", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression case insensitive
#[test]
fn snapshot_parse_suppression_case_insensitive() {
    use insta::assert_snapshot;
    
    let line = "// DIFFGUARD: IGNORE rule.id";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_case_insensitive", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_case_insensitive", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with extra whitespace
#[test]
fn snapshot_parse_suppression_extra_whitespace() {
    use insta::assert_snapshot;
    
    let line = "//   diffguard:   ignore   rule.id  ";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_extra_whitespace", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_extra_whitespace", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression with trailing block comment closer
#[test]
fn snapshot_parse_suppression_trailing_block_closer() {
    use insta::assert_snapshot;
    
    let line = "/* diffguard: ignore rust.no_unwrap */";
    let result = parse_suppression(line);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_trailing_block_closer", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_trailing_block_closer", normalize_suppression_output(&s)),
    }
}

// =============================================================================
// parse_suppression_in_comments() snapshots
// =============================================================================

/// Snapshot: parse_suppression_in_comments when directive is in comment
#[test]
fn snapshot_parse_suppression_in_comments_directive_in_comment() {
    use insta::assert_snapshot;
    
    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);
    let result = parse_suppression_in_comments(line, &masked);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_in_comments_directive_in_comment", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_in_comments_directive_in_comment", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression_in_comments when directive is in string (should be filtered)
#[test]
fn snapshot_parse_suppression_in_comments_directive_in_string() {
    use insta::assert_snapshot;
    
    let line = r#"let x = "diffguard: ignore rust.no_unwrap";"#;
    let masked = masked_comments(line, Language::Rust);
    let result = parse_suppression_in_comments(line, &masked);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_in_comments_directive_in_string", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_in_comments_directive_in_string", normalize_suppression_output(&s)),
    }
}

/// Snapshot: parse_suppression_in_comments length mismatch
#[test]
fn snapshot_parse_suppression_in_comments_length_mismatch() {
    use insta::assert_snapshot;
    
    let line = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked = "short"; // Wrong length
    let result = parse_suppression_in_comments(line, masked);
    
    match result {
        None => assert_snapshot!("snapshot_parse_suppression_in_comments_length_mismatch", "None".to_string()),
        Some(s) => assert_snapshot!("snapshot_parse_suppression_in_comments_length_mismatch", normalize_suppression_output(&s)),
    }
}

// =============================================================================
// SuppressionTracker::process_line() snapshots
// =============================================================================

/// Snapshot: SuppressionTracker process_line with same-line directive
#[test]
fn snapshot_tracker_process_line_same_line() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    let line = "// diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    
    assert_snapshot!("snapshot_tracker_process_line_same_line", normalize_effective_suppressions(&effective));
}

/// Snapshot: SuppressionTracker process_line with ignore-next-line
#[test]
fn snapshot_tracker_process_line_ignore_next_line() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    // Line 1: directive
    let line1 = "// diffguard: ignore-next-line rust.no_dbg";
    let masked1 = masked_comments(line1, Language::Rust);
    let effective1 = tracker.process_line(line1, &masked1);
    
    // Line 2: suppressed
    let line2 = "dbg!(value);";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);
    
    let snapshot = format!(
        "Line1 (directive): {}\nLine2 (suppressed): {}",
        normalize_effective_suppressions(&effective1),
        normalize_effective_suppressions(&effective2)
    );
    
    assert_snapshot!("snapshot_tracker_process_line_ignore_next_line", snapshot);
}

/// Snapshot: SuppressionTracker process_line with no directive
#[test]
fn snapshot_tracker_process_line_no_directive() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    let line = "let x = y.unwrap();";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    
    assert_snapshot!("snapshot_tracker_process_line_no_directive", normalize_effective_suppressions(&effective));
}

/// Snapshot: SuppressionTracker process_line with wildcard suppression
#[test]
fn snapshot_tracker_process_line_wildcard() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    let line = "// diffguard: ignore *";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    
    assert_snapshot!("snapshot_tracker_process_line_wildcard", normalize_effective_suppressions(&effective));
}

/// Snapshot: SuppressionTracker process_line consecutive next-line
#[test]
fn snapshot_tracker_process_line_consecutive_next_line() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    // Line 1: first ignore-next-line
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    tracker.process_line(line1, &masked1);
    
    // Line 2: second ignore-next-line (both pending)
    let line2 = "// diffguard: ignore-next-line rule2";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);
    
    // Line 3: both rule1 and rule2 should be suppressed
    let line3 = "some code";
    let masked3 = masked_comments(line3, Language::Rust);
    let effective3 = tracker.process_line(line3, &masked3);
    
    let snapshot = format!(
        "Line2 (both pending): {}\nLine3 (both applied): {}",
        normalize_effective_suppressions(&effective2),
        normalize_effective_suppressions(&effective3)
    );
    
    assert_snapshot!("snapshot_tracker_process_line_consecutive_next_line", snapshot);
}

/// Snapshot: SuppressionTracker after reset
#[test]
fn snapshot_tracker_process_line_after_reset() {
    use insta::assert_snapshot;
    
    let mut tracker = SuppressionTracker::new();
    
    // Line 1: ignore-next-line
    let line1 = "// diffguard: ignore-next-line rust.no_dbg";
    let masked1 = masked_comments(line1, Language::Rust);
    tracker.process_line(line1, &masked1);
    
    // Reset
    tracker.reset();
    
    // Line 2: should NOT be suppressed after reset
    let line2 = "some code";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective2 = tracker.process_line(line2, &masked2);
    
    assert_snapshot!("snapshot_tracker_process_line_after_reset", normalize_effective_suppressions(&effective2));
}
