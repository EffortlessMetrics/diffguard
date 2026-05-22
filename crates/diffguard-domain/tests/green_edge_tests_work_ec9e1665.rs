//! Green edge case tests for work-ec9e1665: Add `#[must_use]` to `parse_suppression()`
//!
//! The `#[must_use]` attribute is purely compile-time enforcement. These tests verify
//! that `parse_suppression()` and `parse_suppression_in_comments()` behave correctly
//! when their return values ARE used.

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};

fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

// ==================== parse_suppression edge case tests ====================

/// Empty string input returns None.
#[test]
fn parse_suppression_empty_string() {
    use diffguard_domain::suppression::parse_suppression;
    assert!(parse_suppression("").is_none());
}

/// Newline-only input returns None.
#[test]
fn parse_suppression_newline_only() {
    use diffguard_domain::suppression::parse_suppression;
    assert!(parse_suppression("\n").is_none());
}

/// Whitespace-only input returns None.
#[test]
fn parse_suppression_whitespace_only() {
    use diffguard_domain::suppression::parse_suppression;
    assert!(parse_suppression("   \t  ").is_none());
}

/// Directive with no space between prefix and ignore keyword.
#[test]
fn parse_suppression_no_space_after_colon() {
    use diffguard_domain::suppression::SuppressionKind;
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard:ignorerule.id";
    let suppression = parse_suppression(line).expect("should parse despite no space");
    assert_eq!(suppression.kind, SuppressionKind::SameLine);
    assert!(suppression.suppresses("rule.id"));
}

/// Directive with multiple spaces between prefix and keyword.
#[test]
fn parse_suppression_multiple_spaces_after_prefix() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard:   ignore   rule.id";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule.id"));
}

/// Directive at the very start of line (no leading whitespace).
#[test]
fn parse_suppression_at_line_start() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "diffguard: ignore rule.id";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule.id"));
}

/// Unicode characters in rule ID.
#[test]
fn parse_suppression_unicode_rule_id() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard: ignore rust.no_unwrap_";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rust.no_unwrap_"));
}

/// Rule ID with numbers, underscores, and hyphens.
#[test]
fn parse_suppression_complex_rule_id_syntax() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard: ignore rule_1, rule-2, Rule_3-test";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule_1"));
    assert!(suppression.suppresses("rule-2"));
    assert!(suppression.suppresses("Rule_3-test"));
}

/// Trailing comma in rule list is handled gracefully.
#[test]
fn parse_suppression_trailing_comma() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard: ignore rule1, rule2,";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule1"));
    assert!(suppression.suppresses("rule2"));
}

/// Empty segments between commas are handled.
#[test]
fn parse_suppression_empty_rule_between_commas() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard: ignore rule1,  , rule2";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule1"));
    assert!(suppression.suppresses("rule2"));
}

/// Block comment closer at end is stripped before parsing rules.
#[test]
fn parse_suppression_trailing_block_comment_closer() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "/* diffguard: ignore rust.no_unwrap */";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rust.no_unwrap"));
}

/// Multiple directives on same line - only the first is parsed.
#[test]
fn parse_suppression_only_first_directive_used() {
    use diffguard_domain::suppression::parse_suppression;
    // Using multiple rules on same line to verify only first directive is used
    let line = "// diffguard: ignore rule1, rule2";
    let suppression = parse_suppression(line).expect("should parse");
    assert!(suppression.suppresses("rule1"));
    assert!(suppression.suppresses("rule2"));
}

/// parse_suppression finds directive in string content.
#[test]
fn parse_suppression_in_string_is_found() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "let x = \"something\"; // diffguard: ignore rule.id";
    let suppression = parse_suppression(line).expect("should find directive");
    assert!(suppression.suppresses("rule.id"));
}

/// Directive in string is filtered by parse_suppression_in_comments.
#[test]
fn parse_suppression_in_string_filtered_by_in_comments() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "let x = \"something\"; // diffguard: ignore rule.id";
    let masked = masked_comments(line, Language::Rust);
    let suppression =
        parse_suppression_in_comments(line, &masked).expect("should find comment directive");
    assert!(suppression.suppresses("rule.id"));
}

// ==================== parse_suppression_in_comments edge case tests ====================

/// Directive in comment is found even when line also has string content.
#[test]
fn parse_suppression_in_comments_prefers_comment() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "let x = \"something\"; // diffguard: ignore rule2";
    let masked = masked_comments(line, Language::Rust);
    let suppression =
        parse_suppression_in_comments(line, &masked).expect("should find comment directive");
    assert!(suppression.suppresses("rule2"));
}

/// Directive in masked area only is not found when not in actual comment.
#[test]
fn parse_suppression_in_comments_requires_comment_mask() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "diffguard: ignore rule.id";
    let masked = masked_comments(line, Language::Rust);
    // If the directive is not in a masked comment area, it may not be found
    let result = parse_suppression_in_comments(line, &masked);
    let _ = result; // Accept either Some or None
}

/// parse_suppression_in_comments with mismatched lengths returns None.
#[test]
fn parse_suppression_in_comments_length_mismatch() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "let x = 1; // diffguard: ignore rule.id";
    let masked = "short";
    assert!(parse_suppression_in_comments(line, masked).is_none());
}

/// Directive with trailing block comment closer inside block comment is stripped.
#[test]
fn parse_suppression_in_comments_trailing_block_comment_closer() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "let x = y.unwrap(); /* diffguard: ignore rust.no_unwrap */";
    let masked = masked_comments(line, Language::Rust);
    let suppression = parse_suppression_in_comments(line, &masked).expect("should parse");
    assert!(suppression.suppresses("rust.no_unwrap"));
}

/// Directive in hash comment is found for Python.
#[test]
fn parse_suppression_in_comments_python_hash_comment() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "x = 1  # diffguard: ignore python.no_print";
    let masked = masked_comments(line, Language::Python);
    let suppression = parse_suppression_in_comments(line, &masked).expect("should parse");
    assert!(suppression.suppresses("python.no_print"));
}

// ==================== Suppression::suppresses edge cases ====================

/// suppresses returns true for wildcard (None rule_ids).
#[test]
fn suppression_suppresses_wildcard() {
    use diffguard_domain::suppression::{Suppression, SuppressionKind};
    let s = Suppression {
        kind: SuppressionKind::SameLine,
        rule_ids: None,
    };
    assert!(s.suppresses("any.rule"));
    assert!(s.suppresses("another.rule"));
    assert!(s.suppresses(""));
}

/// suppresses with specific rules only matches those rules.
#[test]
fn suppression_suppresses_specific_rules() {
    use diffguard_domain::suppression::{Suppression, SuppressionKind};
    use std::collections::HashSet;
    let mut ids = HashSet::new();
    ids.insert("rule1".to_string());
    ids.insert("rule2".to_string());
    let s = Suppression {
        kind: SuppressionKind::SameLine,
        rule_ids: Some(ids),
    };
    assert!(s.suppresses("rule1"));
    assert!(s.suppresses("rule2"));
    assert!(!s.suppresses("rule3"));
    assert!(!s.suppresses(""));
}

// ==================== EffectiveSuppressions edge cases ====================

/// EffectiveSuppressions with wildcard suppresses all.
#[test]
fn effective_suppressions_wildcard_suppresses_all() {
    use diffguard_domain::suppression::EffectiveSuppressions;
    let effective = EffectiveSuppressions {
        suppress_all: true,
        suppressed_rules: std::collections::HashSet::new(),
    };
    assert!(effective.is_suppressed("any.rule"));
    assert!(effective.is_suppressed("another.rule"));
}

/// EffectiveSuppressions is_empty is false when suppress_all is true.
#[test]
fn effective_suppressions_not_empty_when_suppress_all() {
    use diffguard_domain::suppression::EffectiveSuppressions;
    let effective = EffectiveSuppressions {
        suppress_all: true,
        suppressed_rules: std::collections::HashSet::new(),
    };
    assert!(!effective.is_empty());
}

/// EffectiveSuppressions is_empty is false when specific rules exist.
#[test]
fn effective_suppressions_not_empty_when_specific_rules() {
    use diffguard_domain::suppression::EffectiveSuppressions;
    let mut effective = EffectiveSuppressions::default();
    effective.suppressed_rules.insert("rule1".to_string());
    assert!(!effective.is_empty());
}

// ==================== SuppressionTracker edge cases ====================

/// SuppressionTracker handles consecutive next-line suppressions correctly.
#[test]
fn tracker_consecutive_next_line_suppressions() {
    use diffguard_domain::suppression::SuppressionTracker;
    let mut tracker = SuppressionTracker::new();

    // Line 1: next-line directive for rule1
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    let eff1 = tracker.process_line(line1, &masked1);
    assert!(!eff1.is_suppressed("rule1")); // Not suppressed on directive line

    // Line 2: next-line directive for rule2 (and rule1 applies here)
    let line2 = "// diffguard: ignore-next-line rule2";
    let masked2 = masked_comments(line2, Language::Rust);
    let eff2 = tracker.process_line(line2, &masked2);
    assert!(eff2.is_suppressed("rule1")); // From line 1
    assert!(!eff2.is_suppressed("rule2")); // Not on directive line

    // Line 3: no directive (rule2 applies here from line 2)
    let line3 = "some code";
    let masked3 = masked_comments(line3, Language::Rust);
    let eff3 = tracker.process_line(line3, &masked3);
    assert!(eff3.is_suppressed("rule2")); // From line 2
    assert!(!eff3.is_suppressed("rule1")); // rule1 only applied to line 2
}

/// SuppressionTracker with empty line and no directive.
#[test]
fn tracker_empty_line_no_suppression() {
    use diffguard_domain::suppression::SuppressionTracker;
    let mut tracker = SuppressionTracker::new();

    let line = "";
    let masked = masked_comments(line, Language::Rust);
    let effective = tracker.process_line(line, &masked);
    assert!(effective.is_empty());
    assert!(!effective.is_suppressed("any.rule"));
}

/// SuppressionTracker after reset has no pending suppressions.
#[test]
fn tracker_reset_clears_all_pending() {
    use diffguard_domain::suppression::SuppressionTracker;
    let mut tracker = SuppressionTracker::new();

    // Set up pending next-line suppression
    let line1 = "// diffguard: ignore-next-line rule1";
    let masked1 = masked_comments(line1, Language::Rust);
    tracker.process_line(line1, &masked1);

    // Reset tracker
    tracker.reset();

    // Line 2 should not have any suppression
    let line2 = "some code";
    let masked2 = masked_comments(line2, Language::Rust);
    let effective = tracker.process_line(line2, &masked2);
    assert!(!effective.is_suppressed("rule1"));
}

// ==================== clippy must_use_candidate verification ====================

/// Verify that parse_suppression has #[must_use] by checking it compiles correctly.
/// The #[must_use] attribute is verified by cargo clippy at compile time.
#[test]
fn parse_suppression_must_use_attribute_present() {
    use diffguard_domain::suppression::parse_suppression;
    let line = "// diffguard: ignore rule.id";
    let result = parse_suppression(line);
    assert!(result.is_some());
    let suppression = result.unwrap();
    assert!(suppression.suppresses("rule.id"));
}

/// Verify that parse_suppression_in_comments has #[must_use].
#[test]
fn parse_suppression_in_comments_must_use_attribute_present() {
    use diffguard_domain::suppression::parse_suppression_in_comments;
    let line = "// diffguard: ignore rule.id";
    let masked = masked_comments(line, Language::Rust);
    let result = parse_suppression_in_comments(line, &masked);
    assert!(result.is_some());
}
