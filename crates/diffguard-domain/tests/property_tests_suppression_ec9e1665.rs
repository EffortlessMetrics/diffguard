//! Property-based tests for suppression module
//!
//! Work item: work-ec9e1665
//! Feature: suppression #[must_use] annotation

use proptest::prelude::*;

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};
use diffguard_domain::suppression::{
    parse_suppression, parse_suppression_in_comments, EffectiveSuppressions,
    Suppression, SuppressionKind, SuppressionTracker,
};

/// Generate a random rule ID that looks valid
fn arb_rule_id() -> impl Strategy<Value = String> {
    // Rule IDs are like "rust.no_unwrap", "python.no_print", etc.
    prop::string::string_regex(r"[a-z][a-z0-9_]{0,15}\.[a-z_][a-z0-9_]{0,15}")
        .expect("valid regex")
}

/// Generate a valid suppression directive line
fn arb_suppression_line() -> impl Strategy<Value = String> {
    let kinds = prop::sample::select(vec![
        ("ignore", SuppressionKind::SameLine),
        ("ignore-next-line", SuppressionKind::NextLine),
        ("ignore-all", SuppressionKind::SameLine),
    ]);

    (kinds, prop::collection::vec(arb_rule_id(), 0..3), prop::bool::ANY)
        .prop_map(|(kind, rules, empty_wildcard)| {
            let rule_part = if rules.is_empty() {
                if empty_wildcard { "*".to_string() } else { String::new() }
            } else {
                rules.join(",")
            };
            format!("// diffguard: {} {}", kind.0, rule_part)
        })
}

/// Generate a masked comments string (same length as input, with spaces for comments)
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

// =============================================================================
// Property 1: Suppression::suppresses() consistency with is_wildcard()
// =============================================================================
// Invariant: If is_wildcard() returns true, suppresses() returns true for ALL rule IDs
// Invariant: If is_wildcard() returns false, suppresses() returns true ONLY for rules in rule_ids

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_suppression_wildcard_suppresses_all_rules(_seed: u32) {
        // When rule_ids is None (wildcard), suppresses() should return true for any rule
        let suppression = Suppression {
            kind: SuppressionKind::SameLine,
            rule_ids: None,
        };

        prop_assert!(
            suppression.suppresses("any.rule.we.can.think.of"),
            "Wildcard suppression should suppress any rule"
        );
        prop_assert!(
            suppression.suppresses("another.rule"),
            "Wildcard suppression should suppress any rule"
        );
        prop_assert!(
            suppression.is_wildcard(),
            "is_wildcard() should return true when rule_ids is None"
        );
    }

    #[test]
    fn property_suppression_specific_rules_respected(rule_id in arb_rule_id()) {
        // Generate a suppression with specific rule IDs
        let mut rule_ids = std::collections::HashSet::new();
        rule_ids.insert(rule_id.clone());

        let suppression = Suppression {
            kind: SuppressionKind::SameLine,
            rule_ids: Some(rule_ids),
        };

        // The suppression should NOT be a wildcard
        prop_assert!(
            !suppression.is_wildcard(),
            "Specific rule suppression should not be wildcard"
        );

        // The specific rule should be suppressed
        prop_assert!(
            suppression.suppresses(&rule_id),
            "Rule '{}' should be suppressed (it's in the set)", rule_id
        );

        // A different rule should NOT be suppressed
        let other_rule = "other.rule.id";
        prop_assert!(
            !suppression.suppresses(other_rule),
            "Rule '{}' should NOT be suppressed (not in the set)", other_rule
        );
    }
}

// =============================================================================
// Property 2: EffectiveSuppressions::is_suppressed() consistency
// =============================================================================
// Invariant: If suppress_all is true, is_suppressed() returns true for any rule
// Invariant: If suppress_all is false, is_suppressed() only returns true for rules in suppressed_rules

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_effective_suppressions_suppress_all(rule_id in arb_rule_id()) {
        let effective = EffectiveSuppressions {
            suppress_all: true,
            suppressed_rules: std::collections::HashSet::new(),
        };

        // When suppress_all is true, any rule should be suppressed
        prop_assert!(
            effective.is_suppressed("any.rule.at.all"),
            "When suppress_all=true, is_suppressed should return true for any rule"
        );
        prop_assert!(
            effective.is_suppressed(&rule_id),
            "When suppress_all=true, is_suppressed should return true for rule '{}'", rule_id
        );
        prop_assert!(
            !effective.is_empty(),
            "When suppress_all=true, effective suppressions should not be empty"
        );
    }

    #[test]
    fn property_effective_suppressions_specific_rules(rule_id in arb_rule_id()) {
        let mut suppressed_rules = std::collections::HashSet::new();
        suppressed_rules.insert(rule_id.clone());

        let effective = EffectiveSuppressions {
            suppress_all: false,
            suppressed_rules,
        };

        // The specific rule should be suppressed
        prop_assert!(
            effective.is_suppressed(&rule_id),
            "Rule '{}' should be suppressed", rule_id
        );

        // A different rule should NOT be suppressed
        let other_rule = "other.rule.id";
        prop_assert!(
            !effective.is_suppressed(other_rule),
            "Rule '{}' should NOT be suppressed (not in suppressed_rules)", other_rule
        );
    }

    #[test]
    fn property_effective_suppressions_empty_when_no_suppressions(_seed: u32) {
        let effective = EffectiveSuppressions::default();

        prop_assert!(
            effective.is_empty(),
            "Default EffectiveSuppressions should be empty"
        );
        prop_assert!(
            !effective.is_suppressed("any.rule"),
            "Empty effective suppressions should not suppress any rule"
        );
    }
}

// =============================================================================
// Property 3: SuppressionTracker next-line carries exactly one line
// =============================================================================
// Invariant: A next-line suppression applies to the line IMMEDIATELY after the directive
// Invariant: The suppression does NOT apply to the line after that

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_tracker_next_line_applies_to_next_line_only(rule_id in arb_rule_id()) {
        let mut tracker = SuppressionTracker::new();

        // Line 1: directive with ignore-next-line
        let line1 = format!("// diffguard: ignore-next-line {}", rule_id);
        let masked1 = masked_comments(&line1, Language::Rust);
        let effective1 = tracker.process_line(&line1, &masked1);

        // Directive line should NOT be suppressed
        prop_assert!(
            !effective1.is_suppressed(&rule_id),
            "ignore-next-line should NOT suppress the directive line itself"
        );

        // Line 2: should be suppressed
        let line2 = "some code line";
        let masked2 = masked_comments(line2, Language::Rust);
        let effective2 = tracker.process_line(line2, &masked2);

        prop_assert!(
            effective2.is_suppressed(&rule_id),
            "ignore-next-line should suppress the NEXT line"
        );

        // Line 3: should NOT be suppressed (next-line consumed)
        let line3 = "another code line";
        let masked3 = masked_comments(line3, Language::Rust);
        let effective3 = tracker.process_line(line3, &masked3);

        prop_assert!(
            !effective3.is_suppressed(&rule_id),
            "ignore-next-line suppression should NOT persist beyond the next line"
        );
    }

    #[test]
    fn property_tracker_reset_clears_pending(rule_id in arb_rule_id()) {
        let mut tracker = SuppressionTracker::new();

        // Line 1: directive with ignore-next-line
        let line1 = format!("// diffguard: ignore-next-line {}", rule_id);
        let masked1 = masked_comments(&line1, Language::Rust);
        tracker.process_line(&line1, &masked1);

        // Reset tracker
        tracker.reset();

        // Line 2: should NOT be suppressed after reset
        let line2 = "some code after reset";
        let masked2 = masked_comments(line2, Language::Rust);
        let effective2 = tracker.process_line(line2, &masked2);

        prop_assert!(
            !effective2.is_suppressed(&rule_id),
            "After reset(), pending next-line suppressions should be cleared"
        );
    }
}

// =============================================================================
// Property 4: SuppressionTracker same-line does NOT persist
// =============================================================================
// Invariant: A same-line suppression applies only to the line with the directive
// Invariant: The suppression does NOT carry over to subsequent lines

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_tracker_same_line_does_not_persist(rule_id in arb_rule_id()) {
        let mut tracker = SuppressionTracker::new();

        // Line 1: same-line directive
        let line1 = format!("// diffguard: ignore {}", rule_id);
        let masked1 = masked_comments(&line1, Language::Rust);
        let effective1 = tracker.process_line(&line1, &masked1);

        // Directive line SHOULD be suppressed
        prop_assert!(
            effective1.is_suppressed(&rule_id),
            "ignore (same-line) should suppress the directive line"
        );

        // Line 2: should NOT be suppressed (same-line does not persist)
        let line2 = "some other code";
        let masked2 = masked_comments(line2, Language::Rust);
        let effective2 = tracker.process_line(line2, &masked2);

        prop_assert!(
            !effective2.is_suppressed(&rule_id),
            "Same-line suppression should NOT persist to subsequent lines"
        );
    }
}

// =============================================================================
// Property 5: Consecutive next-line suppressions accumulate
// =============================================================================
// Invariant: Multiple consecutive ignore-next-line directives accumulate
// Invariant: Each directive suppresses only its own next line (not multiple)

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_tracker_consecutive_next_line_accumulates(
        rule1 in arb_rule_id(),
        rule2 in arb_rule_id(),
    ) {
        prop_assume!(rule1 != rule2);

        let mut tracker = SuppressionTracker::new();

        // Line 1: first ignore-next-line
        let line1 = format!("// diffguard: ignore-next-line {}", rule1);
        let masked1 = masked_comments(&line1, Language::Rust);
        tracker.process_line(&line1, &masked1);

        // Line 2: second ignore-next-line (also has rule1 pending)
        let line2 = format!("// diffguard: ignore-next-line {}", rule2);
        let masked2 = masked_comments(&line2, Language::Rust);
        let effective2 = tracker.process_line(&line2, &masked2);

        // Line 2 should have both rule1 (from line1) and rule2 (from line2)
        prop_assert!(
            effective2.is_suppressed(&rule1),
            "First ignore-next-line should still apply on line 2"
        );
        prop_assert!(
            !effective2.is_suppressed(&rule2),
            "Second ignore-next-line should NOT affect directive line itself"
        );

        // Line 3: should only have rule2 (rule1 was consumed)
        let line3 = "third line";
        let masked3 = masked_comments(line3, Language::Rust);
        let effective3 = tracker.process_line(line3, &masked3);

        prop_assert!(
            !effective3.is_suppressed(&rule1),
            "rule1 should have been consumed on line 2"
        );
        prop_assert!(
            effective3.is_suppressed(&rule2),
            "rule2 from second ignore-next-line should apply on line 3"
        );
    }
}

// =============================================================================
// Property 6: parse_suppression is idempotent (parsing same line twice gives same result)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_parse_suppression_idempotent(line in arb_suppression_line()) {
        let result1 = parse_suppression(&line);
        let result2 = parse_suppression(&line);

        prop_assert_eq!(
            result1, result2,
            "parse_suppression should be idempotent - same line should produce same result"
        );
    }

    #[test]
    fn property_parse_suppression_in_comments_idempotent(line in arb_suppression_line()) {
        let masked = masked_comments(&line, Language::Rust);
        let result1 = parse_suppression_in_comments(&line, &masked);
        let result2 = parse_suppression_in_comments(&line, &masked);

        prop_assert_eq!(
            result1, result2,
            "parse_suppression_in_comments should be idempotent"
        );
    }
}

// =============================================================================
// Property 7: Case insensitivity of directive parsing
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_parse_suppression_case_insensitive(rule_id in arb_rule_id()) {
        let line_lower = format!("// diffguard: ignore {}", rule_id);
        let line_mixed = format!("// DIFFGUARD: IGNORE {}", rule_id);

        let result_lower = parse_suppression(&line_lower);
        let result_mixed = parse_suppression(&line_mixed);

        prop_assert_eq!(
            result_lower, result_mixed,
            "Directive parsing should be case-insensitive"
        );
    }
}

// =============================================================================
// Property 8: parse_suppression_in_comments only matches in comments
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_parse_suppression_in_comments_requires_comment_context(rule_id in arb_rule_id()) {
        // Line with directive in a string literal (not in comment)
        let line = format!(r#"let x = "diffguard: ignore {}";"#, rule_id);
        let masked = masked_comments(&line, Language::Rust);

        // Should not find the directive when it's in a string
        let result = parse_suppression_in_comments(&line, &masked);

        prop_assert!(
            result.is_none(),
            "parse_suppression_in_comments should NOT match directives in string literals"
        );
    }
}

// =============================================================================
// Property 9: Trailing block comment closer is stripped
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_parse_trailing_block_comment_closer_stripped(rule_id in arb_rule_id()) {
        // Directive at end of block comment: /* diffguard: ignore rule_id */
        let line = format!("/* diffguard: ignore {} */", rule_id);

        let result = parse_suppression(&line);

        prop_assert!(
            result.is_some(),
            "Should parse directive with trailing block comment closer"
        );

        let suppression = result.unwrap();
        prop_assert!(
            suppression.suppresses(&rule_id),
            "Rule '{}' should be suppressed despite trailing '*/'", rule_id
        );
    }
}
