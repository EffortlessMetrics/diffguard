//! Integration tests for suppression module component handoffs.
//!
//! These tests verify that the `#[must_use]` attribute on `Suppression::suppresses()`
//! doesn't break component handoffs through the suppression system.
//!
//! Component handoffs tested:
//! 1. Preprocessor → SuppressionTracker (masked_comments flow)
//! 2. SuppressionTracker → EffectiveSuppressions (processing result)
//! 3. EffectiveSuppressions → is_suppressed() check (suppression lookup)
//! 4. Suppression::suppresses() return value consumption (#[must_use] verification)

use diffguard_domain::{
    Language, PreprocessOptions, Preprocessor,
    suppression::{
        SuppressionKind, SuppressionTracker, parse_suppression, parse_suppression_in_comments,
    },
};

/// Helper: get masked comments for a line in a given language.
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

/// Test: Suppression::suppresses() return value is properly consumed.
/// Verifies that #[must_use] doesn't cause issues when the return value is used.
#[test]
fn test_suppresses_must_use_return_value_is_used() {
    let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let suppression = parse_suppression(line).expect("should parse");

    // Explicitly use the return value in a conditional
    // This verifies #[must_use] doesn't cause problems when return is consumed
    let suppressed = suppression.suppresses("rust.no_unwrap");
    assert!(suppressed, "rust.no_unwrap should be suppressed");

    // Also verify non-matching rule
    let not_suppressed = suppression.suppresses("other.rule");
    assert!(!not_suppressed, "other.rule should NOT be suppressed");
}

/// Test: EffectiveSuppressions handoff with Suppression::suppresses()
/// Verifies the flow from EffectiveSuppressions through to is_suppressed().
#[test]
fn test_effective_suppressions_handoff_with_suppresses() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Line with suppression directive
    let line = "// diffguard: ignore rule1, rule2";
    let masked = masked_comments(line, lang);

    // Process through tracker to get EffectiveSuppressions (uses public API)
    let effective = tracker.process_line(line, &masked);

    // Verify is_suppressed correctly delegates to Suppression::suppresses()
    assert!(
        effective.is_suppressed("rule1"),
        "rule1 should be suppressed via EffectiveSuppressions"
    );
    assert!(
        effective.is_suppressed("rule2"),
        "rule2 should be suppressed via EffectiveSuppressions"
    );
    assert!(
        !effective.is_suppressed("rule3"),
        "rule3 should NOT be suppressed"
    );
}

/// Test: SuppressionTracker.process_line() with #[must_use] on suppresses()
/// Verifies the full handoff: raw line → tracker → effective suppressions.
#[test]
fn test_suppression_tracker_process_line_handoff() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Line with suppression directive
    let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let masked = masked_comments(line, lang);

    // Process the line through tracker
    let effective = tracker.process_line(line, &masked);

    // Verify the suppression was correctly parsed and applied
    assert!(
        effective.is_suppressed("rust.no_unwrap"),
        "rust.no_unwrap should be suppressed via tracker"
    );
    assert!(
        !effective.is_suppressed("other.rule"),
        "other.rule should NOT be suppressed"
    );
}

/// Test: ignore-next-line directive flow with #[must_use]
/// Verifies pending suppressions work correctly across lines.
#[test]
fn test_suppression_tracker_next_line_directive_flow() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Line with ignore-next-line directive
    let directive_line = "// diffguard: ignore-next-line rust.no_unwrap";
    let directive_masked = masked_comments(directive_line, lang);

    // Process directive line - suppression should be pending for next line
    let effective1 = tracker.process_line(directive_line, &directive_masked);
    assert!(
        effective1.is_empty(),
        "directive line itself should have no suppressions"
    );

    // Line that should be suppressed by the pending directive
    let target_line = "let x = y.unwrap();";
    let target_masked = masked_comments(target_line, lang);

    // Process target line - should now be suppressed
    let effective2 = tracker.process_line(target_line, &target_masked);
    assert!(
        effective2.is_suppressed("rust.no_unwrap"),
        "target line should be suppressed by pending ignore-next-line"
    );
}

/// Test: Multiple suppression directives on consecutive lines.
/// Verifies the tracker correctly handles overlapping suppressions.
#[test]
fn test_suppression_tracker_multiple_consecutive_directives() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Line 1: ignore rust.no_unwrap
    let line1 = "let a = x.unwrap(); // diffguard: ignore rust.no_unwrap";
    let masked1 = masked_comments(line1, lang);
    let eff1 = tracker.process_line(line1, &masked1);
    assert!(eff1.is_suppressed("rust.no_unwrap"));

    // Line 2: ignore-next-line rust.no_unwrap
    let line2 = "// diffguard: ignore-next-line rust.no_unwrap";
    let masked2 = masked_comments(line2, lang);
    let eff2 = tracker.process_line(line2, &masked2);
    assert!(!eff2.is_suppressed("rust.no_unwrap")); // directive line

    // Line 3: should be suppressed by line 2's pending directive
    let line3 = "let b = y.unwrap();";
    let masked3 = masked_comments(line3, lang);
    let eff3 = tracker.process_line(line3, &masked3);
    assert!(eff3.is_suppressed("rust.no_unwrap"));

    // Line 4: no directive, but line 2's pending directive should be consumed
    let line4 = "let c = z.unwrap();";
    let masked4 = masked_comments(line4, lang);
    let eff4 = tracker.process_line(line4, &masked4);
    assert!(
        !eff4.is_suppressed("rust.no_unwrap"),
        "pending directive should be consumed"
    );
}

/// Test: Wildcard suppression with #[must_use] on suppresses()
/// Verifies wildcard suppressions work correctly.
#[test]
fn test_wildcard_suppression_with_must_use() {
    let line = "// diffguard: ignore *";
    let suppression = parse_suppression(line).expect("should parse wildcard");

    // Wildcard should suppress ANY rule
    assert!(
        suppression.suppresses("any.rule"),
        "wildcard should suppress any.rule"
    );
    assert!(
        suppression.suppresses("another.rule"),
        "wildcard should suppress another.rule"
    );
    assert!(
        suppression.suppresses(""),
        "wildcard should suppress empty string rule"
    );
}

/// Test: parse_suppression_in_comments correctly filters by comment context.
/// This is the key integration point between Preprocessor and SuppressionTracker.
#[test]
fn test_parse_suppression_in_comments_filters_by_context() {
    let lang = Language::Rust;

    // Directive in a comment - should be detected
    let in_comment = "let x = 1; // diffguard: ignore rust.no_unwrap";
    let masked_in_comment = masked_comments(in_comment, lang);
    let suppression = parse_suppression_in_comments(in_comment, &masked_in_comment);
    assert!(
        suppression.is_some(),
        "directive in comment should be detected"
    );

    // Directive in a string - should NOT be detected (preprocessor masks strings)
    let in_string = r#"let x = "diffguard: ignore rust.no_unwrap";"#;
    let masked_in_string = masked_comments(in_string, lang);
    let suppression_in_string = parse_suppression_in_comments(in_string, &masked_in_string);
    assert!(
        suppression_in_string.is_none(),
        "directive in string should NOT be detected"
    );
}

/// Test: Case-insensitive directive parsing with #[must_use]
/// Verifies that case variations work correctly.
#[test]
fn test_case_insensitive_directive_with_suppresses() {
    // Various case permutations of "diffguard: ignore"
    let cases = vec![
        "// diffguard: ignore rule1",
        "// DIFFGUARD: IGNORE rule1",
        "// DiffGuard: Ignore rule1",
        "// DiFfGuArD: IgNoRe rule1",
    ];

    for line in cases {
        let suppression =
            parse_suppression(line).unwrap_or_else(|| panic!("should parse: {}", line));
        // The #[must_use] return value should be consumed correctly
        let suppressed = suppression.suppresses("rule1");
        assert!(
            suppressed,
            "case-insensitive directive should suppress rule1: {}",
            line
        );
        let not_suppressed = suppression.suppresses("rule2");
        assert!(
            !not_suppressed,
            "case-insensitive directive should NOT suppress rule2: {}",
            line
        );
    }
}

/// Test: SuppressionKind variants with #[must_use]
/// Verifies both SameLine and NextLine suppressions work.
#[test]
fn test_suppression_kind_variants() {
    // SameLine suppression
    let same_line = "// diffguard: ignore rust.no_unwrap";
    let suppression = parse_suppression(same_line).expect("should parse");
    assert_eq!(
        suppression.kind,
        SuppressionKind::SameLine,
        "should be SameLine suppression"
    );
    assert!(suppression.suppresses("rust.no_unwrap"));

    // NextLine suppression
    let next_line = "// diffguard: ignore-next-line rust.no_unwrap";
    let suppression = parse_suppression(next_line).expect("should parse");
    assert_eq!(
        suppression.kind,
        SuppressionKind::NextLine,
        "should be NextLine suppression"
    );
    assert!(suppression.suppresses("rust.no_unwrap"));
}

/// Test: EffectiveSuppressions::is_empty() returns correct value.
/// Verifies the empty/non-empty state machine works correctly.
#[test]
fn test_effective_suppressions_is_empty() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Line without directive
    let no_directive = "let x = y.unwrap();";
    let masked = masked_comments(no_directive, lang);
    let eff = tracker.process_line(no_directive, &masked);
    assert!(
        eff.is_empty(),
        "line without directive should have empty suppressions"
    );

    // Line with directive
    let with_directive = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let masked_directive = masked_comments(with_directive, lang);
    let eff_directive = tracker.process_line(with_directive, &masked_directive);
    assert!(
        !eff_directive.is_empty(),
        "line with directive should NOT have empty suppressions"
    );
}

/// Test: SuppressionTracker::reset() clears pending state.
/// Verifies reset works correctly after ignore-next-line directives.
#[test]
fn test_suppression_tracker_reset_clears_pending() {
    let lang = Language::Rust;
    let mut tracker = SuppressionTracker::new();

    // Set up pending ignore-next-line
    let directive = "// diffguard: ignore-next-line rust.no_unwrap";
    let masked = masked_comments(directive, lang);
    tracker.process_line(directive, &masked);

    // Reset should clear pending
    tracker.reset();

    // After reset, next line should NOT be suppressed
    let target = "let x = y.unwrap();";
    let masked_target = masked_comments(target, lang);
    let eff = tracker.process_line(target, &masked_target);
    assert!(
        !eff.is_suppressed("rust.no_unwrap"),
        "after reset, pending directive should be cleared"
    );
}
