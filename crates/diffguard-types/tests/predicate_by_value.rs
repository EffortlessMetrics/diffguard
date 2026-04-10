// Red tests for is_zero/is_false/is_match_mode_any taking small types by value
//
// These tests define the TARGET behavior: the predicate functions should accept
// small types (u32, bool, MatchMode) by VALUE, not by reference.
//
// Current (broken) signatures:
//   fn is_zero(n: &u32) -> bool
//   fn is_false(v: &bool) -> bool
//   fn is_match_mode_any(mode: &MatchMode) -> bool
//
// Target (fixed) signatures:
//   fn is_zero(n: u32) -> bool
//   fn is_false(v: bool) -> bool
//   fn is_match_mode_any(mode: MatchMode) -> bool

use diffguard_types::{MatchMode, RuleConfig, Severity, VerdictCounts};
use serde_json;

fn make_test_rule(match_mode: MatchMode, multiline: bool) -> RuleConfig {
    RuleConfig {
        id: "test-rule".to_string(),
        severity: Severity::Warn,
        message: "test message".to_string(),
        description: String::new(),
        languages: Vec::new(),
        patterns: vec!["pattern".to_string()],
        paths: Vec::new(),
        exclude_paths: Vec::new(),
        ignore_comments: false,
        ignore_strings: false,
        match_mode,
        multiline,
        multiline_window: None,
        context_patterns: Vec::new(),
        context_window: None,
        escalate_patterns: Vec::new(),
        escalate_window: None,
        escalate_to: None,
        depends_on: Vec::new(),
        help: None,
        url: None,
        tags: Vec::new(),
        test_cases: Vec::new(),
    }
}

#[test]
fn test_is_zero_accepts_u32_by_value() {
    // The is_zero function should accept u32 by value, not &u32
    // This tests that skip_serializing_if = "is_zero" works with the by-value signature
    let counts_with_zero = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
        suppressed: 0,
    };

    let json = serde_json::to_string(&counts_with_zero).unwrap();
    // When suppressed is 0, it should be skipped (not serialized)
    assert!(
        !json.contains("suppressed"),
        "suppressed=0 should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_zero_with_nonzero_serializes() {
    // When suppressed is non-zero, it should be serialized
    let counts_with_suppressed = VerdictCounts {
        info: 1,
        warn: 2,
        error: 3,
        suppressed: 5,
    };

    let json = serde_json::to_string(&counts_with_suppressed).unwrap();
    assert!(
        json.contains("suppressed"),
        "suppressed=5 should be serialized: {}",
        json
    );
    assert!(
        json.contains("\"suppressed\":5"),
        "suppressed value should be 5: {}",
        json
    );
}

#[test]
fn test_is_false_accepts_bool_by_value() {
    // The is_false function should accept bool by value, not &bool
    // This tests that skip_serializing_if = "is_false" works with the by-value signature
    let rule = make_test_rule(MatchMode::Any, false);

    let json = serde_json::to_string(&rule).unwrap();
    // When multiline is false, it should be skipped (not serialized)
    assert!(
        !json.contains("multiline"),
        "multiline=false should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_false_with_true_serializes() {
    // When multiline is true, it should be serialized
    let rule = make_test_rule(MatchMode::Absent, true);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        json.contains("multiline"),
        "multiline=true should be serialized: {}",
        json
    );
    assert!(
        json.contains("\"multiline\":true"),
        "multiline value should be true: {}",
        json
    );
}

#[test]
fn test_is_match_mode_any_accepts_match_mode_by_value() {
    // The is_match_mode_any function should accept MatchMode by value, not &MatchMode
    // This tests that skip_serializing_if = "is_match_mode_any" works with the by-value signature
    let rule = make_test_rule(MatchMode::Any, false);

    let json = serde_json::to_string(&rule).unwrap();
    // When match_mode is Any (default), it should be skipped (not serialized)
    assert!(
        !json.contains("match_mode"),
        "match_mode=Any should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_match_mode_any_with_absent_serializes() {
    // When match_mode is Absent, it should be serialized
    let rule = make_test_rule(MatchMode::Absent, false);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        json.contains("match_mode"),
        "match_mode=Absent should be serialized: {}",
        json
    );
    assert!(
        json.contains("\"match_mode\":\"absent\""),
        "match_mode value should be absent: {}",
        json
    );
}

#[test]
fn test_skip_serializing_if_combined_default_values() {
    // Test that all default values are properly skipped
    let rule = make_test_rule(MatchMode::Any, false);

    let json = serde_json::to_string(&rule).unwrap();
    // Neither should appear when they have default values
    assert!(
        !json.contains("match_mode"),
        "match_mode=Any should not be serialized: {}",
        json
    );
    assert!(
        !json.contains("multiline"),
        "multiline=false should not be serialized: {}",
        json
    );
}

#[test]
fn test_skip_serializing_if_round_trip() {
    // Ensure serialization/deserialization round-trip works correctly
    let original = make_test_rule(MatchMode::Absent, true);

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RuleConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.match_mode, MatchMode::Absent);
    assert_eq!(deserialized.multiline, true);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_is_zero_u32_max() {
    // u32::MAX should be serialized (not skipped)
    let counts = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
        suppressed: u32::MAX,
    };

    let json = serde_json::to_string(&counts).unwrap();
    assert!(
        json.contains("suppressed"),
        "suppressed=u32::MAX should be serialized: {}",
        json
    );
    assert!(
        json.contains(&format!("\"suppressed\":{}", u32::MAX)),
        "suppressed value should be u32::MAX: {}",
        json
    );
}

#[test]
fn test_is_zero_u32_min() {
    // u32::MIN (0) should be skipped
    let counts = VerdictCounts {
        info: u32::MIN,
        warn: u32::MIN,
        error: u32::MIN,
        suppressed: u32::MIN,
    };

    let json = serde_json::to_string(&counts).unwrap();
    // suppressed=0 should not be serialized
    assert!(
        !json.contains("suppressed"),
        "suppressed=0 (u32::MIN) should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_zero_boundary_values() {
    // Test serialization at boundary between skip and include (1)
    let counts_one = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
        suppressed: 1,
    };
    let json_one = serde_json::to_string(&counts_one).unwrap();
    assert!(
        json_one.contains("suppressed"),
        "suppressed=1 should be serialized: {}",
        json_one
    );

    // Test that 0 is skipped
    let counts_zero = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
        suppressed: 0,
    };
    let json_zero = serde_json::to_string(&counts_zero).unwrap();
    assert!(
        !json_zero.contains("suppressed"),
        "suppressed=0 should not be serialized: {}",
        json_zero
    );
}

#[test]
fn test_is_match_mode_any_with_any_variant() {
    // MatchMode::Any should be skipped (default)
    let rule = make_test_rule(MatchMode::Any, false);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        !json.contains("match_mode"),
        "match_mode=Any should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_match_mode_any_with_absent_variant() {
    // MatchMode::Absent should be serialized
    let rule = make_test_rule(MatchMode::Absent, false);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        json.contains("match_mode"),
        "match_mode=Absent should be serialized: {}",
        json
    );
    assert!(
        json.contains("\"match_mode\":\"absent\""),
        "match_mode value should be absent: {}",
        json
    );
}

#[test]
fn test_is_false_with_false_value() {
    // multiline=false should be skipped
    let rule = make_test_rule(MatchMode::Absent, false);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        !json.contains("multiline"),
        "multiline=false should not be serialized: {}",
        json
    );
}

#[test]
fn test_is_false_with_true_value() {
    // multiline=true should be serialized
    let rule = make_test_rule(MatchMode::Absent, true);

    let json = serde_json::to_string(&rule).unwrap();
    assert!(
        json.contains("multiline"),
        "multiline=true should be serialized: {}",
        json
    );
    assert!(
        json.contains("\"multiline\":true"),
        "multiline value should be true: {}",
        json
    );
}

#[test]
fn test_all_predicates_combined_edge_cases() {
    // Combine all edge cases: MatchMode::Any (skip), multiline=false (skip), suppressed=0 (skip)
    let rule_all_skipped = make_test_rule(MatchMode::Any, false);
    let counts_all_zero = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
        suppressed: 0,
    };

    let json_rule = serde_json::to_string(&rule_all_skipped).unwrap();
    let json_counts = serde_json::to_string(&counts_all_zero).unwrap();

    // All defaults - nothing serialized
    assert!(
        !json_rule.contains("match_mode"),
        "match_mode=Any should be skipped"
    );
    assert!(
        !json_rule.contains("multiline"),
        "multiline=false should be skipped"
    );
    assert!(
        !json_counts.contains("suppressed"),
        "suppressed=0 should be skipped"
    );

    // Combine rule with non-defaults and counts with non-zero
    let rule_with_values = RuleConfig {
        id: "edge-case-test".to_string(),
        severity: Severity::Warn,
        message: "edge case message".to_string(),
        description: String::new(),
        languages: Vec::new(),
        patterns: vec!["pattern".to_string()],
        paths: Vec::new(),
        exclude_paths: Vec::new(),
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::Absent, // Will serialize
        multiline: true,               // Will serialize
        multiline_window: None,
        context_patterns: Vec::new(),
        context_window: None,
        escalate_patterns: Vec::new(),
        escalate_window: None,
        escalate_to: None,
        depends_on: Vec::new(),
        help: None,
        url: None,
        tags: Vec::new(),
        test_cases: Vec::new(),
    };

    let counts_edge = VerdictCounts {
        info: u32::MAX,
        warn: u32::MIN,
        error: 1,
        suppressed: u32::MAX,
    };

    let json_rule_edge = serde_json::to_string(&rule_with_values).unwrap();
    let json_counts_edge = serde_json::to_string(&counts_edge).unwrap();

    // All non-defaults - everything serialized
    assert!(
        json_rule_edge.contains("match_mode"),
        "match_mode=Absent should be serialized"
    );
    assert!(
        json_rule_edge.contains("multiline"),
        "multiline=true should be serialized"
    );
    assert!(
        json_counts_edge.contains("suppressed"),
        "suppressed=u32::MAX should be serialized"
    );
    assert!(
        json_counts_edge.contains("\"suppressed\":4294967295"),
        "suppressed value should be u32::MAX: {}",
        json_counts_edge
    );
}

#[test]
fn test_round_trip_with_edge_case_values() {
    // Test round-trip with edge case values
    let original = RuleConfig {
        id: "round-trip-test".to_string(),
        severity: Severity::Error,
        message: "test".to_string(),
        description: String::new(),
        languages: Vec::new(),
        patterns: vec!["p1".to_string(), "p2".to_string()],
        paths: Vec::new(),
        exclude_paths: Vec::new(),
        ignore_comments: true,
        ignore_strings: true,
        match_mode: MatchMode::Absent,
        multiline: true,
        multiline_window: None,
        context_patterns: Vec::new(),
        context_window: None,
        escalate_patterns: Vec::new(),
        escalate_window: None,
        escalate_to: None,
        depends_on: Vec::new(),
        help: None,
        url: None,
        tags: Vec::new(),
        test_cases: Vec::new(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RuleConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.match_mode, MatchMode::Absent);
    assert_eq!(deserialized.multiline, true);
    assert_eq!(deserialized.ignore_comments, true);
    assert_eq!(deserialized.ignore_strings, true);
}

#[test]
fn test_is_zero_does_not_affect_other_u32_fields() {
    // VerdictCounts has multiple u32 fields - is_zero only affects suppressed
    let counts = VerdictCounts {
        info: u32::MAX,
        warn: u32::MIN,
        error: 1,
        suppressed: 0, // Only suppressed=0 should be skipped
    };

    let json = serde_json::to_string(&counts).unwrap();

    // Other u32 fields should always serialize
    assert!(
        json.contains("info"),
        "info should always be serialized: {}",
        json
    );
    assert!(
        json.contains("warn"),
        "warn should always be serialized: {}",
        json
    );
    assert!(
        json.contains("error"),
        "error should always be serialized: {}",
        json
    );

    // Only suppressed should be skipped when 0
    assert!(
        !json.contains("suppressed"),
        "suppressed=0 should not be serialized: {}",
        json
    );

    // Verify the values
    assert!(
        json.contains(&format!("\"info\":{}", u32::MAX)),
        "info should be u32::MAX: {}",
        json
    );
    assert!(json.contains("\"warn\":0"), "warn should be 0: {}", json);
    assert!(json.contains("\"error\":1"), "error should be 1: {}", json);
}
