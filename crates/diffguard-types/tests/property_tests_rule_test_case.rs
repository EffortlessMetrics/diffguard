//! Property-based tests for RuleTestCase serialization round-trip.
//!
//! These tests verify the invariants for `RuleTestCase` with special focus on
//! the `ignore_comments` and `ignore_strings` fields (lines 398 and 402 in lib.rs).
//!
//! Feature: work-2fb801c2/property-test, Property tests for RuleTestCase

use diffguard_types::RuleTestCase;
use proptest::prelude::*;

// ============================================================================
// Proptest Strategies for generating random RuleTestCase instances
// ============================================================================

/// Strategy for generating non-empty strings for RuleTestCase::input
fn arb_input_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.,!?\\-\\s]{1,100}".prop_map(|s| s)
}

/// Strategy for generating optional strings (for language, description)
fn arb_optional_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("rust".to_string())),
        Just(Some("python".to_string())),
        Just(Some("javascript".to_string())),
        "[a-zA-Z0-9_]{1,50}".prop_map(Some),
    ]
}

/// Strategy for generating valid RuleTestCase instances with varied optional fields.
fn arb_rule_test_case() -> impl Strategy<Value = RuleTestCase> {
    (
        arb_input_string(),              // input: String (required, non-empty)
        any::<bool>(),                   // should_match: bool
        prop::option::of(any::<bool>()), // ignore_comments: Option<bool>
        prop::option::of(any::<bool>()), // ignore_strings: Option<bool>
        arb_optional_string(),           // language: Option<String>
        arb_optional_string(),           // description: Option<String>
    )
        .prop_map(
            |(input, should_match, ignore_comments, ignore_strings, language, description)| {
                RuleTestCase {
                    input,
                    should_match,
                    ignore_comments,
                    ignore_strings,
                    language,
                    description,
                }
            },
        )
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 1: RuleTestCase JSON Round-Trip Serialization
    ///
    /// For any valid RuleTestCase instance, serializing to JSON and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// This verifies that the `ignore_comments` and `ignore_strings` fields
    /// (documented in lines 398 and 402) work correctly with serialization.
    #[test]
    fn rule_test_case_json_round_trip(case in arb_rule_test_case()) {
        // Serialize the RuleTestCase to JSON
        let json_string = serde_json::to_string(&case)
            .expect("RuleTestCase should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: RuleTestCase = serde_json::from_str(&json_string)
            .expect("RuleTestCase should deserialize from JSON");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            case, deserialized,
            "RuleTestCase JSON round-trip should produce equivalent value"
        );
    }

    /// Property 2: ignore_comments Field Round-Trip
    ///
    /// Setting `ignore_comments` to Some(true) or Some(false) in a RuleTestCase
    /// SHALL survive JSON round-trip serialization.
    #[test]
    fn rule_test_case_ignore_comments_round_trip(ignore_comments in prop::option::of(any::<bool>())) {
        let case = RuleTestCase {
            input: "test input".to_string(),
            should_match: true,
            ignore_comments,
            ignore_strings: None,
            language: None,
            description: None,
        };

        // Serialize to JSON and back
        let json_string = serde_json::to_string(&case).expect("should serialize");
        let deserialized: RuleTestCase = serde_json::from_str(&json_string).expect("should deserialize");

        prop_assert_eq!(
            case, deserialized,
            "ignore_comments should survive round-trip"
        );
    }

    /// Property 3: ignore_strings Field Round-Trip
    ///
    /// Setting `ignore_strings` to Some(true) or Some(false) in a RuleTestCase
    /// SHALL survive JSON round-trip serialization.
    #[test]
    fn rule_test_case_ignore_strings_round_trip(ignore_strings in prop::option::of(any::<bool>())) {
        let case = RuleTestCase {
            input: "test input".to_string(),
            should_match: true,
            ignore_comments: None,
            ignore_strings,
            language: None,
            description: None,
        };

        // Serialize to JSON and back
        let json_string = serde_json::to_string(&case).expect("should serialize");
        let deserialized: RuleTestCase = serde_json::from_str(&json_string).expect("should deserialize");

        prop_assert_eq!(
            case, deserialized,
            "ignore_strings should survive round-trip"
        );
    }

    /// Property 4: Combined ignore_comments + ignore_strings Round-Trip
    ///
    /// When both `ignore_comments` and `ignore_strings` are set, both values
    /// SHALL survive JSON round-trip serialization.
    #[test]
    fn rule_test_case_both_flags_round_trip(
        ignore_comments in prop::option::of(any::<bool>()),
        ignore_strings in prop::option::of(any::<bool>())
    ) {
        let case = RuleTestCase {
            input: "test input".to_string(),
            should_match: true,
            ignore_comments,
            ignore_strings,
            language: None,
            description: None,
        };

        // Serialize to JSON and back
        let json_string = serde_json::to_string(&case).expect("should serialize");
        let deserialized: RuleTestCase = serde_json::from_str(&json_string).expect("should deserialize");

        prop_assert_eq!(
            case, deserialized,
            "Both ignore_comments and ignore_strings should survive round-trip"
        );
    }

    /// Property 5: Optional Fields Skipped When None (Serialization Invariant)
    ///
    /// When `ignore_comments` or `ignore_strings` is None, the serialized JSON
    /// SHALL NOT contain those keys.
    #[test]
    fn rule_test_case_skips_none_optional_fields(
        ignore_comments in prop::option::of(any::<bool>()),
        ignore_strings in prop::option::of(any::<bool>())
    ) {
        let case = RuleTestCase {
            input: "test input".to_string(),
            should_match: true,
            ignore_comments,
            ignore_strings,
            language: None,
            description: None,
        };

        // Serialize to JSON value (not string)
        let json_value = serde_json::to_value(&case).expect("should serialize to value");

        // If ignore_comments is None, the key should not be present
        if case.ignore_comments.is_none() {
            prop_assert!(
                !json_value.as_object()
                    .map(|obj| obj.contains_key("ignore_comments"))
                    .unwrap_or(false),
                "ignore_comments should be skipped when None"
            );
        }

        // If ignore_strings is None, the key should not be present
        if case.ignore_strings.is_none() {
            prop_assert!(
                !json_value.as_object()
                    .map(|obj| obj.contains_key("ignore_strings"))
                    .unwrap_or(false),
                "ignore_strings should be skipped when None"
            );
        }
    }
}
