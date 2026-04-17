//! Property-based/invariant tests for diffguard.toml.example configuration.
//!
//! These tests verify invariants about the example configuration file.
//! For documentation-only changes, we test that:
//! 1. The TOML file parses correctly
//! 2. The rust.no_unwrap rule has valid tags including "safety"
//! 3. Positive test case inputs actually match the rule patterns
//! 4. Negative test case inputs don't match the rule patterns
//! 5. All patterns in the rule are valid regex
//!
//! These are property tests because they verify invariants that should hold
//! for any valid example file, not just specific test cases.

use regex::Regex;
use std::fs;
use std::path::Path;

/// Parse the diffguard.toml.example file and return its TOML structure
fn parse_example_config() -> toml::Table {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("diffguard.toml.example");
    let contents = fs::read_to_string(&config_path).expect("diffguard.toml.example should exist");
    contents
        .parse::<toml::Table>()
        .expect("diffguard.toml.example should be valid TOML")
}

/// Find the rust.no_unwrap rule in the parsed config
fn find_rust_no_unwrap_rule(config: &toml::Table) -> Option<&toml::Table> {
    config.get("rule").and_then(|rules| {
        if let toml::Value::Array(rules) = rules {
            for rule in rules {
                if let toml::Value::Table(rule_table) = rule {
                    if rule_table.get("id").and_then(|v| v.as_str()) == Some("rust.no_unwrap") {
                        return Some(rule_table);
                    }
                }
            }
        }
        None
    })
}

/// Extract regex patterns from a rule's patterns array
fn extract_patterns(rule: &toml::Table) -> Vec<String> {
    rule.get("patterns")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract tags from a rule
fn extract_tags(rule: &toml::Table) -> Vec<String> {
    rule.get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract test_cases from a rule
fn extract_test_cases(rule: &toml::Table) -> Vec<(String, bool)> {
    rule.get("test_cases")
        .and_then(|tc| tc.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|tc| {
                    if let toml::Value::Table(tc_table) = tc {
                        let input = tc_table.get("input")?.as_str()?.to_string();
                        let should_match = tc_table.get("should_match")?.as_bool()?;
                        Some((input, should_match))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

// ============================================================================
// Property 1: TOML Validity
// Invariant: The example file must always parse as valid TOML
// ============================================================================

#[test]
fn property_toml_parses_validly() {
    let config = parse_example_config();
    assert!(!config.is_empty(), "Parsed config should not be empty");
}

// ============================================================================
// Property 2: Tags are valid non-empty strings
// Invariant: Any tags defined must be non-empty strings
// ============================================================================

#[test]
fn property_tags_are_non_empty_strings() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let tags = extract_tags(rule);

    for tag in &tags {
        assert!(!tag.is_empty(), "Tags must be non-empty strings");
    }
}

// ============================================================================
// Property 3: rust.no_unwrap should have "safety" tag
// Invariant: Consistent with built-in rules, rust.no_unwrap should have 'safety' tag
// ============================================================================

#[test]
fn property_tags_contains_safety() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let tags = extract_tags(rule);

    assert!(
        tags.contains(&"safety".to_string()),
        "rust.no_unwrap should have 'safety' tag, got: {:?}",
        tags
    );
}

// ============================================================================
// Property 4: Both positive and negative test cases exist
// Invariant: The rust.no_unwrap rule should have both positive and negative test cases
// ============================================================================

#[test]
fn property_has_both_positive_and_negative_test_cases() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let test_cases = extract_test_cases(rule);

    let has_positive = test_cases.iter().any(|(_, should_match)| *should_match);
    let has_negative = test_cases.iter().any(|(_, should_match)| !*should_match);

    assert!(
        has_positive,
        "Should have at least one positive (should_match=true) test case"
    );
    assert!(
        has_negative,
        "Should have at least one negative (should_match=false) test case"
    );
}

// ============================================================================
// Property 5: Positive test case matches patterns
// Invariant: Every positive test case input must match at least one rule pattern
// ============================================================================

#[test]
fn property_positive_test_case_matches_patterns() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let patterns = extract_patterns(rule);
    let test_cases = extract_test_cases(rule);

    let positive_cases: Vec<_> = test_cases
        .iter()
        .filter(|(_, should_match)| *should_match)
        .collect();

    assert!(
        !positive_cases.is_empty(),
        "Should have at least one positive test case"
    );

    for (input, should_match) in positive_cases {
        let matches_any = patterns.iter().any(|pattern| {
            Regex::new(pattern)
                .map(|re| re.is_match(input))
                .unwrap_or(false)
        });

        assert!(
            matches_any,
            "Positive test case '{}' should match at least one pattern, but patterns {:?} didn't match",
            input, patterns
        );

        // Double-check: if it matches, should_match should be true
        assert!(
            *should_match,
            "If input matches pattern, should_match should be true"
        );
    }
}

// ============================================================================
// Property 6: Negative test case does NOT match patterns
// Invariant: Every negative test case input must NOT match any rule pattern
// ============================================================================

#[test]
fn property_negative_test_case_does_not_match_patterns() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let patterns = extract_patterns(rule);
    let test_cases = extract_test_cases(rule);

    let negative_cases: Vec<_> = test_cases
        .iter()
        .filter(|(_, should_match)| !*should_match)
        .collect();

    assert!(
        !negative_cases.is_empty(),
        "Should have at least one negative test case"
    );

    for (input, should_match) in negative_cases {
        let matches_any = patterns.iter().any(|pattern| {
            Regex::new(pattern)
                .map(|re| re.is_match(input))
                .unwrap_or(false)
        });

        assert!(
            !matches_any,
            "Negative test case '{}' should NOT match any pattern, but it matched patterns {:?}",
            input, patterns
        );

        // Double-check: if it doesn't match, should_match should be false
        assert!(
            !*should_match,
            "If input doesn't match pattern, should_match should be false"
        );
    }
}

// ============================================================================
// Property 7: Test cases have valid structure
// Invariant: All test cases must have non-empty input
// ============================================================================

#[test]
fn property_test_cases_have_valid_structure() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let test_cases = extract_test_cases(rule);

    assert!(!test_cases.is_empty(), "Should have at least one test case");

    for (input, _) in &test_cases {
        assert!(!input.is_empty(), "Test case input must be non-empty");
    }
}

// ============================================================================
// Property 8: Patterns are valid regex
// Invariant: All patterns in the rust.no_unwrap rule must be valid regex
// ============================================================================

#[test]
fn property_patterns_are_valid_regex() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let patterns = extract_patterns(rule);

    for pattern in &patterns {
        let result = Regex::new(pattern);
        assert!(
            result.is_ok(),
            "Pattern '{}' should be valid regex, got error: {:?}",
            pattern,
            result.err()
        );
    }
}

// ============================================================================
// Property 9: Test inputs use unambiguous code
// Invariant: Positive test case should use unambiguous unwrap/expect code
//            Negative test case should NOT contain .unwrap() or .expect()
// ============================================================================

#[test]
fn property_test_input_uses_unambiguous_code() {
    let config = parse_example_config();
    let rule = find_rust_no_unwrap_rule(&config).expect("rule must exist");
    let test_cases = extract_test_cases(rule);

    // Positive case should contain .unwrap() or .expect()
    let positive_cases: Vec<_> = test_cases
        .iter()
        .filter(|(_, should_match)| *should_match)
        .collect();

    for (input, _) in positive_cases {
        let contains_unwrap_or_expect = input.contains(".unwrap()") || input.contains(".expect(");
        assert!(
            contains_unwrap_or_expect,
            "Positive test case should contain '.unwrap()' or '.expect(', got: '{}'",
            input
        );
    }

    // Negative case should NOT contain .unwrap() or .expect()
    let negative_cases: Vec<_> = test_cases
        .iter()
        .filter(|(_, should_match)| !*should_match)
        .collect();

    for (input, _) in negative_cases {
        let contains_unwrap_or_expect = input.contains(".unwrap()") || input.contains(".expect(");
        assert!(
            !contains_unwrap_or_expect,
            "Negative test case should NOT contain '.unwrap()' or '.expect(', got: '{}'",
            input
        );
    }
}
