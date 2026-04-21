//! Green tests for work-95f4074b: Edge cases for `is_wildcard()` method
//!
//! These tests stress the `is_wildcard()` method with edge cases that the
//! red tests don't cover:
//! - Empty parts in comma-separated rule lists
//! - Trailing whitespace after wildcard
//! - Block comment closer after directive
//! - Multiple wildcards in list
//! - Mixed whitespace variations
//!
//! The fix adds `#[must_use]` to `is_wildcard()`, but the method's behavior
//! is determined by `parse_rule_ids()` - these tests verify that edge cases
//! in parsing correctly set `rule_ids` which `is_wildcard()` then reflects.

use diffguard_domain::suppression::parse_suppression;

/// Edge case: Empty parts in comma-separated list are skipped.
///
/// `// diffguard: ignore rule1, , rule2` should have rule1 and rule2 only.
/// `is_wildcard()` should return false because there are specific rules.
#[test]
fn is_wildcard_false_for_list_with_empty_parts() {
    let line = "// diffguard: ignore rule1, , rule2";
    let suppression = parse_suppression(line).expect("should parse suppression with empty part");

    // Empty parts are skipped, so we have specific rules
    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false for list with empty parts (has specific rules)"
    );
    assert!(suppression.suppresses("rule1"), "Should suppress rule1");
    assert!(suppression.suppresses("rule2"), "Should suppress rule2");
    assert!(
        !suppression.suppresses("rule3"),
        "Should NOT suppress rule3"
    );
}

/// Edge case: Trailing whitespace after wildcard.
///
/// `// diffguard: ignore *   ` (trailing spaces) should still be wildcard.
#[test]
fn is_wildcard_true_for_wildcard_with_trailing_whitespace() {
    let line = "// diffguard: ignore *   ";
    let suppression = parse_suppression(line).expect("should parse wildcard with trailing spaces");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true even with trailing whitespace after '*'"
    );
    assert!(
        suppression.suppresses("any.rule"),
        "Wildcard should suppress any rule"
    );
}

/// Edge case: Multiple wildcards in comma-separated list.
///
/// `// diffguard: ignore *, *` should be treated as wildcard (any * means wildcard).
#[test]
fn is_wildcard_true_for_multiple_wildcards_in_list() {
    let line = "// diffguard: ignore *, *";
    let suppression = parse_suppression(line).expect("should parse multiple wildcards");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true when '*' appears anywhere in the list"
    );
}

/// Edge case: Wildcard at end of list with other rules.
///
/// `// diffguard: ignore rule1, rule2, *` should be wildcard.
#[test]
fn is_wildcard_true_for_wildcard_at_end_of_list() {
    let line = "// diffguard: ignore rule1, rule2, *";
    let suppression = parse_suppression(line).expect("should parse wildcard at end");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true when '*' appears at end of list"
    );
}

/// Edge case: Wildcard at start of list.
///
/// `// diffguard: ignore *, rule1, rule2` should be wildcard.
#[test]
fn is_wildcard_true_for_wildcard_at_start_of_list() {
    let line = "// diffguard: ignore *, rule1, rule2";
    let suppression = parse_suppression(line).expect("should parse wildcard at start");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true when '*' appears at start of list"
    );
}

/// Edge case: Wildcard mixed with rules in middle.
///
/// `// diffguard: ignore rule1, *, rule2` should be wildcard.
#[test]
fn is_wildcard_true_for_wildcard_in_middle_of_list() {
    let line = "// diffguard: ignore rule1, *, rule2";
    let suppression = parse_suppression(line).expect("should parse wildcard in middle");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true when '*' appears in middle of list"
    );
}

/// Edge case: Block comment closer stripped correctly.
///
/// `// diffguard: ignore */` - the trailing */ should be stripped and empty means wildcard.
#[test]
fn is_wildcard_true_for_empty_after_block_comment_strip() {
    let line = "/* diffguard: ignore */";
    let suppression = parse_suppression(line).expect("should parse block comment directive");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true when directive is followed by block comment closer"
    );
}

/// Edge case: Single rule with surrounding whitespace.
///
/// `// diffguard: ignore   rust.no_unwrap   ` should NOT be wildcard.
#[test]
fn is_wildcard_false_for_single_rule_with_surrounding_whitespace() {
    let line = "// diffguard: ignore   rust.no_unwrap   ";
    let suppression =
        parse_suppression(line).expect("should parse rule with surrounding whitespace");

    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false for specific rule with surrounding whitespace"
    );
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress the rule"
    );
}

/// Edge case: ignore-next-line with wildcard is still wildcard.
///
/// Even though the kind is NextLine, is_wildcard() should return true for wildcard.
#[test]
fn is_wildcard_true_for_ignore_next_line_wildcard() {
    let line = "// diffguard: ignore-next-line *";
    let suppression = parse_suppression(line).expect("should parse ignore-next-line with wildcard");

    // kind is NextLine, but rule_ids is None -> is_wildcard is true
    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true even for ignore-next-line (kind doesn't affect rule_ids)"
    );
}

/// Edge case: ignore-next-line without wildcard is NOT wildcard.
#[test]
fn is_wildcard_false_for_ignore_next_line_specific_rule() {
    let line = "// diffguard: ignore-next-line rust.no_dbg";
    let suppression = parse_suppression(line).expect("should parse ignore-next-line with rule");

    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false for ignore-next-line with specific rule"
    );
}

/// Edge case: ignore-all explicitly is wildcard.
#[test]
fn is_wildcard_true_for_ignore_all() {
    let line = "// diffguard: ignore-all";
    let suppression = parse_suppression(line).expect("should parse ignore-all");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true for ignore-all"
    );
}

/// Edge case: Bare ignore is wildcard (no rules specified).
#[test]
fn is_wildcard_true_for_bare_ignore() {
    let line = "// diffguard: ignore";
    let suppression = parse_suppression(line).expect("should parse bare ignore");

    assert!(
        suppression.is_wildcard(),
        "is_wildcard() should be true for bare ignore (empty means all)"
    );
}

/// Edge case: Multiple spaces between directive and rules.
///
/// `// diffguard: ignore    rule1, rule2` should work correctly.
#[test]
fn is_wildcard_false_for_multiple_spaces_before_rules() {
    let line = "// diffguard: ignore    rule1, rule2";
    let suppression = parse_suppression(line).expect("should parse with multiple spaces");

    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false when rules are specified with extra spaces"
    );
    assert!(suppression.suppresses("rule1"), "Should suppress rule1");
    assert!(suppression.suppresses("rule2"), "Should suppress rule2");
}

/// Edge case: Only whitespace between comma and rule.
///
/// `// diffguard: ignore rule1,    rule2` should work correctly.
#[test]
fn is_wildcard_false_for_extra_whitespace_between_rules() {
    let line = "// diffguard: ignore rule1,    rule2";
    let suppression =
        parse_suppression(line).expect("should parse with extra whitespace between rules");

    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false with extra whitespace between rules"
    );
    assert!(suppression.suppresses("rule1"), "Should suppress rule1");
    assert!(suppression.suppresses("rule2"), "Should suppress rule2");
}

/// Edge case: Rule ID with special characters (dots, underscores).
#[test]
fn is_wildcard_false_for_rule_id_with_special_chars() {
    let line = "// diffguard: ignore rust.no_unwrap, python.no_print, go.no_error_check";
    let suppression =
        parse_suppression(line).expect("should parse rules with dots and underscores");

    assert!(
        !suppression.is_wildcard(),
        "is_wildcard() should be false for specific rules"
    );
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress rust.no_unwrap"
    );
    assert!(
        suppression.suppresses("python.no_print"),
        "Should suppress python.no_print"
    );
    assert!(
        suppression.suppresses("go.no_error_check"),
        "Should suppress go.no_error_check"
    );
    assert!(
        !suppression.suppresses("other.rule"),
        "Should NOT suppress other.rule"
    );
}
