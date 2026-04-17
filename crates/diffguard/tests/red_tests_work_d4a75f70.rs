//! Red tests for work-d4a75f70: Document `tags` and `test_cases` in diffguard.toml.example
//!
//! These tests verify that `diffguard.toml.example` demonstrates the `tags` and `test_cases`
//! features that exist in the codebase but are missing from the example file.
//!
//! **Before fix**: `diffguard.toml.example` is missing:
//!   - `tags = ["safety"]` on `rust.no_unwrap` rule
//!   - `[[rule.test_cases]]` blocks on `rust.no_unwrap` rule
//!
//! **After fix**: `diffguard.toml.example` should contain:
//!   - `rust.no_unwrap` rule with `tags = ["safety"]` (consistent with built_in.json line 30)
//!   - `rust.no_unwrap` rule with at least one positive test case (should_match = true)
//!   - `rust.no_unwrap` rule with at least one negative test case (should_match = false)
//!
//! The path to diffguard.toml.example is computed at compile time using CARGO_MANIFEST_DIR.
//! For tests in crates/diffguard/tests/, CARGO_MANIFEST_DIR = crates/diffguard
//! We need to go up 2 levels to reach the repo root: crates/diffguard -> crates -> repo root

/// The content of diffguard.toml.example embedded at compile time.
const DIFFGUARD_EXAMPLE_CONTENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../diffguard.toml.example"
));

/// Find the bounds of the `rust.no_unwrap` rule block in the TOML.
/// Returns the start and end line indices (0-based).
fn find_rust_no_unwrap_block(lines: &[&str]) -> Option<(usize, usize)> {
    let mut rule_start: Option<usize> = None;
    let mut in_rust_no_unwrap = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Check for end of rust.no_unwrap block BEFORE we process new [[rule]]
        if in_rust_no_unwrap && trimmed == "[[rule]]" {
            return Some((rule_start.unwrap(), i - 1));
        }

        // Start of a new rule block
        if trimmed == "[[rule]]" {
            rule_start = Some(i);
            in_rust_no_unwrap = false;
        } else if let Some(_start) = rule_start {
            // Check if this is the rust.no_unwrap rule
            if trimmed.starts_with("id = ") && trimmed.contains("rust.no_unwrap") {
                in_rust_no_unwrap = true;
            }
        }
    }

    if in_rust_no_unwrap {
        rule_start.map(|s| (s, lines.len() - 1))
    } else {
        None
    }
}

/// Test that `rust.no_unwrap` rule has `tags = ["safety"]` field.
///
/// This verifies that users can discover the `tags` feature from the example file.
/// The value should match built_in.json which uses `tags: ["safety"]` for this rule.
#[test]
fn rust_no_unwrap_rule_has_tags_safety() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    // Extract the rust.no_unwrap rule block
    let rule_block: String = lines[start..=end].join("\n");

    // Check for tags field with "safety" value
    assert!(
        rule_block.contains("tags = [\"safety\"]"),
        "diffguard.toml.example rust.no_unwrap rule is MISSING `tags = [\"safety\"]`.\n\n\
        Expected: The rust.no_unwrap rule block should contain `tags = [\"safety\"]`\n        to demonstrate the tags feature and be consistent with built_in.json (line 30).\n\n\
        Actual: The rust.no_unwrap rule block does not contain `tags = [\"safety\"]`.\n\n\
        The fix: Add `tags = [\"safety\"]` after the existing fields in the rust.no_unwrap rule,\n        after line 51 (ignore_strings = true).\n\n\
        Rule block found at lines {} to {}:\n        ```\n        {}\n        ```",
        start + 1, // 1-indexed for user display
        end + 1,
        rule_block
    );
}

/// Test that `rust.no_unwrap` rule has at least one `[[rule.test_cases]]` block.
///
/// This verifies that users can discover the `test_cases` feature from the example file.
/// The `[[rule.test_cases]]` syntax is TOML's array of tables notation for appending
/// elements to an array.
#[test]
fn rust_no_unwrap_rule_has_test_cases_blocks() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    // Extract the rust.no_unwrap rule block
    let rule_block: String = lines[start..=end].join("\n");

    // Check for [[rule.test_cases]] syntax (TOML array of tables)
    assert!(
        rule_block.contains("[[rule.test_cases]]"),
        "diffguard.toml.example rust.no_unwrap rule is MISSING `[[rule.test_cases]]` blocks.\n\n\
        Expected: The rust.no_unwrap rule should contain at least one `[[rule.test_cases]]`\n        block to demonstrate the test_cases feature for `diff test` command.\n\n\
        Actual: The rust.no_unwrap rule block does not contain `[[rule.test_cases]]`.\n\n\
        The fix: Add `[[rule.test_cases]]` blocks after `tags` within the rust.no_unwrap rule block.\n        Each block should have `input` and `should_match` fields.\n\n\
        Rule block found at lines {} to {}:\n        ```\n        {}\n        ```",
        start + 1,
        end + 1,
        rule_block
    );
}

/// Test that `rust.no_unwrap` rule has a positive test case with `should_match = true`.
///
/// A positive test case verifies that the rule matches inputs that should be flagged.
/// The example input should contain `.unwrap()` or `.expect()` which are the patterns
/// that rust.no_unwrap detects.
#[test]
fn rust_no_unwrap_has_positive_test_case() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    // Extract the rust.no_unwrap rule block
    let rule_block: String = lines[start..=end].join("\n");

    // Look for [[rule.test_cases]] blocks and check for should_match = true
    // A positive test case should contain `.unwrap()` or `.expect()` in the input
    // (which the rule is designed to catch)
    let has_positive_case = rule_block.contains("[[rule.test_cases]]")
        && rule_block.contains("should_match = true")
        && (rule_block.contains(".unwrap()") || rule_block.contains(".expect()"));

    assert!(
        has_positive_case,
        "diffguard.toml.example rust.no_unwrap rule is MISSING a positive test case.\n\n\
        Expected: At least one `[[rule.test_cases]]` block with `should_match = true`\n        where the `input` contains `.unwrap()` or `.expect()` (patterns the rule matches).\n\n\
        Actual: No positive test case found with matching input and should_match = true.\n\n\
        The fix: Add a test case block like:\n        ```toml\n        [[rule.test_cases]]\n        input = \"let x = y.unwrap();\"\n        should_match = true\n        description = \"unwrap() call should be flagged\"\n        ```\n\n\
        Rule block found at lines {} to {}:\n        ```\n        {}\n        ```",
        start + 1,
        end + 1,
        rule_block
    );
}

/// Test that `rust.no_unwrap` rule has a negative test case with `should_match = false`.
///
/// A negative test case verifies that the rule does NOT match safe inputs.
/// The example input should NOT contain `.unwrap()` or `.expect()`.
#[test]
fn rust_no_unwrap_has_negative_test_case() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    // Extract the rust.no_unwrap rule block
    let rule_block: String = lines[start..=end].join("\n");

    // Look for [[rule.test_cases]] blocks and check for should_match = false
    // A negative test case should use safe code without .unwrap() or .expect()
    let has_negative_case = rule_block.contains("[[rule.test_cases]]")
        && rule_block.contains("should_match = false")
        && !rule_block.contains(".unwrap()")
        && !rule_block.contains(".expect()");

    assert!(
        has_negative_case,
        "diffguard.toml.example rust.no_unwrap rule is MISSING a negative test case.\n\n\
        Expected: At least one `[[rule.test_cases]]` block with `should_match = false`\n        where the `input` does NOT contain `.unwrap()` or `.expect()` (safe code).\n\n\
        Actual: No negative test case found with should_match = false and safe input.\n\n\
        The fix: Add a test case block like:\n        ```toml\n        [[rule.test_cases]]\n        input = \"let x = y.ok();\"\n        should_match = false\n        description = \"ok() is safe and should not be flagged\"\n        ```\n\n\
        Rule block found at lines {} to {}:\n        ```\n        {}\n        ```",
        start + 1,
        end + 1,
        rule_block
    );
}

/// Test that tags appears before [[rule.test_cases]] in the rust.no_unwrap rule.
///
/// Per the acceptance criteria, `tags` should appear after existing fields and
/// `[[rule.test_cases]]` blocks should appear after `tags`.
#[test]
fn tags_appears_before_test_cases_in_rust_no_unwrap() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    let rule_block: String = lines[start..=end].join("\n");

    let tags_pos = rule_block.find("tags = [\"safety\"]");
    let test_cases_pos = rule_block.find("[[rule.test_cases]]");

    if tags_pos.is_none() {
        panic!(
            "tags = [\"safety\"] not found in rust.no_unwrap rule block.\n\
            This test requires tags to be present before checking ordering."
        );
    }

    if test_cases_pos.is_none() {
        panic!(
            "[[rule.test_cases]] not found in rust.no_unwrap rule block.\n\
            This test requires test_cases to be present before checking ordering."
        );
    }

    let tags_idx = tags_pos.unwrap();
    let test_cases_idx = test_cases_pos.unwrap();

    assert!(
        tags_idx < test_cases_idx,
        "tags should appear BEFORE [[rule.test_cases]] in the rust.no_unwrap rule.\n\n\
        Expected: tags = [\"safety\"] at position {}, [[rule.test_cases]] at position {}\n        \
        Actual: tags appears after [[rule.test_cases]]\n\n\
        The fix: Ensure `tags = [\"safety\"]` appears after existing fields\n        (after line 51: ignore_strings = true) and BEFORE any [[rule.test_cases]] blocks.\n\n\
        Rule block found at lines {} to {}:\n        ```\n        {}\n        ```",
        tags_idx,
        test_cases_idx,
        start + 1,
        end + 1,
        rule_block
    );
}
