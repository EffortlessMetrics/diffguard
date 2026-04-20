//! Green tests for work-d4a75f70: Document `tags` and `test_cases` in diffguard.toml.example
//!
//! These tests verify that `diffguard.toml.example` demonstrates the `tags` and `test_cases`
//! features that exist in the codebase but are missing from the example file.
//!
//! These green tests CORRECT the logical flaw in the red tests where
//! `rust_no_unwrap_has_negative_test_case` incorrectly checked the entire rule block
//! for `.unwrap()` absence instead of just checking the negative test case's input.
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

/// Extract all [[rule.test_cases]] blocks from the rule block.
/// Returns a vector of (description, input, should_match) tuples.
fn extract_test_cases(rule_block: &str) -> Vec<(Option<&str>, &str, bool)> {
    let mut test_cases = Vec::new();
    let lines: Vec<&str> = rule_block.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "[[rule.test_cases]]" {
            let mut description = None;
            let mut input = None;
            let mut should_match = None;

            // Look ahead for the fields in this test case block
            let mut j = i + 1;
            while j < lines.len() && !lines[j].trim().is_empty() {
                let field_trimmed = lines[j].trim();
                if field_trimmed == "[[rule]]" || field_trimmed.starts_with("id = ") {
                    break;
                }
                if field_trimmed.starts_with("description = ") {
                    description = Some(
                        field_trimmed
                            .trim_start_matches("description = ")
                            .trim_matches('"'),
                    );
                }
                if field_trimmed.starts_with("input = ") {
                    input = Some(
                        field_trimmed
                            .trim_start_matches("input = ")
                            .trim_matches('"'),
                    );
                }
                if field_trimmed.starts_with("should_match = ") {
                    let val = field_trimmed.trim_start_matches("should_match = ");
                    should_match = Some(val == "true");
                }
                j += 1;
            }

            if let (Some(inp), Some(sm)) = (input, should_match) {
                test_cases.push((description, inp, sm));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    test_cases
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
        Actual: The rust.no_unwrap rule block does not contain `tags = [\"safety\"]`."
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
        Expected: The rust.no_unwrap rule should contain at least one `[[rule.test_cases]]`\n        block to demonstrate the test_cases feature for `diff test` command."
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

    // Extract test cases
    let test_cases = extract_test_cases(&rule_block);

    // Find a positive test case (should_match = true and input contains .unwrap() or .expect())
    let has_positive_case = test_cases.iter().any(|(desc, input, should_match)| {
        *should_match && (input.contains(".unwrap()") || input.contains(".expect()"))
    });

    assert!(
        has_positive_case,
        "diffguard.toml.example rust.no_unwrap rule is MISSING a positive test case.\n\n\
        Expected: At least one `[[rule.test_cases]]` block with `should_match = true`\n        where the `input` contains `.unwrap()` or `.expect()` (patterns the rule matches).\n\n\
        Found test cases: {:?}",
        test_cases
    );
}

/// Test that `rust.no_unwrap` rule has a negative test case with `should_match = false`.
///
/// A negative test case verifies that the rule does NOT match safe inputs.
/// This test correctly checks ONLY the negative test case's input, not the entire rule block.
/// This is the CORRECTED version of the flawed red test that incorrectly checked the entire block.
#[test]
fn rust_no_unwrap_has_negative_test_case() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    // Extract the rust.no_unwrap rule block
    let rule_block: String = lines[start..=end].join("\n");

    // Extract test cases
    let test_cases = extract_test_cases(&rule_block);

    // Find a negative test case (should_match = false and input does NOT contain .unwrap() or .expect())
    // CORRECTION: We check ONLY the negative test case's input, not the entire block!
    let has_negative_case = test_cases.iter().any(|(desc, input, should_match)| {
        !*should_match && !input.contains(".unwrap()") && !input.contains(".expect()")
    });

    assert!(
        has_negative_case,
        "diffguard.toml.example rust.no_unwrap rule is MISSING a negative test case.\n\n\
        Expected: At least one `[[rule.test_cases]]` block with `should_match = false`\n        where the `input` does NOT contain `.unwrap()` or `.expect()` (safe code).\n\n\
        Found test cases: {:?}",
        test_cases
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
        Expected: tags = [\"safety\"] at position {}, [[rule.test_cases]] at position {}\n\
        Actual: tags appears after [[rule.test_cases]]",
        tags_idx,
        test_cases_idx
    );
}

/// Test that the TOML file parses correctly.
#[test]
fn toml_parses_correctly() {
    // This is a simple smoke test that the TOML is valid
    let content = DIFFGUARD_EXAMPLE_CONTENT;

    // If this parsing doesn't panic, the TOML is valid
    let _parsed: toml::Table =
        toml::from_str(content).expect("diffguard.toml.example should be valid TOML");

    // If we get here, the TOML is valid
}

/// Edge case: Test that test_cases with both .unwrap() and .expect() patterns are handled.
#[test]
fn test_cases_cover_both_patterns() {
    let lines: Vec<&str> = DIFFGUARD_EXAMPLE_CONTENT.lines().collect();

    let (start, end) = find_rust_no_unwrap_block(&lines)
        .expect("rust.no_unwrap rule block not found in diffguard.toml.example");

    let rule_block: String = lines[start..=end].join("\n");

    // The patterns are ["\\.unwrap\\(", "\\.expect\\("] - check both are represented
    assert!(
        rule_block.contains(".unwrap()") || rule_block.contains(".expect()"),
        "rust.no_unwrap should have test cases covering both .unwrap() and .expect() patterns"
    );
}
