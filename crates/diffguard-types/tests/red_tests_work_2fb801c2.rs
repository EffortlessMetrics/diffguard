//! Red tests for work-2fb801c2: Backtick-quoted identifiers in doc comments
//!
//! These tests verify that the doc comments on `RuleTestCase::ignore_comments`
//! and `RuleTestCase::ignore_strings` use backtick-quoted inline code identifiers,
//! per Rust doc comment convention.
//!
//! **Before fix**:
//! - Line 398: `/// Optional: override ignore_comments for this test case.` (BARE identifier)
//! - Line 402: `/// Optional: override ignore_strings for this test case.` (BARE identifier)
//!
//! **After fix**:
//! - Line 398: `/// Optional: override \`ignore_comments\` for this test case.` (backtick-quoted)
//! - Line 402: `/// Optional: override \`ignore_strings\` for this test case.` (backtick-quoted)

/// Test that line 398 has backtick-quoted `ignore_comments` in its doc comment.
///
/// Rust doc convention requires inline code identifiers to be wrapped in backticks.
/// This test verifies the doc comment above `pub ignore_comments: Option<bool>`
/// follows this convention.
///
/// **Before fix**: Line 398 reads `/// Optional: override ignore_comments for this test case.`
/// **After fix**: Line 398 reads `/// Optional: override \`ignore_comments\` for this test case.`
///
/// This test will FAIL before the fix (bare identifier) and PASS after code-builder
/// adds backticks around `ignore_comments`.
#[test]
fn rule_test_case_ignore_comments_doc_uses_backtick_quoted_identifier() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Get line 398 (1-indexed, so we subtract 1)
    let lines: Vec<&str> = source.lines().collect();
    let line_398 = lines
        .get(397) // 0-indexed
        .expect("Line 398 not found in source");

    // The line should contain backtick-quoted `ignore_comments`
    // i.e., the literal string "`ignore_comments`"
    assert!(
        line_398.contains("`ignore_comments`"),
        "Line 398 doc comment should contain backtick-quoted `ignore_comments`.\n\
         Expected: `/// Optional: override `ignore_comments` for this test case.`\n\
         Actual:   `{}`\n\
         \n\
         The fix: Wrap `ignore_comments` in backticks on line 398 to follow Rust doc convention.",
        line_398
    );

    // Also verify it does NOT have the bare identifier
    // A bare identifier would be "ignore_comments" NOT preceded by a backtick
    // This is a bit tricky, but we check that if "ignore_comments" appears,
    // it must be within backticks
    let bare_pattern = "override ignore_comments ";
    assert!(
        !line_398.contains(bare_pattern),
        "Line 398 doc comment contains bare identifier `ignore_comments` (not backtick-quoted).\n\
         Expected: `/// Optional: override `ignore_comments` for this test case.`\n\
         Actual:   `{}`\n\
         \n\
         The fix: Replace `{}` with `/// Optional: override `ignore_comments` for this test case.`",
        line_398,
        line_398
    );
}

/// Test that line 402 has backtick-quoted `ignore_strings` in its doc comment.
///
/// Rust doc convention requires inline code identifiers to be wrapped in backticks.
/// This test verifies the doc comment above `pub ignore_strings: Option<bool>`
/// follows this convention.
///
/// **Before fix**: Line 402 reads `/// Optional: override ignore_strings for this test case.`
/// **After fix**: Line 402 reads `/// Optional: override \`ignore_strings\` for this test case.`
///
/// This test will FAIL before the fix (bare identifier) and PASS after code-builder
/// adds backticks around `ignore_strings`.
#[test]
fn rule_test_case_ignore_strings_doc_uses_backtick_quoted_identifier() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Get line 402 (1-indexed, so we subtract 1)
    let lines: Vec<&str> = source.lines().collect();
    let line_402 = lines
        .get(401) // 0-indexed
        .expect("Line 402 not found in source");

    // The line should contain backtick-quoted `ignore_strings`
    // i.e., the literal string "`ignore_strings`"
    assert!(
        line_402.contains("`ignore_strings`"),
        "Line 402 doc comment should contain backtick-quoted `ignore_strings`.\n\
         Expected: `/// Optional: override `ignore_strings` for this test case.`\n\
         Actual:   `{}`\n\
         \n\
         The fix: Wrap `ignore_strings` in backticks on line 402 to follow Rust doc convention.",
        line_402
    );

    // Also verify it does NOT have the bare identifier
    let bare_pattern = "override ignore_strings ";
    assert!(
        !line_402.contains(bare_pattern),
        "Line 402 doc comment contains bare identifier `ignore_strings` (not backtick-quoted).\n\
         Expected: `/// Optional: override `ignore_strings` for this test case.`\n\
         Actual:   `{}`\n\
         \n\
         The fix: Replace `{}` with `/// Optional: override `ignore_strings` for this test case.`",
        line_402,
        line_402
    );
}

/// Test that `cargo doc -p diffguard-types --no-deps` would succeed after the fix.
///
/// This is a documentation-only change, but we verify the crate still builds
/// correctly after the doc comment changes.
#[test]
fn crate_doc_builds_successfully() {
    use std::process::Command;

    // Run `cargo doc -p diffguard-types --no-deps` and check exit code
    let result = Command::new("cargo")
        .args(["doc", "-p", "diffguard-types", "--no-deps", "--quiet"])
        .current_dir("/home/hermes/repos/diffguard")
        .output();

    match result {
        Ok(output) if output.status.success() => {
            // Success - documentation builds
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "cargo doc failed with exit code {:?}\n\
                 STDOUT:\n{}\n\
                 STDERR:\n{}",
                output.status.code(),
                stdout,
                stderr
            );
        }
        Err(e) => {
            panic!(
                "Failed to run cargo doc: {}\n\
                 Make sure cargo is available in PATH.",
                e
            );
        }
    }
}
