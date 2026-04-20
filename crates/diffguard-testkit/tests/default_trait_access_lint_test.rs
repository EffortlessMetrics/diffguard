//! Tests verifying that diffguard-testkit passes the default_trait_access clippy lint.
//!
//! These tests ensure that all `Default::default()` calls on MatchMode are replaced
//! with the more explicit `MatchMode::default()` form.
//!
//! See issue #561 for context.

use std::process::Command;

/// Test that diffguard-testkit compiles without default_trait_access lint warnings.
///
/// This test will FAIL if `Default::default()` is used instead of `MatchMode::default()`
/// for MatchMode fields. The fix requires:
/// 1. Adding `MatchMode` to imports in both fixtures.rs and arb.rs
/// 2. Replacing all 12 occurrences of `match_mode: Default::default()` with
///    `match_mode: MatchMode::default()`
#[test]
fn test_no_default_trait_access_warnings() {
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-testkit",
            "--",
            "-W",
            "clippy::default_trait_access",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Count warnings related to default_trait_access
    // The warning message is: "calling `MatchMode::default()` is more clear than this expression"
    let warning_count = stderr
        .lines()
        .filter(|line| {
            line.contains("warning:")
                && (line.contains("MatchMode::default()") || line.contains("default_trait_access"))
        })
        .count();

    assert_eq!(
        warning_count, 0,
        "Expected 0 default_trait_access warnings but found {}.\n\
         To fix, replace `Default::default()` with `MatchMode::default()` in:\n\
         - fixtures.rs (10 occurrences)\n\
         - arb.rs (2 occurrences)\n\
         \n\
         Clippy output:\n{}\n{}",
        warning_count, stdout, stderr
    );
}

/// Test that fixtures.rs uses explicit MatchMode::default() instead of Default::default().
///
/// Verifies that the MatchMode import is present and all match_mode fields use the
/// explicit form.
#[test]
fn test_fixtures_uses_explicit_match_mode_default() {
    let fixtures_path = "/home/hermes/repos/diffguard/crates/diffguard-testkit/src/fixtures.rs";
    let content = std::fs::read_to_string(fixtures_path).expect("fixtures.rs should be readable");

    // Verify MatchMode is imported
    assert!(
        content.contains("MatchMode"),
        "fixtures.rs should import MatchMode from diffguard_types"
    );

    // Verify no unqualified Default::default() for match_mode
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("match_mode:") && line.contains("Default::default()") {
            panic!(
                "fixtures.rs line {} uses unqualified Default::default() for match_mode.\n\
                 Expected: match_mode: MatchMode::default()\n\
                 Found: {}",
                i + 1,
                line.trim()
            );
        }
    }
}

/// Test that arb.rs uses explicit MatchMode::default() instead of Default::default().
///
/// Verifies that the MatchMode import is present and all match_mode fields use the
/// explicit form.
#[test]
fn test_arb_uses_explicit_match_mode_default() {
    let arb_path = "/home/hermes/repos/diffguard/crates/diffguard-testkit/src/arb.rs";
    let content = std::fs::read_to_string(arb_path).expect("arb.rs should be readable");

    // Verify MatchMode is imported
    assert!(
        content.contains("MatchMode"),
        "arb.rs should import MatchMode from diffguard_types"
    );

    // Verify no unqualified Default::default() for match_mode
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("match_mode:") && line.contains("Default::default()") {
            panic!(
                "arb.rs line {} uses unqualified Default::default() for match_mode.\n\
                 Expected: match_mode: MatchMode::default()\n\
                 Found: {}",
                i + 1,
                line.trim()
            );
        }
    }
}

/// Test that all 12 match_mode occurrences in fixtures.rs use MatchMode::default().
///
/// There should be exactly 10 occurrences in fixtures.rs (as documented in issue #561).
#[test]
fn test_fixtures_has_correct_match_mode_count() {
    let fixtures_path = "/home/hermes/repos/diffguard/crates/diffguard-testkit/src/fixtures.rs";
    let content = std::fs::read_to_string(fixtures_path).expect("fixtures.rs should be readable");

    let match_mode_count = content
        .match_indices("match_mode: MatchMode::default()")
        .count();

    assert_eq!(
        match_mode_count, 10,
        "fixtures.rs should have exactly 10 match_mode: MatchMode::default() occurrences.\n\
         Found: {}\n\
         This represents all RuleConfig instances using the default MatchMode.",
        match_mode_count
    );
}

/// Test that all 2 match_mode occurrences in arb.rs use MatchMode::default().
///
/// There should be exactly 2 occurrences in arb.rs (as documented in issue #561).
#[test]
fn test_arb_has_correct_match_mode_count() {
    let arb_path = "/home/hermes/repos/diffguard/crates/diffguard-testkit/src/arb.rs";
    let content = std::fs::read_to_string(arb_path).expect("arb.rs should be readable");

    let match_mode_count = content
        .match_indices("match_mode: MatchMode::default()")
        .count();

    assert_eq!(
        match_mode_count, 2,
        "arb.rs should have exactly 2 match_mode: MatchMode::default() occurrences.\n\
         Found: {}\n\
         This represents arb_rule_config() and arb_minimal_rule_config() strategies.",
        match_mode_count
    );
}
