//! Tests for clippy truncation warning suppression at main.rs:646
//!
//! These tests verify:
//! 1. The `cast_possible_truncation` warning for the `i32 → u8` cast at main.rs:646 is suppressed
//! 2. The SAFETY comment documents the clamp invariant
//!
//! These tests FAIL before the fix is applied and PASS after.

use std::path::Path;
use std::process::Command;

/// Test that the clippy truncation warning at main.rs:646 is suppressed.
///
/// Before fix: This test FAILS because the warning is present.
/// After fix: This test PASSES because the `#[allow(clippy::cast_possible_truncation)]`
///           attribute suppresses the warning.
#[test]
fn test_clippy_truncation_warning_suppressed_at_main_rs_646() {
    let _manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard",
            "--",
            "-W",
            "clippy::cast_possible_truncation",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .output()
        .expect("Failed to execute cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    // The warning should NOT contain a reference to main.rs:646 for the i32->u8 cast
    // If the fix is applied correctly, the #[allow] attribute will suppress this warning.
    let has_line_646_warning = combined.contains("main.rs:646")
        && combined.contains("i32")
        && combined.contains("u8")
        && combined.contains("may truncate");

    assert!(
        !has_line_646_warning,
        "Expected clippy truncation warning at main.rs:646 to be SUPPRESSED, but it was PRESENT.\n\
         The #[allow(clippy::cast_possible_truncation)] attribute should suppress this warning.\n\
         Clippy output:\n{}",
        combined
    );
}

/// Test that the SAFETY comment is present directly above the `as u8` cast at main.rs:646.
///
/// Before fix: This test FAILS because the SAFETY comment is absent.
/// After fix: This test PASSES because the comment documents the clamp invariant.
#[test]
fn test_safety_comment_present_above_cast() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let content = std::fs::read_to_string(&main_rs_path).expect("Failed to read main.rs");

    let lines: Vec<&str> = content.lines().collect();

    // Find line 646 (0-indexed: 645)
    // The fix adds the SAFETY comment directly above the std::process::ExitCode::from line
    let target_line_idx = 645; // 0-indexed

    if target_line_idx >= lines.len() {
        panic!("main.rs has fewer than 646 lines");
    }

    let target_line = lines[target_line_idx];

    // Verify the target line is the ExitCode::from expression with as u8
    assert!(
        target_line.contains("std::process::ExitCode::from"),
        "Line 646 should be the ExitCode::from expression"
    );
    assert!(
        target_line.contains("as u8"),
        "Line 646 should contain 'as u8' cast"
    );

    // Check if line 645 (0-indexed) contains the SAFETY comment
    // and line 644 contains the #[allow] attribute
    let safety_comment_idx = target_line_idx.saturating_sub(1);
    let allow_attr_idx = target_line_idx.saturating_sub(2);

    let has_safety_comment = safety_comment_idx < lines.len()
        && lines[safety_comment_idx].contains("SAFETY")
        && lines[safety_comment_idx].contains("clamp")
        && lines[safety_comment_idx].contains("[0, 255]");

    let has_allow_attr = allow_attr_idx < lines.len()
        && lines[allow_attr_idx].contains("#[allow(clippy::cast_possible_truncation)]");

    assert!(
        has_safety_comment && has_allow_attr,
        "Expected SAFETY comment and #[allow] attribute above line 646.\n\
         Found SAFETY comment: {}, Found #[allow]: {}\n\
         Line 644 (if exists): {:?}\n\
         Line 645 (if exists): {:?}\n\
         Line 646: {:?}",
        has_safety_comment,
        has_allow_attr,
        lines.get(644).map(|s| s.to_string()),
        lines.get(645).map(|s| s.to_string()),
        Some(target_line.to_string())
    );
}
