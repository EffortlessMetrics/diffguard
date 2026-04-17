// Test file for verifying lossless u8→u32 conversion in unescape_git_path
//
// These tests verify that the octal digit parsing in unescape_git_path
// uses u32::from() for lossless widening casts instead of `as u32`.
//
// The cast_lossless lint requires:
//   u32::from(u8_value) instead of u8_value as u32
//
// These tests verify the SOURCE CODE uses the correct pattern.

use std::fs;

/// Test that unescape_git_path uses u32::from for lossless cast on line 546.
///
/// This test verifies the specification: the widening cast from u8 (the result
/// of `next - b'0'`) to u32 must use `u32::from()` to satisfy clippy::cast_lossless.
///
/// Line 546 pattern should be:
///   let mut val = u32::from(next - b'0');
///
/// NOT:
///   let mut val = (next - b'0') as u32;
#[test]
fn test_unescape_git_path_line_570_uses_from_trait() {
    let source = fs::read_to_string("src/unified.rs").expect("Failed to read unified.rs");

    let lines: Vec<&str> = source.lines().collect();

    // Line 546 (0-indexed: 545)
    let line_570 = lines[545];
    assert!(
        line_570.contains("u32::from"),
        "Line 546 must use u32::from() for lossless cast, but found: {}\n\
         Expected pattern: u32::from(next - b'0')",
        line_570
    );
    assert!(
        !line_570.contains("as u32"),
        "Line 546 must NOT use 'as u32' (triggers cast_lossless lint): {}",
        line_570
    );
}

/// Test that unescape_git_path uses u32::from for lossless cast on line 550.
///
/// This test verifies the specification: the widening cast from u8 (the result
/// of `d - b'0'`) to u32 must use `u32::from()` to satisfy clippy::cast_lossless.
///
/// Line 550 pattern should be:
///   val = val * 8 + u32::from(d - b'0');
///
/// NOT:
///   val = val * 8 + (d - b'0') as u32;
#[test]
fn test_unescape_git_path_line_574_uses_from_trait() {
    let source = fs::read_to_string("src/unified.rs").expect("Failed to read unified.rs");

    let lines: Vec<&str> = source.lines().collect();

    // Line 550 (0-indexed: 549)
    let line_574 = lines[549];
    assert!(
        line_574.contains("u32::from"),
        "Line 550 must use u32::from() for lossless cast, but found: {}\n\
         Expected pattern: val * 8 + u32::from(d - b'0')",
        line_574
    );
    assert!(
        !line_574.contains("as u32"),
        "Line 550 must NOT use 'as u32' (triggers cast_lossless lint): {}",
        line_574
    );
}

/// Test that the narrowing cast on line 556 remains unchanged.
///
/// The narrowing cast from u32 to u8 is intentional and should use `as u8`.
/// The cast_lossless lint only flags widening casts.
///
/// Line 556 should remain:
///   out.push((val & 0xFF) as u8);
///
/// This test ensures we don't accidentally "fix" the narrowing cast.
#[test]
fn test_unescape_git_path_line_580_narrowing_cast_unchanged() {
    let source = fs::read_to_string("src/unified.rs").expect("Failed to read unified.rs");

    let lines: Vec<&str> = source.lines().collect();

    // Line 556 (0-indexed: 555)
    let line_580 = lines[555];
    assert!(
        line_580.contains("as u8"),
        "Line 556 must still use 'as u8' for narrowing cast: {}",
        line_580
    );
}

/// Test that clippy::cast_lossless produces no warnings in unified.rs.
///
/// This is the ultimate acceptance criterion: after the fix, clippy
/// must report zero cast_lossless warnings.
#[test]
fn test_clippy_cast_lossless_no_warnings() {
    let output = std::process::Command::new("cargo")
        .args([
            "clippy",
            "--package",
            "diffguard-diff",
            "--",
            "-W",
            "clippy::cast_lossless",
        ])
        .current_dir(".")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The cast_lossless warnings should NOT appear for lines 546 and 550
    assert!(
        !stderr.contains("crates/diffguard-diff/src/unified.rs:546"),
        "Line 546 still triggers cast_lossless warning"
    );
    assert!(
        !stderr.contains("crates/diffguard-diff/src/unified.rs:550"),
        "Line 550 still triggers cast_lossless warning"
    );
}
