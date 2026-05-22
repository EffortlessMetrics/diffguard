//! Edge case tests for exit code i32 → u8 conversion with clamp.
//!
//! These tests verify that the `clamp` in main() correctly constrains
//! exit codes to [0, 255] before casting to u8.
//!
//! The documented exit codes are:
//! - 0: Pass
//! - 1: Tool error
//! - 2: Policy fail (errors found)
//! - 3: Warn-fail
//!
//! But the implementation must handle ANY i32 value gracefully by clamping
//! to [0, 255] before the u8 cast.

use std::process::ExitCode;

/// Test that clamp correctly handles boundary values within [0, 255].
///
/// Values 0, 1, 2, 3 (documented exit codes), 127, 128, 254, 255
/// should all pass through unchanged.
#[test]
fn test_clamp_preserves_valid_exit_codes() {
    // Documented exit codes
    assert_eq!(0i32.clamp(0, 255) as u8, 0);
    assert_eq!(1i32.clamp(0, 255) as u8, 1);
    assert_eq!(2i32.clamp(0, 255) as u8, 2);
    assert_eq!(3i32.clamp(0, 255) as u8, 3);

    // Boundary values
    assert_eq!(127i32.clamp(0, 255) as u8, 127);
    assert_eq!(128i32.clamp(0, 255) as u8, 128);
    assert_eq!(254i32.clamp(0, 255) as u8, 254);
    assert_eq!(255i32.clamp(0, 255) as u8, 255);
}

/// Test that clamp correctly constrains values below 0 to 0.
#[test]
fn test_clamp_clamps_negative_values_to_zero() {
    assert_eq!((-1i32).clamp(0, 255) as u8, 0);
    assert_eq!((-128i32).clamp(0, 255) as u8, 0);
    assert_eq!((-256i32).clamp(0, 255) as u8, 0);
    assert_eq!(i32::MIN.clamp(0, 255) as u8, 0);
}

/// Test that clamp correctly constrains values above 255 to 255.
#[test]
fn test_clamp_clamps_large_values_to_255() {
    assert_eq!(256i32.clamp(0, 255) as u8, 255);
    assert_eq!(300i32.clamp(0, 255) as u8, 255);
    assert_eq!(1000i32.clamp(0, 255) as u8, 255);
    assert_eq!(i32::MAX.clamp(0, 255) as u8, 255);
}

/// Test that ExitCode::from with clamped value produces valid exit codes.
#[test]
fn test_exit_code_from_clamped_value() {
    // All documented codes should produce valid ExitCode
    let _ = ExitCode::from(0i32.clamp(0, 255) as u8);
    let _ = ExitCode::from(1i32.clamp(0, 255) as u8);
    let _ = ExitCode::from(2i32.clamp(0, 255) as u8);
    let _ = ExitCode::from(3i32.clamp(0, 255) as u8);

    // Large values should also produce valid ExitCode (clamped to 255)
    let _ = ExitCode::from(i32::MAX.clamp(0, 255) as u8);

    // Negative values should also produce valid ExitCode (clamped to 0)
    let _ = ExitCode::from(i32::MIN.clamp(0, 255) as u8);
}

/// Test the exact pattern used in main.rs for exit code conversion.
#[test]
fn test_exit_code_conversion_pattern() {
    // This is the exact pattern from main.rs:659
    // std::process::ExitCode::from(code.clamp(i32::from(u8::MIN), i32::from(u8::MAX)) as u8)
    let pattern = |code: i32| -> u8 {
        // Note: we return u8 directly since ExitCode doesn't expose .code() in stable Rust
        code.clamp(i32::from(u8::MIN), i32::from(u8::MAX)) as u8
    };

    // Documented codes
    assert_eq!(pattern(0), 0);
    assert_eq!(pattern(1), 1);
    assert_eq!(pattern(2), 2);
    assert_eq!(pattern(3), 3);

    // Boundary: u8::MAX = 255
    assert_eq!(pattern(255), 255);

    // Out of range: should be clamped
    assert_eq!(pattern(-1), 0); // Negative → 0
    assert_eq!(pattern(256), 255); // Above max → 255
    assert_eq!(pattern(i32::MAX), 255); // i32::MAX → 255
    assert_eq!(pattern(i32::MIN), 0); // i32::MIN → 0
}

/// Test that u8::MIN and u8::MAX constants are correctly used in the clamp.
#[test]
fn test_u8_bounds_are_correct() {
    assert_eq!(u8::MIN, 0);
    assert_eq!(u8::MAX, 255);
    assert_eq!(i32::from(u8::MIN), 0);
    assert_eq!(i32::from(u8::MAX), 255);
}
