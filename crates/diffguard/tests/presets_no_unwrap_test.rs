//! Red test: Verify presets.rs test functions use `.expect()` not `.unwrap()`
//!
//! This test ensures the `rust.no_unwrap` rule is not self-defeating.
//! The test functions in presets.rs should use `.expect()` with descriptive
//! error messages, not `.unwrap()`.
//!
//! These tests FAIL now (red) and will PASS after code-builder replaces
//! unwrap() with expect() calls.

use std::fs;

/// Test that rust-quality preset test uses `.expect()` not `.unwrap()`
///
/// This verifies the `rust.no_unwrap` rule is not self-defeating.
#[test]
fn test_rust_quality_preset_test_uses_expect_not_unwrap() {
    let source = fs::read_to_string("src/presets.rs")
        .expect("presets.rs source file should exist");

    // Find the test function for rust-quality preset
    let test_fn_start = source
        .find("fn test_rust_quality_preset_generates_valid_toml()")
        .expect("test_rust_quality_preset_generates_valid_toml function should exist");

    // Extract a chunk of the function (up to 20 lines)
    let test_chunk = &source[test_fn_start..test_fn_start + 1500];

    // The function should use .expect() with a descriptive message
    // not .unwrap() which provides no context on failure
    assert!(
        test_chunk.contains(r#"result.expect("rust-quality preset should parse as valid TOML")"#),
        "test_rust_quality_preset_generates_valid_toml should use .expect() with descriptive message, not .unwrap()"
    );

    // Should NOT contain .unwrap() in this function
    assert!(
        !test_chunk.contains("result.unwrap()"),
        "test_rust_quality_preset_generates_valid_toml should not use .unwrap()"
    );
}

/// Test that secrets preset test uses `.expect()` not `.unwrap()`
///
/// This verifies the `rust.no_unwrap` rule is not self-defeating.
#[test]
fn test_secrets_preset_test_uses_expect_not_unwrap() {
    let source = fs::read_to_string("src/presets.rs")
        .expect("presets.rs source file should exist");

    // Find the test function for secrets preset
    let test_fn_start = source
        .find("fn test_secrets_preset_generates_valid_toml()")
        .expect("test_secrets_preset_generates_valid_toml function should exist");

    // Extract a chunk of the function
    let test_chunk = &source[test_fn_start..test_fn_start + 1200];

    // The function should use .expect() with a descriptive message
    assert!(
        test_chunk.contains(r#"result.expect("secrets preset should parse as valid TOML")"#),
        "test_secrets_preset_generates_valid_toml should use .expect() with descriptive message, not .unwrap()"
    );

    // Should NOT contain .unwrap() in this function
    assert!(
        !test_chunk.contains("result.unwrap()"),
        "test_secrets_preset_generates_valid_toml should not use .unwrap()"
    );
}

/// Test that js-console preset test uses `.expect()` not `.unwrap()`
///
/// This verifies the `rust.no_unwrap` rule is not self-defeating.
#[test]
fn test_js_console_preset_test_uses_expect_not_unwrap() {
    let source = fs::read_to_string("src/presets.rs")
        .expect("presets.rs source file should exist");

    // Find the test function for js-console preset
    let test_fn_start = source
        .find("fn test_js_console_preset_generates_valid_toml()")
        .expect("test_js_console_preset_generates_valid_toml function should exist");

    // Extract a chunk of the function
    let test_chunk = &source[test_fn_start..test_fn_start + 1200];

    // The function should use .expect() with a descriptive message
    assert!(
        test_chunk.contains(r#"result.expect("js-console preset should parse as valid TOML")"#),
        "test_js_console_preset_generates_valid_toml should use .expect() with descriptive message, not .unwrap()"
    );

    // Should NOT contain .unwrap() in this function
    assert!(
        !test_chunk.contains("result.unwrap()"),
        "test_js_console_preset_generates_valid_toml should not use .unwrap()"
    );
}

/// Test that python-debug preset test uses `.expect()` not `.unwrap()`
///
/// This verifies the `rust.no_unwrap` rule is not self-defeating.
#[test]
fn test_python_debug_preset_test_uses_expect_not_unwrap() {
    let source = fs::read_to_string("src/presets.rs")
        .expect("presets.rs source file should exist");

    // Find the test function for python-debug preset
    let test_fn_start = source
        .find("fn test_python_debug_preset_generates_valid_toml()")
        .expect("test_python_debug_preset_generates_valid_toml function should exist");

    // Extract a chunk of the function
    let test_chunk = &source[test_fn_start..test_fn_start + 1200];

    // The function should use .expect() with a descriptive message
    assert!(
        test_chunk.contains(r#"result.expect("python-debug preset should parse as valid TOML")"#),
        "test_python_debug_preset_generates_valid_toml should use .expect() with descriptive message, not .unwrap()"
    );

    // Should NOT contain .unwrap() in this function
    assert!(
        !test_chunk.contains("result.unwrap()"),
        "test_python_debug_preset_generates_valid_toml should not use .unwrap()"
    );
}
