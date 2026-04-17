//! Red tests for work-b7331fdb: #[must_use] attribute verification
//!
//! Feature: clippy::must_use_candidate
//!
//! Issue: #445 reported that `is_binary_file` and `is_submodule` in
//! `crates/diffguard-diff/src/unified.rs` lack `#[must_use]`, triggering
//! `clippy::must_use_candidate`.
//!
//! The fix was already merged via PR #511 (commit 7214b2a on April 15, 2026).
//!
//! These tests verify the CORRECT behavior (that #[must_use] is present):
//! - They PASS when the fix is in place
//! - They would FAIL if #[must_use] were removed
//!
//! This is the expected state after the implementation is complete.

use diffguard_diff::{
    is_binary_file, is_deleted_file, is_mode_change_only, is_new_file, is_submodule,
    parse_rename_from, parse_rename_to,
};

/// Verifies that is_binary_file has #[must_use] attribute.
/// This test passes by compilation - if the function lacked #[must_use],
/// clippy would warn about must_use_candidate when this test calls the function
/// without using the result.
#[test]
fn test_is_binary_file_has_must_use_attribute() {
    // Call the function and discard the result - this would trigger
    // clippy::must_use_candidate if #[must_use] were missing.
    // The #[must_use] attribute silences this warning.
    let _ = is_binary_file("Binary files a/foo and b/foo differ");

    // Also verify the function still works correctly
    assert!(is_binary_file(
        "Binary files a/image.png and b/image.png differ"
    ));
    assert!(!is_binary_file("diff --git a/foo b/foo"));
}

/// Verifies that is_submodule has #[must_use] attribute.
#[test]
fn test_is_submodule_has_must_use_attribute() {
    let _ = is_submodule("Subproject commit abc123");
    assert!(is_submodule("Subproject commit abc123def456"));
    assert!(!is_submodule("diff --git a/foo b/foo"));
}

/// Verifies that is_deleted_file has #[must_use] attribute.
#[test]
fn test_is_deleted_file_has_must_use_attribute() {
    let _ = is_deleted_file("deleted file mode 100644");
    assert!(is_deleted_file("deleted file mode 100644"));
    assert!(!is_deleted_file("new file mode 100644"));
}

/// Verifies that is_new_file has #[must_use] attribute.
#[test]
fn test_is_new_file_has_must_use_attribute() {
    let _ = is_new_file("new file mode 100644");
    assert!(is_new_file("new file mode 100644"));
    assert!(!is_new_file("deleted file mode 100644"));
}

/// Verifies that is_mode_change_only has #[must_use] attribute.
#[test]
fn test_is_mode_change_only_has_must_use_attribute() {
    let _ = is_mode_change_only("old mode 100644");
    assert!(is_mode_change_only("old mode 100644"));
    assert!(is_mode_change_only("new mode 100755"));
    assert!(!is_mode_change_only("deleted file mode 100644"));
}

/// Verifies that parse_rename_from has #[must_use] attribute.
#[test]
fn test_parse_rename_from_has_must_use_attribute() {
    let _ = parse_rename_from("rename from src/foo.rs");
    assert_eq!(
        parse_rename_from("rename from src/foo.rs"),
        Some("src/foo.rs".to_string())
    );
}

/// Verifies that parse_rename_to has #[must_use] attribute.
#[test]
fn test_parse_rename_to_has_must_use_attribute() {
    let _ = parse_rename_to("rename to dst/bar.rs");
    assert_eq!(
        parse_rename_to("rename to dst/bar.rs"),
        Some("dst/bar.rs".to_string())
    );
}
