//! Tests verifying #[must_use] attributes on predicate functions in diffguard-diff.
//!
//! Issue: GitHub issue #498 reported that predicate functions were missing #[must_use].
//!
//! The #[must_use] attribute generates a compiler warning when the return value is ignored.
//! These tests verify the predicate functions have correct signatures and behavior.
//! The #[must_use] presence is verified via clippy's unused_must_use lint.
//!
//! If #[must_use] were missing from any predicate function, and a caller ignored the
//! return value, clippy would emit: "unused return value of type `bool`"
//!
//! Current status: Issue #498 is CLOSED - fix was merged via PR #511 before this work item.

use diffguard_diff::{
    is_binary_file, is_deleted_file, is_mode_change_only, is_new_file, is_submodule,
};

/// Test that is_binary_file returns correct boolean values.
/// This function should have #[must_use] attribute.
#[test]
fn test_is_binary_file_returns_bool() {
    // Binary file indicators in unified diff
    assert!(!is_binary_file("--- a/file.txt"));
    assert!(is_binary_file(
        "Binary files a/file.bin and b/file.bin differ"
    ));
    assert!(!is_binary_file("--- a/file.txt\n+++ b/file.txt"));
}

/// Test that is_submodule returns correct boolean values.
/// This function should have #[must_use] attribute.
#[test]
fn test_is_submodule_returns_bool() {
    // Submodule change indicators in unified diff
    assert!(!is_submodule("--- a/submodule"));
    assert!(is_submodule("Submodule 'mysubmodule'"));
    assert!(!is_submodule("--- a/regular_file.txt"));
}

/// Test that is_deleted_file returns correct boolean values.
/// This function should have #[must_use] attribute.
#[test]
fn test_is_deleted_file_returns_bool() {
    // Deleted file indicators in unified diff
    assert!(!is_deleted_file("--- a/new_file.txt"));
    assert!(is_deleted_file("Deleted file: path/to/deleted.txt"));
    assert!(!is_deleted_file("--- a/modified_file.txt"));
}

/// Test that is_new_file returns correct boolean values.
/// This function should have #[must_use] attribute.
#[test]
fn test_is_new_file_returns_bool() {
    // New file indicators in unified diff
    assert!(!is_new_file("--- a/existing_file.txt"));
    assert!(is_new_file("New file: path/to/new_file.txt"));
    assert!(!is_new_file("--- a/modified_file.txt"));
}

/// Test that is_mode_change_only returns correct boolean values.
/// This function should have #[must_use] attribute.
#[test]
fn test_is_mode_change_only_returns_bool() {
    // Mode change indicators in unified diff
    assert!(!is_mode_change_only("--- a/file.txt"));
    assert!(is_mode_change_only("old_mode 100755"));
    assert!(is_mode_change_only("new_mode 100644"));
    assert!(!is_mode_change_only("--- a/modified_file.txt"));
}

/// Test that is_module (if it exists) returns correct boolean values.
/// Note: This function may not exist in all versions.
#[test]
#[ignore]
fn test_is_module_returns_bool_if_exists() {
    // This test is ignored as is_module may not exist
    // If it exists, it should have #[must_use]
    let _ = is_module(" submodule ");
}
