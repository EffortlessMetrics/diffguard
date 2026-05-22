//! Red test: Verify that FileBuilderInProgress and HunkBuilderInProgress
//! Self-returning methods produce warnings when called without chaining.
//!
//! This test compiles successfully (with warnings) because #[must_use] produces
//! warnings, not errors. The test serves as a SPECIFICATION that:
//! 1. Calling builder methods without chaining SHOULD produce unused_must_use warnings
//! 2. The per-method #[must_use] makes this expectation explicit
//!
//! Run with: cargo test -p diffguard-testkit --test red_tests_must_use
//! Check warnings: cargo clippy -p diffguard-testkit --lib -- -W clippy::return_self_not_must_use

use diffguard_testkit::diff_builder::DiffBuilder;

/// Test that FileBuilderInProgress::binary works with chaining.
#[test]
fn test_file_builder_binary_chained() {
    let diff = DiffBuilder::new()
        .file("src/main.rs")
        .binary()
        .hunk(1, 1, 1, 1)
        .context("fn main() {}")
        .add_line("fn main() {}")
        .done()
        .done()
        .build();

    // Binary files should have "Binary files" in output
    assert!(
        diff.contains("Binary files"),
        "Expected 'Binary files' in diff, got: {}",
        diff
    );
}

/// Test that FileBuilderInProgress::new_file works with chaining.
#[test]
fn test_file_builder_new_file_chained() {
    let diff = DiffBuilder::new()
        .file("src/new.rs")
        .new_file()
        .hunk(1, 1, 1, 1)
        .context("")
        .add_line("fn main() {}")
        .done()
        .done()
        .build();

    // New files should have "new file mode" in output
    assert!(
        diff.contains("new file mode"),
        "Expected 'new file mode' in diff, got: {}",
        diff
    );
}

/// Test that FileBuilderInProgress::deleted works with chaining.
#[test]
fn test_file_builder_deleted_chained() {
    let diff = DiffBuilder::new()
        .file("src/deleted.rs")
        .deleted()
        .hunk(1, 1, 1, 1)
        .context("fn old() {}")
        .done()
        .done()
        .build();

    // Deleted files should have "deleted file mode" in output
    assert!(
        diff.contains("deleted file mode"),
        "Expected 'deleted file mode' in diff, got: {}",
        diff
    );
}

/// Test that HunkBuilderInProgress methods work with chaining.  
#[test]
fn test_hunk_builder_in_progress_methods_chained() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 1, 1, 2)
        .context("fn existing() {}")
        .add_line("fn new() {}")
        .remove("fn old() {}")
        .done()
        .done()
        .build();

    assert!(!diff.is_empty());
    // Verify hunk content
    assert!(diff.contains("fn existing() {}"));
    assert!(diff.contains("+fn new() {}"));
    assert!(diff.contains("-fn old() {}"));
}

/// Test for FileBuilderInProgress::mode_change with chaining.
#[test]
fn test_file_builder_mode_change_chained() {
    let diff = DiffBuilder::new()
        .file("src/main.rs")
        .mode_change("100644", "100755")
        .done()
        .build();

    assert!(!diff.is_empty());
    assert!(diff.contains("old mode 100644"));
    assert!(diff.contains("new mode 100755"));
}
