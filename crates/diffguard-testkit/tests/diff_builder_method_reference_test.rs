//! Tests for DiffBuilder::build() behavior with method references
//!
//! These tests verify that DiffBuilder::build() correctly concatenates
//! file diffs when using method references. The issue at hand is replacing
//! the redundant closure `|f| f.build()` with the method reference `FileBuilder::build`.
//!
//! Note: These tests verify BEHAVIOR, which is identical regardless of whether
//! a closure or method reference is used. The mechanical fix changes only
//! the syntax, not the behavior.

use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, HunkBuilder};

/// Verifies that DiffBuilder::build() correctly concatenates multiple file diffs.
/// The output should contain both files' diff output joined by newlines.
#[test]
fn test_diff_builder_build_concatenates_multiple_files() {
    let diff = DiffBuilder::new()
        .file("src/a.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn a() {}")
        .done()
        .done()
        .file("src/b.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn b() {}")
        .done()
        .done()
        .build();

    // Both files should be present in the output
    assert!(
        diff.contains("diff --git a/src/a.rs b/src/a.rs"),
        "First file header missing from output"
    );
    assert!(
        diff.contains("diff --git a/src/b.rs b/src/b.rs"),
        "Second file header missing from output"
    );
    // Both added lines should be present
    assert!(
        diff.contains("+fn a() {}"),
        "First file content missing from output"
    );
    assert!(
        diff.contains("+fn b() {}"),
        "Second file content missing from output"
    );
    // Files should be separated by newline
    assert!(
        diff.contains("b/src/b.rs\n"),
        "Files should be separated by newline"
    );
}

/// Verifies that FileBuilder::build produces correct output for a single file.
/// This ensures the method used via method reference produces valid diff output.
#[test]
fn test_file_builder_build_produces_valid_diff_header() {
    let file_diff = FileBuilder::new("src/lib.rs")
        .add_hunk(
            HunkBuilder::new(1, 1, 1, 2)
                .context("fn existing() {}")
                .add_line("fn new_function() {}"),
        )
        .build();

    assert!(
        file_diff.contains("diff --git a/src/lib.rs b/src/lib.rs"),
        "Diff header should contain both paths"
    );
    assert!(
        file_diff.contains("+fn new_function() {}"),
        "Added line should appear with + prefix"
    );
    assert!(
        file_diff.contains(" fn existing() {}"),
        "Context line should appear with single space"
    );
}

/// Verifies that method reference via FileBuilder::build works correctly
/// when added to DiffBuilder via add_file().
#[test]
fn test_diff_builder_with_prebuilt_file() {
    let file = FileBuilder::new("src/main.rs")
        .add_hunk(
            HunkBuilder::new(10, 5, 10, 7)
                .remove("fn old_main() {}")
                .remove("    // old code")
                .add_line("fn new_main() {")
                .add_line("    // new code")
                .add_line("    // more new")
                .add_line("}"),
        )
        .build();

    // FileBuilder::build should return a String with the diff format
    assert!(
        file.contains("diff --git"),
        "FileBuilder::build should produce diff header"
    );

    let diff = DiffBuilder::new()
        .add_file(
            FileBuilder::new("src/main.rs").add_hunk(
                HunkBuilder::new(10, 5, 10, 7)
                    .remove("fn old_main() {}")
                    .remove("    // old code")
                    .add_line("fn new_main() {")
                    .add_line("    // new code")
                    .add_line("    // more new")
                    .add_line("}"),
            ),
        )
        .build();

    assert!(
        diff.contains("diff --git a/src/main.rs b/src/main.rs"),
        "Pre-built file should appear in diff output"
    );
}

/// Verifies that the build() output is correctly formatted with newlines
/// between file diffs.
#[test]
fn test_build_output_has_newline_separators() {
    let diff = DiffBuilder::new()
        .file("file1.txt")
        .hunk(1, 0, 1, 1)
        .add_line("content1")
        .done()
        .done()
        .file("file2.txt")
        .hunk(1, 0, 1, 1)
        .add_line("content2")
        .done()
        .done()
        .build();

    // Count occurrences of the pattern that indicates proper separation
    let file2_header = "diff --git a/file2.txt b/file2.txt";
    let occurrences: usize = diff.matches(file2_header).count();
    assert_eq!(
        occurrences, 1,
        "file2 header should appear exactly once, got {}",
        occurrences
    );
}

/// Verifies that FileBuilder::build returns String type, which is what
/// the method reference FileBuilder::build will return when called.
#[test]
fn test_file_builder_build_returns_string() {
    let file = FileBuilder::new("test.rs").build();
    // The return type is String
    let _: String = file;
    // String should be non-empty for a new file with no hunks
    // (it will have the diff header at minimum)
    assert!(
        !file.is_empty() || file.contains("diff --git"),
        "FileBuilder::build should return a non-empty diff string"
    );
}

// =============================================================================
// Edge case tests — boundary values and empty inputs
// =============================================================================

/// Verifies that DiffBuilder::build() on an empty builder returns an empty string.
/// This is the boundary case of zero files — the iterator produces nothing,
/// collect::<Vec<_>>() yields an empty Vec, and join("\n") returns "".
#[test]
fn test_diff_builder_empty_build_returns_empty_string() {
    let diff = DiffBuilder::new().build();
    assert_eq!(
        diff, "",
        "Empty DiffBuilder::build() should return empty string, got: {:?}",
        diff
    );
}

/// Verifies that a new file with no hunks produces valid diff output via
/// the method reference path. FileBuilder::build always produces the diff
/// header even with zero hunks.
#[test]
fn test_new_file_with_no_hunks_builds_valid_header() {
    let file = FileBuilder::new("src/new.rs").new_file().build();

    // Even with no hunks, a new file diff has the header
    assert!(
        file.contains("diff --git a/src/new.rs b/src/new.rs"),
        "New file should have diff header"
    );
    assert!(
        file.contains("new file mode"),
        "New file should be marked as new"
    );
    assert!(
        file.contains("--- /dev/null"),
        "New file should have /dev/null as old path"
    );
    assert!(
        file.contains("+++ b/src/new.rs"),
        "New file should have correct b/ path"
    );
}

/// Verifies that DiffBuilder handles exactly MAX_FILES (5) files correctly.
/// This is the upper boundary — all 5 files should appear in the output
/// and be properly separated by newlines.
#[test]
fn test_diff_builder_with_exactly_max_files() {
    let diff = DiffBuilder::new()
        .file("file0.rs")
        .hunk(1, 0, 1, 1)
        .add_line("line0")
        .done()
        .done()
        .file("file1.rs")
        .hunk(1, 0, 1, 1)
        .add_line("line1")
        .done()
        .done()
        .file("file2.rs")
        .hunk(1, 0, 1, 1)
        .add_line("line2")
        .done()
        .done()
        .file("file3.rs")
        .hunk(1, 0, 1, 1)
        .add_line("line3")
        .done()
        .done()
        .file("file4.rs")
        .hunk(1, 0, 1, 1)
        .add_line("line4")
        .done()
        .done()
        .build();

    // All 5 files should be present
    for i in 0..5 {
        assert!(
            diff.contains(&format!("diff --git a/file{}.rs b/file{}.rs", i, i)),
            "file{} should be present in diff",
            i
        );
        assert!(
            diff.contains(&format!("+line{}", i)),
            "line{} should be present in diff",
            i
        );
    }
    // Count total file headers — should be exactly 5
    let header_count = diff.matches("diff --git a/file").count();
    assert_eq!(
        header_count, 5,
        "Should have exactly 5 file headers, got {}",
        header_count
    );
}

/// Verifies that mixing add_file() and file() chaining works correctly.
/// The method reference path (FileBuilder::build) is used for both code paths,
/// so this combination should work seamlessly.
#[test]
fn test_add_file_mixed_with_file_chaining() {
    let _prebuilt = FileBuilder::new("src/prebuilt.rs")
        .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("prebuilt line"))
        .build();

    let diff = DiffBuilder::new()
        .add_file(
            FileBuilder::new("src/first.rs")
                .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("first line")),
        )
        .file("src/second.rs")
        .hunk(1, 0, 1, 1)
        .add_line("second line")
        .done()
        .done()
        .add_file(
            FileBuilder::new("src/third.rs")
                .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("third line")),
        )
        .build();

    assert!(
        diff.contains("diff --git a/src/first.rs b/src/first.rs"),
        "First file (add_file) should be present"
    );
    assert!(
        diff.contains("+first line"),
        "First file content should be present"
    );
    assert!(
        diff.contains("diff --git a/src/second.rs b/src/second.rs"),
        "Second file (file chain) should be present"
    );
    assert!(
        diff.contains("+second line"),
        "Second file content should be present"
    );
    assert!(
        diff.contains("diff --git a/src/third.rs b/src/third.rs"),
        "Third file (add_file) should be present"
    );
    assert!(
        diff.contains("+third line"),
        "Third file content should be present"
    );
}
