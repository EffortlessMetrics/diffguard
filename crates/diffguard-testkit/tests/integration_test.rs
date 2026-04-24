//! Integration tests for DiffBuilder component seams.
//!
//! These tests verify that the components in diff_builder.rs work correctly
//! together, exercising the full chain:
//!   HunkBuilder → FileBuilder → DiffBuilder → String output
//!
//! The mechanical fix (replacing `.map(|f| f.build())` with `.map(FileBuilder::build)`)
//! is a pure refactor with identical behavior. These tests verify the seams
//! between components continue to work correctly.

use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, GeneratedDiff, HunkBuilder};

/// Integration test: GeneratedDiff::with_additions exercises the full chain.
/// Flow: HunkBuilder → FileBuilder → DiffBuilder → String
/// Verifies: DiffBuilder::build() concatenation via FileBuilder::build method reference
#[test]
fn integration_generated_diff_with_additions_full_chain() {
    let diff = GeneratedDiff::with_additions("src/lib.rs", &["fn a() {}", "fn b() {}"]);

    // The GeneratedDiff bundles metadata + the diff text
    assert_eq!(diff.expected_files, 1);
    assert_eq!(diff.expected_added_lines, 2);
    assert_eq!(diff.file_paths, vec!["src/lib.rs"]);

    // The diff text was built by the full chain:
    // DiffBuilder.file() → FileBuilderInProgress.hunk() → HunkBuilder → FileBuilderInProgress.done() → DiffBuilder
    // then DiffBuilder.build() calls FileBuilder::build on each file via .map(FileBuilder::build)
    assert!(diff.text.contains("diff --git a/src/lib.rs b/src/lib.rs"));
    assert!(diff.text.contains("+fn a() {}"));
    assert!(diff.text.contains("+fn b() {}"));
}

/// Integration test: GeneratedDiff::with_changes exercises HunkBuilder with
/// both remove and add_line, passing through FileBuilder to DiffBuilder.
#[test]
fn integration_generated_diff_with_changes_removes_and_adds() {
    let diff = GeneratedDiff::with_changes(
        "src/main.rs",
        &["fn old_main() {}", "    // old code"],
        &["fn new_main() {", "    // new code", "}"],
    );

    assert_eq!(diff.expected_added_lines, 3);
    assert_eq!(diff.expected_changed_lines, 3);
    assert!(diff.text.contains("-fn old_main() {}"));
    assert!(diff.text.contains("+fn new_main() {"));
    assert!(diff.text.contains("+    // new code"));
}

/// Integration test: GeneratedDiff::deleted exercises the add_file path
/// where a pre-built FileBuilder is passed to DiffBuilder.
#[test]
fn integration_generated_diff_deleted_file_add_file_path() {
    let diff = GeneratedDiff::deleted("src/old.rs", &["fn removed1() {}", "fn removed2() {}"]);

    // Deleted files have no lines extracted
    assert_eq!(diff.expected_files, 0);
    assert_eq!(diff.expected_added_lines, 0);
    assert!(diff.text.contains("deleted file mode"));
    assert!(diff.text.contains("-fn removed1() {}"));
    assert!(diff.text.contains("-fn removed2() {}"));
}

/// Integration test: GeneratedDiff::renamed exercises the add_file path
/// with rename_from set on FileBuilder.
#[test]
fn integration_generated_diff_renamed_file() {
    let diff = GeneratedDiff::renamed(
        "src/old_name.rs",
        "src/new_name.rs",
        &["fn refactored() {}"],
    );

    assert_eq!(diff.expected_files, 1);
    assert_eq!(diff.expected_added_lines, 1);
    assert!(diff.text.contains("rename from src/old_name.rs"));
    assert!(diff.text.contains("rename to src/new_name.rs"));
    assert!(diff.text.contains("+fn refactored() {}"));
}

/// Integration test: GeneratedDiff::binary exercises the binary flag
/// path where FileBuilder has no hunks but binary flag set.
#[test]
fn integration_generated_diff_binary_file() {
    let diff = GeneratedDiff::binary("asset.png");

    assert_eq!(diff.expected_files, 0);
    assert!(diff.text.contains("Binary files"));
    assert!(diff.text.contains("asset.png"));
}

/// Integration test: Multiple files via .file().done().file().done() chain.
/// This exercises the core path that uses .map(FileBuilder::build) at line 78.
#[test]
fn integration_diff_builder_multiple_files_via_file_chain() {
    let diff = DiffBuilder::new()
        .file("file1.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn first() {}")
        .done()
        .done()
        .file("file2.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn second() {}")
        .done()
        .done()
        .file("file3.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn third() {}")
        .done()
        .done()
        .build();

    assert!(diff.contains("diff --git a/file1.rs b/file1.rs"));
    assert!(diff.contains("diff --git a/file2.rs b/file2.rs"));
    assert!(diff.contains("diff --git a/file3.rs b/file3.rs"));
    assert!(diff.contains("+fn first() {}"));
    assert!(diff.contains("+fn second() {}"));
    assert!(diff.contains("+fn third() {}"));
    // Files are separated by newlines
    assert!(diff.contains("b/file2.rs\n"));
    assert!(diff.contains("b/file3.rs\n"));
}

/// Integration test: Mixing .file().done() chain with .add_file() pre-built.
/// This tests both code paths to DiffBuilder.files.
#[test]
fn integration_diff_builder_mixed_file_and_add_file() {
    // add_file() takes a FileBuilder (not a built string)
    let prebuilt = FileBuilder::new("src/utils.rs")
        .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("fn util() {}"));

    let diff = DiffBuilder::new()
        .add_file(prebuilt)
        .file("src/main.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn main() {}")
        .done()
        .done()
        .build();

    assert!(diff.contains("diff --git a/src/utils.rs b/src/utils.rs"));
    assert!(diff.contains("diff --git a/src/main.rs b/src/main.rs"));
    assert!(diff.contains("+fn util() {}"));
    assert!(diff.contains("+fn main() {}"));
}

/// Integration test: build_for_scope delegates to build, verifying the
/// full chain is exercised when called through the scope-aware entry point.
#[test]
fn integration_diff_builder_build_for_scope() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 0, 1, 2)
        .add_line("fn new1() {}")
        .add_line("fn new2() {}")
        .done()
        .done()
        .build_for_scope(diffguard_types::Scope::Added);

    assert!(diff.contains("+fn new1() {}"));
    assert!(diff.contains("+fn new2() {}"));
    assert!(diff.contains("diff --git a/src/lib.rs b/src/lib.rs"));
}

/// Integration test: Verifies the output format is valid unified diff.
/// This is the format that diffguard-core parses.
#[test]
fn integration_output_is_valid_unified_diff_format() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(10, 2, 10, 3)
        .remove("fn old() {}")
        .remove("fn older() {}")
        .add_line("fn new() {}")
        .add_line("fn newer() {}")
        .context("fn kept() {}")
        .done()
        .done()
        .build();

    // Must have git diff header
    assert!(diff.contains("diff --git a/src/lib.rs b/src/lib.rs"));
    // Must have index line
    assert!(diff.contains("index "));
    // Must have --- and +++ lines
    assert!(diff.contains("--- a/src/lib.rs"));
    assert!(diff.contains("+++ b/src/lib.rs"));
    // Must have hunk header
    assert!(diff.contains("@@ -10,2 +10,3 @@"));
    // Must have proper line markers
    assert!(diff.contains("-fn old() {}"));
    assert!(diff.contains("+fn new() {}"));
    assert!(diff.contains(" fn kept() {}"));
}

/// Integration test: Empty diff (zero files) edge case.
/// The .map(FileBuilder::build) on an empty iterator should produce "".
#[test]
fn integration_empty_diffbuilder_produces_empty_string() {
    let diff = DiffBuilder::new().build();
    assert_eq!(diff, "");
}

/// Integration test: File with no hunks produces valid header.
/// This is the minimal FileBuilder output, used as baseline.
#[test]
fn integration_file_builder_no_hunks_produces_valid_header() {
    let file = FileBuilder::new("src/empty.rs").new_file().build();

    assert!(file.contains("diff --git a/src/empty.rs b/src/empty.rs"));
    assert!(file.contains("new file mode"));
    assert!(file.contains("--- /dev/null"));
    assert!(file.contains("+++ b/src/empty.rs"));
    // No hunks means no @@ header
    assert!(!file.contains("@@"));
}
