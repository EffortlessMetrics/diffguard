//! Snapshot tests for DiffBuilder output baselines.
//!
//! These tests capture the string output of DiffBuilder::build(),
//! FileBuilder::build(), and HunkBuilder::build() so that ANY change
//! to the output is immediately detected.
//!
//! The mechanical fix (closure to method reference) should produce
//! IDENTICAL output - these snapshots establish that baseline.

use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, HunkBuilder};

// =============================================================================
// DiffBuilder::build() snapshots
// =============================================================================

/// Snapshot: DiffBuilder::build() with empty builder
#[test]
fn snapshot_diff_builder_empty() {
    let diff = DiffBuilder::new().build();
    insta::assert_snapshot!("diff_builder_empty", diff);
}

/// Snapshot: DiffBuilder::build() with single file, single hunk, single line
#[test]
fn snapshot_diff_builder_single_file_single_hunk() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 0, 1, 1)
        .add_line("fn new_function() {}")
        .done()
        .done()
        .build();
    insta::assert_snapshot!("diff_builder_single_file_single_hunk", diff);
}

/// Snapshot: DiffBuilder::build() with two files
#[test]
fn snapshot_diff_builder_two_files() {
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
    insta::assert_snapshot!("diff_builder_two_files", diff);
}

/// Snapshot: DiffBuilder::build() with five files (MAX_FILES boundary)
#[test]
fn snapshot_diff_builder_max_files() {
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
    insta::assert_snapshot!("diff_builder_max_files", diff);
}

/// Snapshot: DiffBuilder::build() with add_file (pre-built FileBuilder)
#[test]
fn snapshot_diff_builder_add_file() {
    let prebuilt = FileBuilder::new("src/prebuilt.rs")
        .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("prebuilt"))
        .build();

    let diff = DiffBuilder::new()
        .add_file(
            FileBuilder::new("src/first.rs")
                .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("first")),
        )
        .file("src/second.rs")
        .hunk(1, 0, 1, 1)
        .add_line("second")
        .done()
        .done()
        .add_file(
            FileBuilder::new("src/third.rs")
                .add_hunk(HunkBuilder::new(1, 0, 1, 1).add_line("third")),
        )
        .build();
    insta::assert_snapshot!("diff_builder_add_file", diff);
}

// =============================================================================
// FileBuilder::build() snapshots
// =============================================================================

/// Snapshot: FileBuilder::build() for modified file with context and changes
#[test]
fn snapshot_file_builder_modified() {
    let file = FileBuilder::new("src/lib.rs")
        .add_hunk(
            HunkBuilder::new(1, 1, 1, 2)
                .context("fn existing() {}")
                .add_line("fn new_function() {}"),
        )
        .build();
    insta::assert_snapshot!("file_builder_modified", file);
}

/// Snapshot: FileBuilder::build() for new file
#[test]
fn snapshot_file_builder_new_file() {
    let file = FileBuilder::new("src/new.rs")
        .new_file()
        .add_hunk(HunkBuilder::new(0, 0, 1, 1).add_line("fn init() {}"))
        .build();
    insta::assert_snapshot!("file_builder_new_file", file);
}

/// Snapshot: FileBuilder::build() for new file with no hunks
#[test]
fn snapshot_file_builder_new_file_no_hunks() {
    let file = FileBuilder::new("src/new.rs").new_file().build();
    insta::assert_snapshot!("file_builder_new_file_no_hunks", file);
}

/// Snapshot: FileBuilder::build() for deleted file
#[test]
fn snapshot_file_builder_deleted() {
    let file = FileBuilder::new("src/old.rs")
        .deleted()
        .add_hunk(HunkBuilder::new(1, 1, 0, 0).remove("fn old() {}"))
        .build();
    insta::assert_snapshot!("file_builder_deleted", file);
}

/// Snapshot: FileBuilder::build() for binary file
#[test]
fn snapshot_file_builder_binary() {
    let file = FileBuilder::new("asset.bin").binary().build();
    insta::assert_snapshot!("file_builder_binary", file);
}

/// Snapshot: FileBuilder::build() for renamed file
#[test]
fn snapshot_file_builder_rename() {
    let file = FileBuilder::new("src/renamed.rs")
        .rename_from("src/original.rs")
        .add_hunk(
            HunkBuilder::new(1, 1, 1, 2)
                .context("fn foo() {}")
                .add_line("fn bar() {}"),
        )
        .build();
    insta::assert_snapshot!("file_builder_rename", file);
}

/// Snapshot: FileBuilder::build() for mode change
#[test]
fn snapshot_file_builder_mode_change() {
    let file = FileBuilder::new("script.sh")
        .mode_change("100644", "100755")
        .build();
    insta::assert_snapshot!("file_builder_mode_change", file);
}

// =============================================================================
// HunkBuilder::build() snapshots
// =============================================================================

/// Snapshot: HunkBuilder::build() with context, add, and remove lines
#[test]
fn snapshot_hunk_builder_mixed() {
    let hunk = HunkBuilder::new(10, 3, 10, 5)
        .remove("fn old_main() {")
        .remove("    // old code")
        .remove("}")
        .add_line("fn new_main() {")
        .add_line("    // new code")
        .add_line("    // more new")
        .add_line("}")
        .context("fn helper() {}")
        .build();
    insta::assert_snapshot!("hunk_builder_mixed", hunk);
}

/// Snapshot: HunkBuilder::build() with only context lines
#[test]
fn snapshot_hunk_builder_context_only() {
    let hunk = HunkBuilder::new(5, 3, 5, 3)
        .context("line 1")
        .context("line 2")
        .context("line 3")
        .build();
    insta::assert_snapshot!("hunk_builder_context_only", hunk);
}

/// Snapshot: HunkBuilder::build() for additions only (new lines at end)
#[test]
fn snapshot_hunk_builder_additions_only() {
    let hunk = HunkBuilder::for_additions(10, 3)
        .add_line("new line 1")
        .add_line("new line 2")
        .add_line("new line 3")
        .build();
    insta::assert_snapshot!("hunk_builder_additions_only", hunk);
}
