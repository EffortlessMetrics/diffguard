//! Green edge case tests for diff_builder.
//!
//! These tests stress the implementation with boundary values, empty inputs,
//! malformed data, and error paths to ensure robustness.

use diffguard_testkit::arb::{MAX_FILES, MAX_HUNKS_PER_FILE, MAX_LINE_LENGTH, MAX_LINES_PER_HUNK};
use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, GeneratedDiff, HunkBuilder};

/// Test that exactly MAX_FILES files can be added (boundary).
#[test]
fn can_add_exactly_max_files() {
    let mut builder = DiffBuilder::new();
    for i in 0..MAX_FILES {
        builder = builder.file(&format!("file{}.rs", i)).done();
    }
    let diff = builder.build();
    // Should have MAX_FILES diff headers
    let count = diff.matches("diff --git").count();
    assert_eq!(count, MAX_FILES);
}

/// Test that MAX_FILES + 1 files panics.
#[test]
#[should_panic(expected = "Cannot add more than")]
fn panics_when_exceeding_max_files() {
    let mut builder = DiffBuilder::new();
    for i in 0..=MAX_FILES {
        builder = builder.file(&format!("file{}.rs", i)).done();
    }
}

/// Test that add_file also enforces MAX_FILES boundary.
#[test]
#[should_panic(expected = "Cannot add more than")]
fn add_file_enforces_max_files() {
    let mut builder = DiffBuilder::new();
    for i in 0..MAX_FILES {
        let file = FileBuilder::new(&format!("file{}.rs", i));
        builder = builder.add_file(file);
    }
    // Adding one more via add_file should also panic
    let extra_file = FileBuilder::new("extra.rs");
    let _ = builder.add_file(extra_file);
}

/// Test that exactly MAX_HUNKS_PER_FILE hunks can be added (boundary).
#[test]
fn can_add_exactly_max_hunks_per_file() {
    let mut file = FileBuilder::new("test.rs");
    for i in 0..MAX_HUNKS_PER_FILE {
        let hunk = HunkBuilder::new(i as u32 + 1, 1, i as u32 + 1, 1)
            .context("ctx")
            .add_line("add");
        file = file.add_hunk(hunk);
    }
    let diff = DiffBuilder::new().add_file(file).build();
    // Should have MAX_HUNKS_PER_FILE hunk headers
    let count = diff.matches("@@ -").count();
    assert_eq!(count, MAX_HUNKS_PER_FILE);
}

/// Test that MAX_HUNKS_PER_FILE + 1 hunks panics.
#[test]
#[should_panic(expected = "Cannot add more than")]
fn panics_when_exceeding_max_hunks_per_file() {
    let file = FileBuilder::new("test.rs");
    let mut file = file;
    for i in 0..=MAX_HUNKS_PER_FILE {
        let hunk = HunkBuilder::new(i as u32 + 1, 1, i as u32 + 1, 1).context("line");
        file = file.add_hunk(hunk);
    }
}

/// Test that exactly MAX_LINES_PER_HUNK lines can be added (boundary).
#[test]
fn can_add_exactly_max_lines_per_hunk() {
    let mut hunk = HunkBuilder::new(1, 1, 1, MAX_LINES_PER_HUNK as u32);
    for i in 0..MAX_LINES_PER_HUNK {
        hunk = hunk.add_line(&format!("ln{}", i));
    }
    let output = hunk.build();
    // Each added line has a + prefix, and we added exactly MAX_LINES_PER_HUNK lines
    let add_count = output.matches("+ln").count();
    assert_eq!(add_count, MAX_LINES_PER_HUNK);
}

/// Test that MAX_LINES_PER_HUNK + 1 lines panics.
#[test]
#[should_panic(expected = "Cannot add more than")]
fn panics_when_exceeding_max_lines_per_hunk() {
    let mut hunk = HunkBuilder::new(1, 1, 1, 1);
    for i in 0..=MAX_LINES_PER_HUNK {
        hunk = hunk.add_line(&format!("line{}", i));
    }
}

/// Test that exactly MAX_LINE_LENGTH bytes works (boundary).
#[test]
fn can_add_line_at_max_line_length() {
    let line = "x".repeat(MAX_LINE_LENGTH);
    let hunk = HunkBuilder::new(1, 1, 1, 1).add_line(&line);
    let output = hunk.build();
    let expected = format!("+{}", line);
    assert!(output.contains(&expected));
}

/// Test that MAX_LINE_LENGTH + 1 bytes panics.
#[test]
#[should_panic(expected = "Line content cannot exceed")]
fn panics_when_line_exceeds_max_line_length() {
    let line = "x".repeat(MAX_LINE_LENGTH + 1);
    let _hunk = HunkBuilder::new(1, 1, 1, 1).add_line(&line);
}

/// Test that zero values in hunk header are handled.
#[test]
fn hunk_with_zero_counts_handled() {
    let hunk = HunkBuilder::new(0, 0, 1, 1).add_line("new function");
    let output = hunk.build();
    assert!(output.contains("@@ -0,0 +1,1 @@"));
}

/// Test that empty file path is handled.
#[test]
fn empty_file_path_handled() {
    let diff = DiffBuilder::new()
        .file("")
        .hunk(0, 0, 1, 1)
        .add_line("content")
        .done()
        .done()
        .build();
    assert!(diff.contains("diff --git a/ b/"));
}

/// Test that file path with spaces is handled.
#[test]
fn file_path_with_spaces() {
    let diff = DiffBuilder::new()
        .file("src/My Files/main.rs")
        .hunk(1, 0, 1, 1)
        .add_line("new line")
        .done()
        .done()
        .build();
    assert!(diff.contains("diff --git a/src/My Files/main.rs b/src/My Files/main.rs"));
}

/// Test that unicode in file path is handled.
#[test]
fn unicode_file_path() {
    let diff = DiffBuilder::new()
        .file("src/文件.rs")
        .hunk(1, 0, 1, 1)
        .add_line("内容")
        .done()
        .done()
        .build();
    assert!(diff.contains("diff --git a/src/文件.rs b/src/文件.rs"));
}

/// Test that file path with special characters is handled.
#[test]
fn file_path_with_special_chars() {
    let diff = DiffBuilder::new()
        .file("src/file[1](2).rs")
        .hunk(1, 0, 1, 1)
        .add_line("code")
        .done()
        .done()
        .build();
    assert!(diff.contains("diff --git a/src/file[1](2).rs b/src/file[1](2).rs"));
}

/// Test context, add, and remove lines at boundary.
#[test]
fn mixed_line_types_at_boundary() {
    let mut hunk = HunkBuilder::new(1, 10, 1, 10);
    for i in 0..5 {
        hunk = hunk.context(&format!("ctx{}", i));
        hunk = hunk.add_line(&format!("add{}", i));
        hunk = hunk.remove(&format!("rem{}", i));
    }
    let output = hunk.build();
    assert!(output.contains(" ctx"));
    assert!(output.contains("+add"));
    assert!(output.contains("-rem"));
}

/// Test GeneratedDiff helpers work at boundaries.
#[test]
fn generated_diff_with_changes_at_boundary() {
    let diff = GeneratedDiff::with_changes(
        "test.rs",
        &["rem0", "rem1", "rem2"],
        &["line0", "line1", "line2", "line3", "line4"],
    );
    assert_eq!(diff.expected_added_lines, 5);
    assert_eq!(diff.expected_changed_lines, 5);
}

/// Test that build_for_scope with different scopes works.
#[test]
fn build_for_scope_with_various_scopes() {
    use diffguard_types::Scope;

    let diff_added = DiffBuilder::new()
        .file("a.rs")
        .hunk(1, 0, 1, 1)
        .add_line("new")
        .done()
        .done()
        .build_for_scope(Scope::Added);

    let diff_changed = DiffBuilder::new()
        .file("a.rs")
        .hunk(1, 1, 1, 1)
        .remove("old")
        .done()
        .done()
        .build_for_scope(Scope::Changed);

    assert!(diff_added.contains("+new"));
    assert!(diff_changed.contains("-old"));
}

/// Test for_additions helper with boundary values.
#[test]
fn for_additions_at_boundary() {
    // Adding 1 line at line 10
    let hunk = HunkBuilder::for_additions(10, 1).add_line("content");
    let output = hunk.build();
    // start_line.saturating_sub(1) = 9 for old_start, count + 1 = 2 for new_count
    assert!(output.contains("@@ -9,1 +10,2 @@"));
    assert!(output.contains("+content"));

    // Adding MAX_LINES_PER_HUNK - 1 lines using for_additions (should not panic)
    let start: u32 = 5;
    let count: u32 = (MAX_LINES_PER_HUNK - 1) as u32;
    let mut hunk = HunkBuilder::for_additions(start, count);
    for i in 0..(MAX_LINES_PER_HUNK - 1) {
        hunk = hunk.add_line(&format!("ln{}", i));
    }
    let output = hunk.build();
    // Should contain the additions with ln prefix
    assert!(output.contains("+ln"));
}

/// Test that add_lines_from_slice respects boundary.
#[test]
fn add_lines_from_slice_at_boundary() {
    let string_lines: Vec<String> = (0..MAX_LINES_PER_HUNK)
        .map(|i| format!("ln{}", i))
        .collect();
    let lines: Vec<&str> = string_lines.iter().map(|s| s.as_str()).collect();
    let hunk = HunkBuilder::new(1, 1, 1, MAX_LINES_PER_HUNK as u32).add_lines_from_slice(&lines);
    let output = hunk.build();
    // Each line should be prefixed with +
    for i in 0..MAX_LINES_PER_HUNK {
        assert!(output.contains(&format!("+ln{}", i)));
    }
}

/// Test add_lines_from_slice with exactly one over boundary.
#[test]
#[should_panic(expected = "Cannot add more than")]
fn add_lines_from_slice_exceeds_boundary() {
    let string_lines: Vec<String> = (0..=MAX_LINES_PER_HUNK)
        .map(|i| format!("line{}", i))
        .collect();
    let lines: Vec<&str> = string_lines.iter().map(|s| s.as_str()).collect();
    let _hunk = HunkBuilder::new(1, 1, 1, 1).add_lines_from_slice(&lines);
}

/// Test remove_lines respects boundary.
#[test]
fn remove_lines_at_boundary() {
    let lines: Vec<&str> = vec!["rem0", "rem1", "rem2", "rem3", "rem4"];
    let hunk = HunkBuilder::new(1, 5, 1, 0).remove_lines(&lines);
    let output = hunk.build();
    // Verify all removed lines appear with - prefix
    for i in 0..5 {
        assert!(output.contains(&format!("-rem{}", i)));
    }
}

/// Test that binary file diff does not contain hunk markers.
#[test]
fn binary_file_no_hunk_markers() {
    let diff = DiffBuilder::new().file("image.png").binary().done().build();
    assert!(diff.contains("Binary files"));
    assert!(!diff.contains("@@"));
}

/// Test deleted file produces correct format.
#[test]
fn deleted_file_correct_format() {
    let diff = DiffBuilder::new()
        .file("old.rs")
        .deleted()
        .hunk(1, 1, 0, 0)
        .remove("fn removed() {}")
        .done()
        .done()
        .build();
    assert!(diff.contains("deleted file mode"));
    assert!(diff.contains("--- a/old.rs"));
    assert!(diff.contains("+++ /dev/null"));
    assert!(!diff.contains("new file mode"));
}

/// Test new file produces correct format.
#[test]
fn new_file_correct_format() {
    let diff = DiffBuilder::new()
        .file("new.rs")
        .new_file()
        .hunk(0, 0, 1, 1)
        .add_line("fn new() {}")
        .done()
        .done()
        .build();
    assert!(diff.contains("new file mode"));
    assert!(diff.contains("--- /dev/null"));
    assert!(!diff.contains("deleted file mode"));
}

/// Test mode_change produces correct format without hunks.
#[test]
fn mode_change_correct_format() {
    let diff = DiffBuilder::new()
        .file("script.sh")
        .mode_change("100644", "100755")
        .done()
        .build();
    assert!(diff.contains("old mode 100644"));
    assert!(diff.contains("new mode 100755"));
    assert!(!diff.contains("@@")); // No hunks for mode-only change
}

/// Test rename produces correct format.
#[test]
fn rename_correct_format() {
    let diff = DiffBuilder::new()
        .file("new_name.rs")
        .rename_from("old_name.rs")
        .hunk(1, 1, 1, 1)
        .context("unchanged")
        .done()
        .done()
        .build();
    assert!(diff.contains("rename from old_name.rs"));
    assert!(diff.contains("rename to new_name.rs"));
    assert!(diff.contains("similarity index 90%"));
}

/// Test file builder flags are composable.
#[test]
fn file_builder_flags_composable() {
    // Test that we can chain binary and new_file (edge case - unusual but valid API usage)
    let diff = DiffBuilder::new()
        .file("bin.rs")
        .binary()
        .new_file()
        .done()
        .build();
    // Binary takes precedence, so we should see Binary files
    assert!(diff.contains("Binary files"));
}

/// Test build produces valid multi-file diff output.
#[test]
fn build_multi_file_diff_valid() {
    let diff = DiffBuilder::new()
        .file("file_a.rs")
        .hunk(1, 0, 1, 1)
        .add_line("content_a")
        .done()
        .done()
        .file("file_b.rs")
        .hunk(1, 0, 1, 1)
        .add_line("content_b")
        .done()
        .done()
        .file("file_c.rs")
        .hunk(1, 0, 1, 1)
        .add_line("content_c")
        .done()
        .done()
        .build();

    // Should have 3 diff headers
    let diff_count = diff.matches("diff --git").count();
    assert_eq!(diff_count, 3);
    // Should have 3 hunk headers
    let hunk_count = diff.matches("@@ -").count();
    assert_eq!(hunk_count, 3);
    // Each file should have its specific content
    assert!(diff.contains("+content_a"));
    assert!(diff.contains("+content_b"));
    assert!(diff.contains("+content_c"));
}

/// Test GeneratedDiff with_additions helper.
#[test]
fn generated_diff_with_additions_helper() {
    let diff = GeneratedDiff::with_additions("test.rs", &["fn a() {}", "fn b() {}", "fn c() {}"]);
    assert_eq!(diff.expected_files, 1);
    assert_eq!(diff.expected_added_lines, 3);
    assert!(diff.text.contains("+fn a() {}"));
    assert!(diff.text.contains("+fn b() {}"));
    assert!(diff.text.contains("+fn c() {}"));
}

/// Test GeneratedDiff binary helper.
#[test]
fn generated_diff_binary_helper() {
    let diff = GeneratedDiff::binary("image.png");
    assert_eq!(diff.expected_files, 0);
    assert!(diff.text.contains("Binary files"));
}

/// Test GeneratedDiff deleted helper.
#[test]
fn generated_diff_deleted_helper() {
    let diff = GeneratedDiff::deleted("old.rs", &["fn removed() {}", "fn also_gone() {}"]);
    assert_eq!(diff.expected_files, 0);
    assert!(diff.text.contains("deleted file mode"));
    assert!(diff.text.contains("-fn removed() {}"));
}

/// Test GeneratedDiff renamed helper.
#[test]
fn generated_diff_renamed_helper() {
    let diff = GeneratedDiff::renamed("old.rs", "new.rs", &["fn kept() {}"]);
    assert_eq!(diff.expected_files, 1);
    assert!(diff.text.contains("rename from old.rs"));
    assert!(diff.text.contains("rename to new.rs"));
    assert!(diff.text.contains("+fn kept() {}"));
}

/// Test that very long file paths are handled.
#[test]
fn long_file_path_handled() {
    let long_path = "src/".to_string() + &"very/".repeat(20) + "long_file_name.rs";
    let diff = DiffBuilder::new()
        .file(&long_path)
        .hunk(1, 0, 1, 1)
        .add_line("content")
        .done()
        .done()
        .build();
    assert!(diff.contains(&format!("diff --git a/{} b/{}", long_path, long_path)));
}
