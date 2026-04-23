//! Property-based tests for diff_builder module.
//!
//! These tests verify invariants that should hold across all inputs,
//! not just specific examples.

use diffguard_testkit::arb::{arb_file_path, arb_safe_line_content};
use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, GeneratedDiff, HunkBuilder};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

// =============================================================================
// Bounds Tests - Verify documented limits are enforced
// =============================================================================

#[test]
fn can_add_exactly_max_files() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        // Should not panic - adding exactly MAX_FILES is allowed
        let result = DiffBuilder::new()
            .file(&format!("src/{}", path))
            .done()
            .file(&format!("lib/{}", path))
            .done()
            .file(&format!("tests/{}", path))
            .done()
            .file(&format!("examples/{}", path))
            .done()
            .file(&format!("benches/{}", path))
            .done()
            .build();
        assert!(result.contains("diff --git"));
    }
}

#[test]
fn can_add_exactly_max_hunks_per_file() {
    for _ in 0..100 {
        let mut file = FileBuilder::new("test.rs");
        for i in 0..5 {
            // Use a fixed short line to avoid exceeding MAX_LINE_LENGTH
            let hunk =
                HunkBuilder::new(i as u32 + 1, 1, i as u32 + 1, 1).context("line");
            file = file.add_hunk(hunk);
        }
        let result = file.build();
        // Should contain 5 hunk headers starting with @@ -
        // Count occurrences of "@@ -" which is unique to hunk headers
        let count = result.matches("@@ -").count();
        assert_eq!(count, 5);
    }
}

#[test]
fn can_add_exactly_max_lines_per_hunk() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        // Generate a short line to avoid exceeding MAX_LINE_LENGTH when we add index
        let line = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        // Truncate to 180 chars to leave room for the index
        let line = &line[..line.len().min(180)];
        let hunk = HunkBuilder::new(1, 1, 1, 20);
        // Adding exactly MAX_LINES_PER_HUNK lines should succeed
        let result = (0..20)
            .fold(hunk, |h, i| h.add_line(&format!("{}{}", line, i)))
            .build();
        assert!(result.contains('+'));
    }
}

#[test]
fn can_add_line_at_max_line_length() {
    // 200 byte line should be allowed
    let line: String = "x".repeat(200);
    let hunk = HunkBuilder::new(1, 0, 1, 1).add_line(&line);
    let result = hunk.build();
    let expected = format!("+{}", line);
    assert!(result.contains(&expected));
}

// =============================================================================
// Format Well-Formedness Tests
// =============================================================================

#[test]
fn diff_starts_with_git_header() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let diff = DiffBuilder::new()
            .file(&path)
            .hunk(1, 0, 1, 1)
            .add_line("test")
            .done()
            .done()
            .build();

        let expected_header = format!("diff --git a/{} b/{}", path, path);
        assert!(diff.starts_with(&expected_header));
    }
}

#[test]
fn hunk_headers_are_valid_unified_format() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let old_start = any::<u32>().new_tree(&mut runner).unwrap().current() % 1000;
        let old_count = any::<u32>().new_tree(&mut runner).unwrap().current() % 100;
        let new_start = any::<u32>().new_tree(&mut runner).unwrap().current() % 1000;
        let new_count = any::<u32>().new_tree(&mut runner).unwrap().current() % 100;

        let hunk = HunkBuilder::new(old_start, old_count, new_start, new_count)
            .add_line("test")
            .build();

        let expected_header =
            format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@");
        assert!(hunk.contains(&expected_header));
    }
}

#[test]
fn added_lines_start_with_plus() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let content = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let hunk = HunkBuilder::new(1, 0, 1, 1).add_line(&content).build();

        let expected = format!("+{}", content);
        assert!(hunk.contains(&expected));
    }
}

#[test]
fn removed_lines_start_with_minus() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let content = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let hunk = HunkBuilder::new(1, 1, 1, 0).remove(&content).build();

        let expected = format!("-{}", content);
        assert!(hunk.contains(&expected));
    }
}

#[test]
fn context_lines_start_with_space() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let content = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let hunk = HunkBuilder::new(1, 1, 1, 1).context(&content).build();

        let expected = format!(" {}", content);
        assert!(hunk.contains(&expected));
    }
}

// =============================================================================
// Structure Invariants
// =============================================================================

#[test]
fn multi_file_diff_contains_all_files() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path1 = arb_file_path().new_tree(&mut runner).unwrap().current();
        let path2 = arb_file_path().new_tree(&mut runner).unwrap().current();

        let diff = DiffBuilder::new()
            .file(&path1)
            .hunk(1, 0, 1, 1)
            .add_line("test1")
            .done()
            .done()
            .file(&path2)
            .hunk(1, 0, 1, 1)
            .add_line("test2")
            .done()
            .done()
            .build();

        let expected1 = format!("diff --git a/{} b/{}", path1, path1);
        let expected2 = format!("diff --git a/{} b/{}", path2, path2);
        assert!(diff.contains(&expected1));
        assert!(diff.contains(&expected2));
    }
}

#[test]
fn file_contains_its_hunks() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let diff = DiffBuilder::new()
            .file(&path)
            .hunk(10, 2, 20, 3)
            .context("unchanged")
            .add_line("added")
            .remove("removed")
            .done()
            .done()
            .build();

        // The file section should contain the hunk header
        let file_section_start = diff
            .find(&format!("diff --git a/{} b/{}", path, path))
            .expect("file header should exist");
        let file_section = &diff[file_section_start..];

        assert!(file_section.contains("@@ -10,2 +20,3 @@"));
    }
}

#[test]
fn binary_file_contains_binary_indicator() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let diff = DiffBuilder::new()
            .file(&path)
            .binary()
            .done()
            .build();

        assert!(diff.contains("Binary files"));
        assert!(diff.contains("differ"));
    }
}

#[test]
fn deleted_file_contains_deleted_mode_marker() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let file = FileBuilder::new(&path)
            .deleted()
            .add_hunk(HunkBuilder::new(1, 1, 1, 0).remove("fn old() {}"));
        let diff = DiffBuilder::new().add_file(file).build();

        assert!(diff.contains("deleted file mode"));
        let expected = format!("--- a/{}", path);
        assert!(diff.contains(&expected));
        assert!(diff.contains("+++ /dev/null"));
    }
}

#[test]
fn new_file_contains_new_file_mode_marker() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let diff = DiffBuilder::new()
            .file(&path)
            .new_file()
            .hunk(0, 0, 1, 1)
            .add_line("fn new() {}")
            .done()
            .done()
            .build();

        assert!(diff.contains("new file mode"));
        assert!(diff.contains("--- /dev/null"));
        let expected = format!("+++ b/{}", path);
        assert!(diff.contains(&expected));
    }
}

#[test]
fn rename_contains_rename_markers() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let old_path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let new_path = arb_file_path().new_tree(&mut runner).unwrap().current();

        let file = FileBuilder::new(&new_path).rename_from(&old_path).add_hunk(
            HunkBuilder::new(1, 1, 1, 2)
                .context("unchanged")
                .add_line("added"),
        );
        let diff = DiffBuilder::new().add_file(file).build();

        assert!(diff.contains("similarity index 90%"));
        let rename_from = format!("rename from {}", old_path);
        let rename_to = format!("rename to {}", new_path);
        assert!(diff.contains(&rename_from));
        assert!(diff.contains(&rename_to));
    }
}

#[test]
fn mode_change_contains_modes() {
    let modes = vec!["100644", "100755", "100600"];
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let idx1 = any::<usize>().new_tree(&mut runner).unwrap().current() % modes.len();
        let idx2 = any::<usize>().new_tree(&mut runner).unwrap().current() % modes.len();
        let old_mode = modes[idx1];
        let new_mode = modes[idx2];

        let diff = DiffBuilder::new()
            .file(&path)
            .mode_change(old_mode, new_mode)
            .done()
            .build();

        let old_mode_line = format!("old mode {}", old_mode);
        let new_mode_line = format!("new mode {}", new_mode);
        assert!(diff.contains(&old_mode_line));
        assert!(diff.contains(&new_mode_line));
    }
}

// =============================================================================
// GeneratedDiff Helper Invariants
// =============================================================================

#[test]
fn generated_diff_additions_line_count() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let lines = prop::collection::vec(arb_safe_line_content(), 1..10)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let lines_refs: Vec<&str> =
            lines.iter().map(|s| s.as_str()).collect::<Vec<_>>();

        let diff = GeneratedDiff::with_additions(&path, &lines_refs);
        assert_eq!(diff.expected_added_lines, lines.len());
        assert_eq!(diff.expected_files, 1);
    }
}

#[test]
fn generated_diff_changes_line_count() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let removed = prop::collection::vec(arb_safe_line_content(), 1..5)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let added = prop::collection::vec(arb_safe_line_content(), 1..5)
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let removed_refs: Vec<&str> =
            removed.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let added_refs: Vec<&str> =
            added.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let diff = GeneratedDiff::with_changes(&path, &removed_refs, &added_refs);

        assert_eq!(diff.expected_added_lines, added.len());
        assert_eq!(diff.expected_changed_lines, added.len());
    }
}

#[test]
fn generated_diff_additions_contains_content() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let lines = prop::collection::vec(arb_safe_line_content(), 1..5)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let lines_refs: Vec<&str> =
            lines.iter().map(|s| s.as_str()).collect::<Vec<_>>();

        let diff = GeneratedDiff::with_additions(&path, &lines_refs);
        for line in &lines {
            let expected = format!("+{}", line);
            assert!(
                diff.text.contains(&expected),
                "Diff should contain +{}",
                line
            );
        }
    }
}

#[test]
fn generated_diff_renamed_new_path() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let old_path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let new_path = arb_file_path().new_tree(&mut runner).unwrap().current();

        let diff = GeneratedDiff::renamed(&old_path, &new_path, &["fn added() {}"]);
        assert!(diff.file_paths.contains(&new_path));
        let expected = format!("rename to {}", new_path);
        assert!(diff.text.contains(&expected));
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn empty_file_path_handled() {
    let diff = DiffBuilder::new()
        .file("")
        .hunk(1, 0, 1, 1)
        .add_line("test")
        .done()
        .done()
        .build();

    assert!(diff.contains("diff --git"));
}

#[test]
fn hunk_with_zero_counts_handled() {
    let diff = DiffBuilder::new()
        .file("test.rs")
        .hunk(0, 0, 1, 1)
        .add_line("new line")
        .done()
        .done()
        .build();

    assert!(diff.contains("@@ -0,0 +1,1 @@"));
}

#[test]
fn mixed_line_types_at_boundary() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let removed = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let context = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let added = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let hunk = HunkBuilder::new(1, 1, 1, 1)
            .remove(&removed)
            .context(&context)
            .add_line(&added);
        let output = hunk.build();

        assert!(output.contains(&format!("-{}", removed)));
        assert!(output.contains(&format!(" {}", context)));
        assert!(output.contains(&format!("+{}", added)));
    }
}

// =============================================================================
// build_for_scope Invariants
// =============================================================================

#[test]
fn build_for_scope_with_various_scopes() {
    let mut runner = TestRunner::default();

    for _ in 0..100 {
        let path = arb_file_path().new_tree(&mut runner).unwrap().current();
        let content = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();

        use diffguard_types::Scope;

        let diff1 = DiffBuilder::new()
            .file(&path)
            .hunk(1, 0, 1, 1)
            .add_line(&content)
            .done()
            .done()
            .build();

        let diff2 = DiffBuilder::new()
            .file(&path)
            .hunk(1, 0, 1, 1)
            .add_line(&content)
            .done()
            .done()
            .build_for_scope(Scope::Added);

        assert_eq!(diff1, diff2);
    }
}
