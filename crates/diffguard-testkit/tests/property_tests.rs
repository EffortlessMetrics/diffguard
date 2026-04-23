//! Property-based tests for diff_builder module.
//!
//! These tests verify invariants that should hold across all inputs,
//! not just specific examples.

use diffguard_testkit::diff_builder::{DiffBuilder, FileBuilder, GeneratedDiff, HunkBuilder};
use diffguard_testkit::arb::{arb_file_path, arb_safe_line_content};
use proptest::prelude::*;

// =============================================================================
// Bounds Tests - Verify documented limits are enforced
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: Adding MAX_FILES files should succeed.
    #[test]
    fn can_add_exactly_max_files(path in arb_file_path()) {
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
        prop_assert!(result.contains("diff --git"));
    }

    // Property: Adding MAX_HUNKS_PER_FILE hunks should succeed.
    #[test]
    fn can_add_exactly_max_hunks_per_file(line in arb_safe_line_content()) {
        let mut file = FileBuilder::new("test.rs");
        for i in 0..5 {
            let hunk = HunkBuilder::new(i as u32 + 1, 1, i as u32 + 1, 1)
                .context(&format!("{}{}", line, i));
            file = file.add_hunk(hunk);
        }
        let result = file.build();
        // Should contain all 5 hunks
        let count = result.matches("@@").count();
        prop_assert_eq!(count, 5);
    }

    // Property: Adding MAX_LINES_PER_HUNK lines should succeed.
    #[test]
    fn can_add_exactly_max_lines_per_hunk(line in arb_safe_line_content()) {
        let hunk = HunkBuilder::new(1, 1, 1, 20);
        // Adding exactly MAX_LINES_PER_HUNK lines should succeed
        let result = (0..20).fold(hunk, |h, i| {
            h.add_line(&format!("{}{}", line, i))
        }).build();
        prop_assert!(result.contains('+'));
    }

    // Property: Adding line at exactly MAX_LINE_LENGTH should succeed.
    #[test]
    fn can_add_line_at_max_line_length() {
        // 200 byte line should be allowed
        let line: String = "x".repeat(200);
        let hunk = HunkBuilder::new(1, 0, 1, 1)
            .add_line(&line);
        let result = hunk.build();
        let expected = format!("+{}", line);
        prop_assert!(result.contains(&expected));
    }
}

// =============================================================================
// Format Well-Formedness Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: Every diff should start with valid git diff header.
    #[test]
    fn diff_starts_with_git_header(path in arb_file_path()) {
        let diff = DiffBuilder::new()
            .file(&path)
            .hunk(1, 0, 1, 1)
            .add_line("test")
            .done()
            .done()
            .build();

        let expected_header = format!("diff --git a/{} b/{}", path, path);
        prop_assert!(diff.starts_with(&expected_header));
    }

    // Property: Every hunk header should have valid unified diff format.
    #[test]
    fn hunk_headers_are_valid_unified_format(
        old_start in 0u32..1000,
        old_count in 0u32..100,
        new_start in 0u32..1000,
        new_count in 0u32..100
    ) {
        let hunk = HunkBuilder::new(old_start, old_count, new_start, new_count)
            .add_line("test")
            .build();

        let expected_header = format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@");
        prop_assert!(hunk.contains(&expected_header));
    }

    // Property: Added lines should start with '+'.
    #[test]
    fn added_lines_start_with_plus(content in arb_safe_line_content()) {
        let hunk = HunkBuilder::new(1, 0, 1, 1)
            .add_line(&content)
            .build();

        let expected = format!("+{}", content);
        prop_assert!(hunk.contains(&expected));
    }

    // Property: Removed lines should start with '-'.
    #[test]
    fn removed_lines_start_with_minus(content in arb_safe_line_content()) {
        let hunk = HunkBuilder::new(1, 1, 1, 0)
            .remove(&content)
            .build();

        let expected = format!("-{}", content);
        prop_assert!(hunk.contains(&expected));
    }

    // Property: Context lines should start with ' ' (space).
    #[test]
    fn context_lines_start_with_space(content in arb_safe_line_content()) {
        let hunk = HunkBuilder::new(1, 1, 1, 1)
            .context(&content)
            .build();

        let expected = format!(" {}", content);
        prop_assert!(hunk.contains(&expected));
    }
}

// =============================================================================
// Structure Invariants
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: Multi-file diffs should contain all added files.
    #[test]
    fn multi_file_diff_contains_all_files(
        path1 in arb_file_path(),
        path2 in arb_file_path()
    ) {
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
        prop_assert!(diff.contains(&expected1));
        prop_assert!(diff.contains(&expected2));
    }

    // Property: Each file's hunks should appear in the file's diff section.
    #[test]
    fn file_contains_its_hunks(path in arb_file_path()) {
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
        let file_section_start = diff.find(&format!("diff --git a/{} b/{}", path, path))
            .expect("file header should exist");
        let file_section = &diff[file_section_start..];

        prop_assert!(file_section.contains("@@ -10,2 +20,3 @@"));
    }

    // Property: Adding binary flag should produce binary file indicator.
    #[test]
    fn binary_file_contains_binary_indicator(path in arb_file_path()) {
        let diff = DiffBuilder::new()
            .file(&path)
            .binary()
            .done()
            .build();

        prop_assert!(diff.contains("Binary files"));
        prop_assert!(diff.contains("differ"));
    }

    // Property: Deleted file should contain deleted file mode marker.
    #[test]
    fn deleted_file_contains_deleted_mode_marker(path in arb_file_path()) {
        let file = FileBuilder::new(&path)
            .deleted()
            .add_hunk(HunkBuilder::new(1, 1, 1, 0).remove("fn old() {}"));
        let diff = DiffBuilder::new().add_file(file).build();

        prop_assert!(diff.contains("deleted file mode"));
        let expected = format!("--- a/{}", path);
        prop_assert!(diff.contains(&expected));
        prop_assert!(diff.contains("+++ /dev/null"));
    }

    // Property: New file should contain new file mode marker.
    #[test]
    fn new_file_contains_new_file_mode_marker(path in arb_file_path()) {
        let diff = DiffBuilder::new()
            .file(&path)
            .new_file()
            .hunk(0, 0, 1, 1)
            .add_line("fn new() {}")
            .done()
            .done()
            .build();

        prop_assert!(diff.contains("new file mode"));
        prop_assert!(diff.contains("--- /dev/null"));
        let expected = format!("+++ b/{}", path);
        prop_assert!(diff.contains(&expected));
    }

    // Property: Rename should contain rename markers.
    #[test]
    fn rename_contains_rename_markers(
        old_path in arb_file_path(),
        new_path in arb_file_path()
    ) {
        let file = FileBuilder::new(&new_path)
            .rename_from(&old_path)
            .add_hunk(HunkBuilder::new(1, 1, 1, 2)
                .context("unchanged")
                .add_line("added"));
        let diff = DiffBuilder::new().add_file(file).build();

        prop_assert!(diff.contains("similarity index 90%"));
        let rename_from = format!("rename from {}", old_path);
        let rename_to = format!("rename to {}", new_path);
        prop_assert!(diff.contains(&rename_from));
        prop_assert!(diff.contains(&rename_to));
    }

    // Property: Mode change should contain old and new mode.
    #[test]
    fn mode_change_contains_modes(
        path in arb_file_path(),
        old_mode in prop::sample::select(vec!["100644", "100755", "100600"]),
        new_mode in prop::sample::select(vec!["100644", "100755", "100600"])
    ) {
        let diff = DiffBuilder::new()
            .file(&path)
            .mode_change(&old_mode, &new_mode)
            .done()
            .build();

        let old_mode_line = format!("old mode {}", old_mode);
        let new_mode_line = format!("new mode {}", new_mode);
        prop_assert!(diff.contains(&old_mode_line));
        prop_assert!(diff.contains(&new_mode_line));
    }
}

// =============================================================================
// GeneratedDiff Helper Invariants
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: GeneratedDiff::with_additions should report correct added line count.
    #[test]
    fn generated_diff_additions_line_count(
        path in arb_file_path(),
        lines in prop::collection::vec(arb_safe_line_content(), 1..10)
    ) {
        let lines_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let diff = GeneratedDiff::with_additions(&path, &lines_refs);
        prop_assert_eq!(diff.expected_added_lines, lines.len());
        prop_assert_eq!(diff.expected_files, 1);
    }

    // Property: GeneratedDiff::with_changes should report correct changed line count.
    #[test]
    fn generated_diff_changes_line_count(
        path in arb_file_path(),
        removed in prop::collection::vec(arb_safe_line_content(), 1..5),
        added in prop::collection::vec(arb_safe_line_content(), 1..5)
    ) {
        let removed_refs: Vec<&str> = removed.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let added_refs: Vec<&str> = added.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let diff = GeneratedDiff::with_changes(&path, &removed_refs, &added_refs);
        prop_assert_eq!(diff.expected_added_lines, added.len());
        prop_assert_eq!(diff.expected_changed_lines, added.len());
    }

    // Property: GeneratedDiff should contain the added content.
    #[test]
    fn generated_diff_additions_contains_content(
        path in arb_file_path(),
        lines in prop::collection::vec(arb_safe_line_content(), 1..5)
    ) {
        let lines_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let diff = GeneratedDiff::with_additions(&path, &lines_refs);
        for line in &lines {
            let expected = format!("+{}", line);
            prop_assert!(diff.text.contains(&expected), "Diff should contain +{}", line);
        }
    }

    // Property: GeneratedDiff::renamed should track the new path.
    #[test]
    fn generated_diff_renamed_new_path(
        old_path in arb_file_path(),
        new_path in arb_file_path()
    ) {
        let diff = GeneratedDiff::renamed(&old_path, &new_path, &["fn added() {}"]);
        prop_assert!(diff.file_paths.contains(&new_path));
        let expected = format!("rename to {}", new_path);
        prop_assert!(diff.text.contains(&expected));
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: Empty file path should still produce valid output.
    #[test]
    fn empty_file_path_handled() {
        let diff = DiffBuilder::new()
            .file("")
            .hunk(1, 0, 1, 1)
            .add_line("test")
            .done()
            .done()
            .build();

        prop_assert!(diff.contains("diff --git"));
    }

    // Property: Zero counts in hunk header should be handled.
    #[test]
    fn hunk_with_zero_counts_handled() {
        let diff = DiffBuilder::new()
            .file("test.rs")
            .hunk(0, 0, 1, 1)
            .add_line("new line")
            .done()
            .done()
            .build();

        prop_assert!(diff.contains("@@ -0,0 +1,1 @@"));
    }

    // Property: Mixed line types should all appear.
    #[test]
    fn mixed_line_types_at_boundary(
        removed in arb_safe_line_content(),
        context in arb_safe_line_content(),
        added in arb_safe_line_content()
    ) {
        let hunk = HunkBuilder::new(1, 1, 1, 1)
            .remove(&removed)
            .context(&context)
            .add_line(&added);
        let output = hunk.build();

        prop_assert!(output.contains(&format!("-{}", removed)));
        prop_assert!(output.contains(&format!(" {}", context)));
        prop_assert!(output.contains(&format!("+{}", added)));
    }
}

// =============================================================================
// build_for_scope Invariants
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Property: build_for_scope should produce same output as build.
    #[test]
    fn build_for_scope_with_various_scopes(
        path in arb_file_path(),
        content in arb_safe_line_content()
    ) {
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

        prop_assert_eq!(diff1, diff2);
    }
}
