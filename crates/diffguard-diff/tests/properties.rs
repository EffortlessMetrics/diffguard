//! Property-based tests for diffguard-diff
//!
//! Feature: diffguard-completion
//!
//! These tests verify the enhanced diff parsing functionality for handling
//! special cases like binary files, submodules, renames, and malformed content.
//!
//! Feature: comprehensive-test-coverage
//!
//! These tests also verify diff parsing consistency and correctness properties.

use proptest::prelude::*;

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

// ============================================================================
// Strategies for generating diff content
// ============================================================================

/// Strategy to generate valid file paths (alphanumeric with slashes)
fn file_path_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{0,15}").expect("valid regex"),
        1..4,
    )
    .prop_map(|parts| parts.join("/"))
    .prop_filter("path must not be empty", |p| !p.is_empty())
}

/// Strategy to generate file extensions
fn extension_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "rs", "py", "js", "ts", "go", "java", "rb", "c", "cpp", "txt", "md",
    ])
    .prop_map(|s| s.to_string())
}

/// Strategy to generate a full file path with extension
fn full_path_strategy() -> impl Strategy<Value = String> {
    (file_path_strategy(), extension_strategy()).prop_map(|(path, ext)| format!("{}.{}", path, ext))
}

/// Strategy to generate valid line content (no special diff characters at start)
fn line_content_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_(){}\\[\\];:,.<>=+\\-*/& ]{0,80}")
        .expect("valid regex")
        .prop_filter("must not start with diff markers", |s| {
            !s.starts_with('+')
                && !s.starts_with('-')
                && !s.starts_with('@')
                && !s.starts_with(' ')
                && !s.starts_with('\\')
        })
}

/// Strategy to generate a valid hunk header
fn hunk_header_strategy(new_start: u32, new_count: u32) -> String {
    format!("@@ -1,1 +{},{} @@", new_start, new_count)
}

/// Strategy to generate git commit hashes (40 hex chars)
fn commit_hash_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[0-9a-f]{40}").expect("valid regex")
}

/// Strategy to generate file modes
fn file_mode_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["100644", "100755", "120000", "160000"]).prop_map(|s| s.to_string())
}

// ============================================================================
// Helper functions to generate diff content
// ============================================================================

/// Generate a standard diff header for a file
fn make_diff_header(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         --- a/{path}\n\
         +++ b/{path}",
        path = path
    )
}

/// Generate a diff with added lines
fn make_diff_with_added_lines(path: &str, lines: &[&str]) -> String {
    let header = make_diff_header(path);
    let hunk = hunk_header_strategy(1, lines.len() as u32);
    let content: String = lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!("{}\n{}\n{}", header, hunk, content)
}

/// Generate a binary file diff
fn make_binary_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         Binary files a/{path} and b/{path} differ",
        path = path
    )
}

/// Generate a submodule diff
fn make_submodule_diff(path: &str, old_commit: &str, new_commit: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index {old_short}..{new_short} 160000\n\
         --- a/{path}\n\
         +++ b/{path}\n\
         @@ -1 +1 @@\n\
         -Subproject commit {old_commit}\n\
         +Subproject commit {new_commit}",
        path = path,
        old_short = &old_commit[..7],
        new_short = &new_commit[..7],
        old_commit = old_commit,
        new_commit = new_commit
    )
}

/// Generate a deleted file diff
fn make_deleted_file_diff(path: &str, mode: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         deleted file mode {mode}\n\
         index 1111111..0000000\n\
         --- a/{path}\n\
         +++ /dev/null\n\
         @@ -1,1 +0,0 @@\n\
         -fn deleted() {{}}",
        path = path,
        mode = mode
    )
}

/// Generate a mode-only change diff
fn make_mode_change_diff(path: &str, old_mode: &str, new_mode: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         old mode {old_mode}\n\
         new mode {new_mode}",
        path = path,
        old_mode = old_mode,
        new_mode = new_mode
    )
}

/// Generate a rename diff with content changes
fn make_rename_diff(old_path: &str, new_path: &str, added_lines: &[&str]) -> String {
    let hunk = hunk_header_strategy(1, added_lines.len() as u32 + 1);
    let content: String = added_lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!(
        "diff --git a/{old_path} b/{new_path}\n\
         similarity index 90%\n\
         rename from {old_path}\n\
         rename to {new_path}\n\
         --- a/{old_path}\n\
         +++ b/{new_path}\n\
         {hunk}\n\
         fn existing() {{}}\n\
         {content}",
        old_path = old_path,
        new_path = new_path,
        hunk = hunk,
        content = content
    )
}

// ============================================================================
// Property 3: Diff Parsing Consistency
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property 3: Diff Parsing Consistency
// For any well-formed unified diff string, calling `parse_unified_diff` twice
// with the same scope SHALL return identical results (same DiffLines in same order).
// **Validates: Requirements 2.1**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: comprehensive-test-coverage, Property 3: Diff Parsing Consistency
    // Parsing the same diff twice with Scope::Added should return identical results
    // **Validates: Requirements 2.1**
    #[test]
    fn property_parse_consistency_added_scope(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        // Filter out empty lines
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        // Create a well-formed diff
        let diff = make_diff_with_added_lines(&path, &non_empty_lines);

        // Parse the diff twice with the same scope
        let result1 = parse_unified_diff(&diff, Scope::Added);
        let result2 = parse_unified_diff(&diff, Scope::Added);

        // Both parses should succeed
        prop_assert!(
            result1.is_ok(),
            "First parse should succeed, but got error: {:?}",
            result1.err()
        );
        prop_assert!(
            result2.is_ok(),
            "Second parse should succeed, but got error: {:?}",
            result2.err()
        );

        let (lines1, stats1) = result1.unwrap();
        let (lines2, stats2) = result2.unwrap();

        // Property: Both parses should return the same number of lines
        prop_assert_eq!(
            lines1.len(),
            lines2.len(),
            "Both parses should return the same number of lines, but got {} vs {}",
            lines1.len(),
            lines2.len()
        );

        // Property: Both parses should return identical DiffStats
        prop_assert_eq!(
            stats1.files,
            stats2.files,
            "Both parses should return the same file count, but got {} vs {}",
            stats1.files,
            stats2.files
        );
        prop_assert_eq!(
            stats1.lines,
            stats2.lines,
            "Both parses should return the same line count, but got {} vs {}",
            stats1.lines,
            stats2.lines
        );

        // Property: Both parses should return lines in the same order with identical content
        for (i, (line1, line2)) in lines1.iter().zip(lines2.iter()).enumerate() {
            prop_assert_eq!(
                &line1.path,
                &line2.path,
                "Line {} should have the same path, but got '{}' vs '{}'",
                i,
                line1.path,
                line2.path
            );
            prop_assert_eq!(
                line1.line,
                line2.line,
                "Line {} should have the same line number, but got {} vs {}",
                i,
                line1.line,
                line2.line
            );
            prop_assert_eq!(
                &line1.content,
                &line2.content,
                "Line {} should have the same content, but got '{}' vs '{}'",
                i,
                line1.content,
                line2.content
            );
        }
    }

    // Feature: comprehensive-test-coverage, Property 3: Diff Parsing Consistency
    // Parsing the same diff twice with Scope::Changed should return identical results
    // **Validates: Requirements 2.1**
    #[test]
    fn property_parse_consistency_changed_scope(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        // Filter out empty lines
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        // Create a well-formed diff
        let diff = make_diff_with_added_lines(&path, &non_empty_lines);

        // Parse the diff twice with the same scope
        let result1 = parse_unified_diff(&diff, Scope::Changed);
        let result2 = parse_unified_diff(&diff, Scope::Changed);

        // Both parses should succeed
        prop_assert!(
            result1.is_ok(),
            "First parse should succeed, but got error: {:?}",
            result1.err()
        );
        prop_assert!(
            result2.is_ok(),
            "Second parse should succeed, but got error: {:?}",
            result2.err()
        );

        let (lines1, stats1) = result1.unwrap();
        let (lines2, stats2) = result2.unwrap();

        // Property: Both parses should return the same number of lines
        prop_assert_eq!(
            lines1.len(),
            lines2.len(),
            "Both parses should return the same number of lines, but got {} vs {}",
            lines1.len(),
            lines2.len()
        );

        // Property: Both parses should return identical DiffStats
        prop_assert_eq!(
            stats1.files,
            stats2.files,
            "Both parses should return the same file count, but got {} vs {}",
            stats1.files,
            stats2.files
        );
        prop_assert_eq!(
            stats1.lines,
            stats2.lines,
            "Both parses should return the same line count, but got {} vs {}",
            stats1.lines,
            stats2.lines
        );

        // Property: Both parses should return lines in the same order with identical content
        for (i, (line1, line2)) in lines1.iter().zip(lines2.iter()).enumerate() {
            prop_assert_eq!(
                &line1.path,
                &line2.path,
                "Line {} should have the same path, but got '{}' vs '{}'",
                i,
                line1.path,
                line2.path
            );
            prop_assert_eq!(
                line1.line,
                line2.line,
                "Line {} should have the same line number, but got {} vs {}",
                i,
                line1.line,
                line2.line
            );
            prop_assert_eq!(
                &line1.content,
                &line2.content,
                "Line {} should have the same content, but got '{}' vs '{}'",
                i,
                line1.content,
                line2.content
            );
        }
    }

    // Feature: comprehensive-test-coverage, Property 3: Diff Parsing Consistency
    // Parsing a multi-file diff twice should return identical results
    // **Validates: Requirements 2.1**
    #[test]
    fn property_parse_consistency_multi_file(
        path1 in full_path_strategy(),
        path2 in full_path_strategy(),
        lines1 in prop::collection::vec(line_content_strategy(), 1..3),
        lines2 in prop::collection::vec(line_content_strategy(), 1..3),
    ) {
        // Ensure paths are different
        prop_assume!(path1 != path2);

        // Filter out empty lines
        let non_empty_lines1: Vec<&str> = lines1.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_lines2: Vec<&str> = lines2.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines1.is_empty());
        prop_assume!(!non_empty_lines2.is_empty());

        // Create a well-formed multi-file diff
        let diff1 = make_diff_with_added_lines(&path1, &non_empty_lines1);
        let diff2 = make_diff_with_added_lines(&path2, &non_empty_lines2);
        let combined = format!("{}\n{}", diff1, diff2);

        // Parse the diff twice with the same scope
        let result1 = parse_unified_diff(&combined, Scope::Added);
        let result2 = parse_unified_diff(&combined, Scope::Added);

        // Both parses should succeed
        prop_assert!(
            result1.is_ok(),
            "First parse should succeed, but got error: {:?}",
            result1.err()
        );
        prop_assert!(
            result2.is_ok(),
            "Second parse should succeed, but got error: {:?}",
            result2.err()
        );

        let (parsed_lines1, stats1) = result1.unwrap();
        let (parsed_lines2, stats2) = result2.unwrap();

        // Property: Both parses should return the same number of lines
        prop_assert_eq!(
            parsed_lines1.len(),
            parsed_lines2.len(),
            "Both parses should return the same number of lines, but got {} vs {}",
            parsed_lines1.len(),
            parsed_lines2.len()
        );

        // Property: Both parses should return identical DiffStats
        prop_assert_eq!(
            stats1.files,
            stats2.files,
            "Both parses should return the same file count, but got {} vs {}",
            stats1.files,
            stats2.files
        );
        prop_assert_eq!(
            stats1.lines,
            stats2.lines,
            "Both parses should return the same line count, but got {} vs {}",
            stats1.lines,
            stats2.lines
        );

        // Property: Both parses should return lines in the same order with identical content
        for (i, (line1, line2)) in parsed_lines1.iter().zip(parsed_lines2.iter()).enumerate() {
            prop_assert_eq!(
                &line1.path,
                &line2.path,
                "Line {} should have the same path, but got '{}' vs '{}'",
                i,
                line1.path,
                line2.path
            );
            prop_assert_eq!(
                line1.line,
                line2.line,
                "Line {} should have the same line number, but got {} vs {}",
                i,
                line1.line,
                line2.line
            );
            prop_assert_eq!(
                &line1.content,
                &line2.content,
                "Line {} should have the same content, but got '{}' vs '{}'",
                i,
                line1.content,
                line2.content
            );
        }
    }
}

// ============================================================================
// Property 6: Diff Parser Skips Special Files
// ============================================================================
//
// Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
// For any unified diff containing binary file markers, submodule commits,
// mode-only changes, or deleted file markers, the `parse_unified_diff` function
// SHALL return successfully with no lines extracted from those special files.
// **Validates: Requirements 4.1, 4.2, 4.4, 4.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
    // Binary files should be skipped
    // **Validates: Requirements 4.1**
    #[test]
    fn property_binary_files_skipped(
        binary_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(binary_path != normal_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a binary file followed by a normal file
        let binary_diff = make_binary_diff(&binary_path);
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&line_content]);
        let combined = format!("{}\n{}", binary_diff, normal_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines should be extracted from the binary file
        let binary_lines: Vec<_> = lines.iter().filter(|l| l.path == binary_path).collect();
        prop_assert!(
            binary_lines.is_empty(),
            "No lines should be extracted from binary file '{}', but found {:?}",
            binary_path,
            binary_lines
        );

        // Property: lines from normal file should still be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}', but found none",
            normal_path
        );
    }


    // Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
    // Submodule changes should be skipped
    // **Validates: Requirements 4.2**
    #[test]
    fn property_submodule_changes_skipped(
        submodule_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        old_commit in commit_hash_strategy(),
        new_commit in commit_hash_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different and commits are different
        prop_assume!(submodule_path != normal_path);
        prop_assume!(old_commit != new_commit);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a submodule change followed by a normal file
        let submodule_diff = make_submodule_diff(&submodule_path, &old_commit, &new_commit);
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&line_content]);
        let combined = format!("{}\n{}", submodule_diff, normal_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines should be extracted from the submodule
        let submodule_lines: Vec<_> = lines.iter().filter(|l| l.path == submodule_path).collect();
        prop_assert!(
            submodule_lines.is_empty(),
            "No lines should be extracted from submodule '{}', but found {:?}",
            submodule_path,
            submodule_lines
        );

        // Property: lines from normal file should still be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}', but found none",
            normal_path
        );
    }


    // Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
    // Deleted files should be skipped
    // **Validates: Requirements 4.5**
    #[test]
    fn property_deleted_files_skipped(
        deleted_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        mode in file_mode_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(deleted_path != normal_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a deleted file followed by a normal file
        let deleted_diff = make_deleted_file_diff(&deleted_path, &mode);
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&line_content]);
        let combined = format!("{}\n{}", deleted_diff, normal_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines should be extracted from the deleted file
        let deleted_lines: Vec<_> = lines.iter().filter(|l| l.path == deleted_path).collect();
        prop_assert!(
            deleted_lines.is_empty(),
            "No lines should be extracted from deleted file '{}', but found {:?}",
            deleted_path,
            deleted_lines
        );

        // Property: lines from normal file should still be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}', but found none",
            normal_path
        );
    }


    // Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
    // Mode-only changes should be skipped
    // **Validates: Requirements 4.4**
    #[test]
    fn property_mode_only_changes_skipped(
        mode_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(mode_path != normal_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a mode-only change followed by a normal file
        let mode_diff = make_mode_change_diff(&mode_path, "100644", "100755");
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&line_content]);
        let combined = format!("{}\n{}", mode_diff, normal_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines should be extracted from the mode-only change
        let mode_lines: Vec<_> = lines.iter().filter(|l| l.path == mode_path).collect();
        prop_assert!(
            mode_lines.is_empty(),
            "No lines should be extracted from mode-only change '{}', but found {:?}",
            mode_path,
            mode_lines
        );

        // Property: lines from normal file should still be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}', but found none",
            normal_path
        );
    }


    // Feature: diffguard-completion, Property 6: Diff Parser Skips Special Files
    // Combined test: multiple special file types in one diff
    // **Validates: Requirements 4.1, 4.2, 4.4, 4.5**
    #[test]
    fn property_multiple_special_files_all_skipped(
        binary_path in full_path_strategy(),
        deleted_path in full_path_strategy(),
        mode_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        mode in file_mode_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure all paths are different
        prop_assume!(binary_path != deleted_path);
        prop_assume!(binary_path != mode_path);
        prop_assume!(binary_path != normal_path);
        prop_assume!(deleted_path != mode_path);
        prop_assume!(deleted_path != normal_path);
        prop_assume!(mode_path != normal_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with multiple special files followed by a normal file
        let binary_diff = make_binary_diff(&binary_path);
        let deleted_diff = make_deleted_file_diff(&deleted_path, &mode);
        let mode_diff = make_mode_change_diff(&mode_path, "100644", "100755");
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&line_content]);
        let combined = format!(
            "{}\n{}\n{}\n{}",
            binary_diff, deleted_diff, mode_diff, normal_diff
        );

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines from any special file
        for special_path in [&binary_path, &deleted_path, &mode_path] {
            let special_lines: Vec<_> = lines.iter().filter(|l| &l.path == special_path).collect();
            prop_assert!(
                special_lines.is_empty(),
                "No lines should be extracted from special file '{}', but found {:?}",
                special_path,
                special_lines
            );
        }

        // Property: lines from normal file should still be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}', but found none",
            normal_path
        );
    }
}

// ============================================================================
// Property 7: Diff Parser Handles Renames
// ============================================================================
//
// Feature: diffguard-completion, Property 7: Diff Parser Handles Renames
// For any unified diff containing a file rename, the `parse_unified_diff` function
// SHALL use the new (destination) path for all extracted lines from that file.
// **Validates: Requirements 4.3**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: diffguard-completion, Property 7: Diff Parser Handles Renames
    // Renamed files should use the new path
    // **Validates: Requirements 4.3**
    #[test]
    fn property_renamed_files_use_new_path(
        old_path in full_path_strategy(),
        new_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(old_path != new_path);
        prop_assume!(!line_content.is_empty());

        // Create a rename diff with added content
        let rename_diff = make_rename_diff(&old_path, &new_path, &[&line_content]);

        let result = parse_unified_diff(&rename_diff, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: no lines should use the old path
        let old_path_lines: Vec<_> = lines.iter().filter(|l| l.path == old_path).collect();
        prop_assert!(
            old_path_lines.is_empty(),
            "No lines should use old path '{}', but found {:?}",
            old_path,
            old_path_lines
        );

        // Property: all extracted lines should use the new path
        for line in &lines {
            prop_assert_eq!(
                &line.path,
                &new_path,
                "All lines should use new path '{}', but found line with path '{}'",
                new_path,
                line.path
            );
        }
    }


    // Feature: diffguard-completion, Property 7: Diff Parser Handles Renames
    // Renamed files with multiple added lines should all use the new path
    // **Validates: Requirements 4.3**
    #[test]
    fn property_renamed_files_multiple_lines_use_new_path(
        old_path in full_path_strategy(),
        new_path in full_path_strategy(),
        line1 in line_content_strategy(),
        line2 in line_content_strategy(),
        line3 in line_content_strategy(),
    ) {
        // Ensure paths are different and we have content
        prop_assume!(old_path != new_path);
        prop_assume!(!line1.is_empty() || !line2.is_empty() || !line3.is_empty());

        // Filter out empty lines
        let lines: Vec<&str> = [line1.as_str(), line2.as_str(), line3.as_str()]
            .into_iter()
            .filter(|l| !l.is_empty())
            .collect();

        if lines.is_empty() {
            return Ok(());
        }

        // Create a rename diff with multiple added lines
        let rename_diff = make_rename_diff(&old_path, &new_path, &lines);

        let result = parse_unified_diff(&rename_diff, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (parsed_lines, _stats) = result.unwrap();

        // Property: all extracted lines should use the new path
        for line in &parsed_lines {
            prop_assert_eq!(
                &line.path,
                &new_path,
                "All lines should use new path '{}', but found line with path '{}'",
                new_path,
                line.path
            );
        }
    }

    // Feature: diffguard-completion, Property 7: Diff Parser Handles Renames
    // Renamed file followed by normal file should both be parsed correctly
    // **Validates: Requirements 4.3**
    #[test]
    fn property_renamed_and_normal_files_parsed_correctly(
        old_path in full_path_strategy(),
        new_path in full_path_strategy(),
        normal_path in full_path_strategy(),
        rename_content in line_content_strategy(),
        normal_content in line_content_strategy(),
    ) {
        // Ensure all paths are different
        prop_assume!(old_path != new_path);
        prop_assume!(old_path != normal_path);
        prop_assume!(new_path != normal_path);
        prop_assume!(!rename_content.is_empty());
        prop_assume!(!normal_content.is_empty());

        // Create a diff with a renamed file followed by a normal file
        let rename_diff = make_rename_diff(&old_path, &new_path, &[&rename_content]);
        let normal_diff = make_diff_with_added_lines(&normal_path, &[&normal_content]);
        let combined = format!("{}\n{}", rename_diff, normal_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: renamed file lines should use new path
        let renamed_lines: Vec<_> = lines.iter().filter(|l| l.path == new_path).collect();
        prop_assert!(
            !renamed_lines.is_empty(),
            "Lines should be extracted from renamed file with new path '{}'",
            new_path
        );

        // Property: no lines should use old path
        let old_path_lines: Vec<_> = lines.iter().filter(|l| l.path == old_path).collect();
        prop_assert!(
            old_path_lines.is_empty(),
            "No lines should use old path '{}', but found {:?}",
            old_path,
            old_path_lines
        );

        // Property: normal file lines should be extracted
        let normal_lines: Vec<_> = lines.iter().filter(|l| l.path == normal_path).collect();
        prop_assert!(
            !normal_lines.is_empty(),
            "Lines should be extracted from normal file '{}'",
            normal_path
        );
    }
}

// ============================================================================
// Property 8: Diff Parser Resilience
// ============================================================================
//
// Feature: diffguard-completion, Property 8: Diff Parser Resilience
// For any unified diff where malformed content appears after a valid file header,
// the `parse_unified_diff` function SHALL continue processing and extract lines
// from subsequent valid files.
// **Validates: Requirements 4.6**

/// Generate a malformed hunk header
fn make_malformed_hunk_header() -> &'static str {
    "@@ malformed hunk header without proper format"
}

/// Generate a diff with a malformed hunk header
fn make_malformed_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         --- a/{path}\n\
         +++ b/{path}\n\
         {malformed}\n\
         +this line should be skipped",
        path = path,
        malformed = make_malformed_hunk_header()
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: diffguard-completion, Property 8: Diff Parser Resilience
    // Malformed hunk headers should not stop processing of subsequent files
    // **Validates: Requirements 4.6**
    #[test]
    fn property_continues_after_malformed_hunk(
        malformed_path in full_path_strategy(),
        valid_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(malformed_path != valid_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a malformed file followed by a valid file
        let malformed_diff = make_malformed_diff(&malformed_path);
        let valid_diff = make_diff_with_added_lines(&valid_path, &[&line_content]);
        let combined = format!("{}\n{}", malformed_diff, valid_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed (not return an error)
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed despite malformed content, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: lines from the valid file should be extracted
        let valid_lines: Vec<_> = lines.iter().filter(|l| l.path == valid_path).collect();
        prop_assert!(
            !valid_lines.is_empty(),
            "Lines should be extracted from valid file '{}' after malformed content, but found none",
            valid_path
        );
    }


    // Feature: diffguard-completion, Property 8: Diff Parser Resilience
    // Multiple malformed files should not stop processing of subsequent valid files
    // **Validates: Requirements 4.6**
    #[test]
    fn property_continues_after_multiple_malformed_hunks(
        malformed_path1 in full_path_strategy(),
        malformed_path2 in full_path_strategy(),
        valid_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure all paths are different
        prop_assume!(malformed_path1 != malformed_path2);
        prop_assume!(malformed_path1 != valid_path);
        prop_assume!(malformed_path2 != valid_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with multiple malformed files followed by a valid file
        let malformed_diff1 = make_malformed_diff(&malformed_path1);
        let malformed_diff2 = make_malformed_diff(&malformed_path2);
        let valid_diff = make_diff_with_added_lines(&valid_path, &[&line_content]);
        let combined = format!("{}\n{}\n{}", malformed_diff1, malformed_diff2, valid_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed despite multiple malformed files, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: lines from the valid file should be extracted
        let valid_lines: Vec<_> = lines.iter().filter(|l| l.path == valid_path).collect();
        prop_assert!(
            !valid_lines.is_empty(),
            "Lines should be extracted from valid file '{}' after malformed content, but found none",
            valid_path
        );
    }

    // Feature: diffguard-completion, Property 8: Diff Parser Resilience
    // Valid file before malformed file should still be parsed
    // **Validates: Requirements 4.6**
    #[test]
    fn property_valid_file_before_malformed_is_parsed(
        valid_path in full_path_strategy(),
        malformed_path in full_path_strategy(),
        line_content in line_content_strategy(),
    ) {
        // Ensure paths are different
        prop_assume!(valid_path != malformed_path);
        prop_assume!(!line_content.is_empty());

        // Create a diff with a valid file followed by a malformed file
        let valid_diff = make_diff_with_added_lines(&valid_path, &[&line_content]);
        let malformed_diff = make_malformed_diff(&malformed_path);
        let combined = format!("{}\n{}", valid_diff, malformed_diff);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, _stats) = result.unwrap();

        // Property: lines from the valid file should be extracted
        let valid_lines: Vec<_> = lines.iter().filter(|l| l.path == valid_path).collect();
        prop_assert!(
            !valid_lines.is_empty(),
            "Lines should be extracted from valid file '{}', but found none",
            valid_path
        );
    }


    // Feature: diffguard-completion, Property 8: Diff Parser Resilience
    // Interleaved valid and malformed files should all be handled correctly
    // **Validates: Requirements 4.6**
    #[test]
    fn property_interleaved_valid_and_malformed_files(
        valid_path1 in full_path_strategy(),
        malformed_path in full_path_strategy(),
        valid_path2 in full_path_strategy(),
        content1 in line_content_strategy(),
        content2 in line_content_strategy(),
    ) {
        // Ensure all paths are different
        prop_assume!(valid_path1 != malformed_path);
        prop_assume!(valid_path1 != valid_path2);
        prop_assume!(malformed_path != valid_path2);
        prop_assume!(!content1.is_empty());
        prop_assume!(!content2.is_empty());

        // Create a diff: valid -> malformed -> valid
        let valid_diff1 = make_diff_with_added_lines(&valid_path1, &[&content1]);
        let malformed_diff = make_malformed_diff(&malformed_path);
        let valid_diff2 = make_diff_with_added_lines(&valid_path2, &[&content2]);
        let combined = format!("{}\n{}\n{}", valid_diff1, malformed_diff, valid_diff2);

        let result = parse_unified_diff(&combined, Scope::Added);

        // Property: parsing should succeed
        prop_assert!(
            result.is_ok(),
            "Parsing should succeed, but got error: {:?}",
            result.err()
        );

        let (lines, stats) = result.unwrap();

        // Property: lines from both valid files should be extracted
        let valid1_lines: Vec<_> = lines.iter().filter(|l| l.path == valid_path1).collect();
        prop_assert!(
            !valid1_lines.is_empty(),
            "Lines should be extracted from first valid file '{}', but found none",
            valid_path1
        );

        let valid2_lines: Vec<_> = lines.iter().filter(|l| l.path == valid_path2).collect();
        prop_assert!(
            !valid2_lines.is_empty(),
            "Lines should be extracted from second valid file '{}', but found none",
            valid_path2
        );

        // Property: stats should reflect both valid files
        prop_assert_eq!(
            stats.files,
            2,
            "Stats should show 2 files, but got {}",
            stats.files
        );
    }
}

// ============================================================================
// Property 4: Scope Filtering Correctness
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
// For any unified diff, the set of lines returned by `Scope::Changed` SHALL be
// a subset of lines returned by `Scope::Added`, and for pure additions (no removed
// lines), `Scope::Changed` SHALL return empty.
// **Validates: Requirements 2.2, 2.3**

/// Generate a diff with only added lines (no removed lines)
fn make_pure_addition_diff(path: &str, lines: &[&str]) -> String {
    let header = make_diff_header(path);
    let hunk = hunk_header_strategy(1, lines.len() as u32);
    let content: String = lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!("{}\n{}\n{}", header, hunk, content)
}

/// Generate a diff with changed lines (removed followed by added)
fn make_changed_diff(path: &str, removed_lines: &[&str], added_lines: &[&str]) -> String {
    let header = make_diff_header(path);
    let total_new_lines = added_lines.len() as u32;
    let total_old_lines = removed_lines.len() as u32;
    let hunk = format!("@@ -1,{} +1,{} @@", total_old_lines, total_new_lines);
    let removed: String = removed_lines.iter().map(|l| format!("-{}\n", l)).collect();
    let added: String = added_lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!("{}\n{}\n{}{}", header, hunk, removed, added)
}

/// Generate a diff with mixed content: context, removed, and added lines
fn make_mixed_diff(
    path: &str,
    context_before: &[&str],
    removed_lines: &[&str],
    added_lines: &[&str],
    context_after: &[&str],
) -> String {
    let header = make_diff_header(path);
    let old_count = context_before.len() + removed_lines.len() + context_after.len();
    let new_count = context_before.len() + added_lines.len() + context_after.len();
    let hunk = format!("@@ -1,{} +1,{} @@", old_count, new_count);

    let ctx_before: String = context_before.iter().map(|l| format!(" {}\n", l)).collect();
    let removed: String = removed_lines.iter().map(|l| format!("-{}\n", l)).collect();
    let added: String = added_lines.iter().map(|l| format!("+{}\n", l)).collect();
    let ctx_after: String = context_after.iter().map(|l| format!(" {}\n", l)).collect();

    format!(
        "{}\n{}\n{}{}{}{}",
        header, hunk, ctx_before, removed, added, ctx_after
    )
}

/// Generate a diff with interleaved additions (some after removals, some not)
fn make_interleaved_diff(
    path: &str,
    pure_added: &[&str],
    removed: &[&str],
    changed_added: &[&str],
) -> String {
    let header = make_diff_header(path);
    let old_count = removed.len();
    let new_count = pure_added.len() + changed_added.len();
    let hunk = format!("@@ -1,{} +1,{} @@", old_count, new_count);

    // First add pure additions (not preceded by removals)
    let pure: String = pure_added.iter().map(|l| format!("+{}\n", l)).collect();
    // Then removals
    let rem: String = removed.iter().map(|l| format!("-{}\n", l)).collect();
    // Then changed additions (preceded by removals)
    let changed: String = changed_added.iter().map(|l| format!("+{}\n", l)).collect();

    format!("{}\n{}\n{}{}{}", header, hunk, pure, rem, changed)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // For pure additions (no removed lines), Scope::Changed SHALL return empty
    // **Validates: Requirements 2.2**
    #[test]
    fn property_pure_additions_return_empty_changed(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        // Filter out empty lines
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        // Create a diff with only added lines (no removals)
        let diff = make_pure_addition_diff(&path, &non_empty_lines);

        // Parse with Scope::Added - should return all lines
        let result_added = parse_unified_diff(&diff, Scope::Added);
        prop_assert!(
            result_added.is_ok(),
            "Parsing with Scope::Added should succeed, but got error: {:?}",
            result_added.err()
        );
        let (added_lines, _) = result_added.unwrap();

        // Parse with Scope::Changed - should return empty
        let result_changed = parse_unified_diff(&diff, Scope::Changed);
        prop_assert!(
            result_changed.is_ok(),
            "Parsing with Scope::Changed should succeed, but got error: {:?}",
            result_changed.err()
        );
        let (changed_lines, _) = result_changed.unwrap();

        // Property: Scope::Added should return all added lines
        prop_assert!(
            !added_lines.is_empty(),
            "Scope::Added should return lines for pure additions, but got empty"
        );

        // Property: Scope::Changed should return empty for pure additions
        prop_assert!(
            changed_lines.is_empty(),
            "Scope::Changed should return empty for pure additions (no removed lines), but got {} lines: {:?}",
            changed_lines.len(),
            changed_lines.iter().map(|l| &l.content).collect::<Vec<_>>()
        );
    }

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // Scope::Changed lines are always a subset of Scope::Added lines
    // **Validates: Requirements 2.3**
    #[test]
    fn property_changed_is_subset_of_added(
        path in full_path_strategy(),
        removed_lines in prop::collection::vec(line_content_strategy(), 1..3),
        added_lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        // Filter out empty lines
        let non_empty_removed: Vec<&str> = removed_lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_added: Vec<&str> = added_lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_removed.is_empty());
        prop_assume!(!non_empty_added.is_empty());

        // Create a diff with removed and added lines (changed content)
        let diff = make_changed_diff(&path, &non_empty_removed, &non_empty_added);

        // Parse with both scopes
        let result_added = parse_unified_diff(&diff, Scope::Added);
        let result_changed = parse_unified_diff(&diff, Scope::Changed);

        prop_assert!(result_added.is_ok(), "Parsing with Scope::Added should succeed");
        prop_assert!(result_changed.is_ok(), "Parsing with Scope::Changed should succeed");

        let (added_result, _) = result_added.unwrap();
        let (changed_result, _) = result_changed.unwrap();

        // Property: Every line in changed_result must also be in added_result
        // We compare by (path, line number, content) tuple
        let added_set: std::collections::HashSet<_> = added_result
            .iter()
            .map(|l| (&l.path, l.line, &l.content))
            .collect();

        for changed_line in &changed_result {
            let key = (&changed_line.path, changed_line.line, &changed_line.content);
            prop_assert!(
                added_set.contains(&key),
                "Changed line {:?} at line {} should be in Added results, but was not found",
                changed_line.content,
                changed_line.line
            );
        }

        // Property: Changed count should be <= Added count
        prop_assert!(
            changed_result.len() <= added_result.len(),
            "Changed count ({}) should be <= Added count ({})",
            changed_result.len(),
            added_result.len()
        );
    }

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // Multi-file diff: Changed is subset of Added across all files
    // **Validates: Requirements 2.2, 2.3**
    #[test]
    fn property_changed_subset_multi_file(
        path1 in full_path_strategy(),
        path2 in full_path_strategy(),
        lines1 in prop::collection::vec(line_content_strategy(), 1..3),
        removed2 in prop::collection::vec(line_content_strategy(), 1..2),
        added2 in prop::collection::vec(line_content_strategy(), 1..3),
    ) {
        // Ensure paths are different
        prop_assume!(path1 != path2);

        // Filter out empty lines
        let non_empty_lines1: Vec<&str> = lines1.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_removed2: Vec<&str> = removed2.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_added2: Vec<&str> = added2.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines1.is_empty());
        prop_assume!(!non_empty_removed2.is_empty());
        prop_assume!(!non_empty_added2.is_empty());

        // File 1: pure additions (no removals)
        // File 2: changed content (removals + additions)
        let diff1 = make_pure_addition_diff(&path1, &non_empty_lines1);
        let diff2 = make_changed_diff(&path2, &non_empty_removed2, &non_empty_added2);
        let combined = format!("{}\n{}", diff1, diff2);

        // Parse with both scopes
        let result_added = parse_unified_diff(&combined, Scope::Added);
        let result_changed = parse_unified_diff(&combined, Scope::Changed);

        prop_assert!(result_added.is_ok(), "Parsing with Scope::Added should succeed");
        prop_assert!(result_changed.is_ok(), "Parsing with Scope::Changed should succeed");

        let (added_result, _) = result_added.unwrap();
        let (changed_result, _) = result_changed.unwrap();

        // Property: Every line in changed_result must also be in added_result
        let added_set: std::collections::HashSet<_> = added_result
            .iter()
            .map(|l| (&l.path, l.line, &l.content))
            .collect();

        for changed_line in &changed_result {
            let key = (&changed_line.path, changed_line.line, &changed_line.content);
            prop_assert!(
                added_set.contains(&key),
                "Changed line {:?} at line {} in file {} should be in Added results",
                changed_line.content,
                changed_line.line,
                changed_line.path
            );
        }

        // Property: File 1 (pure additions) should have no lines in Changed result
        let file1_changed: Vec<_> = changed_result.iter().filter(|l| l.path == path1).collect();
        prop_assert!(
            file1_changed.is_empty(),
            "File with pure additions ({}) should have no Changed lines, but found {:?}",
            path1,
            file1_changed
        );

        // Property: File 2 (with removals) may have Changed lines
        // (This is just a sanity check - the main property is subset)
        let file2_changed: Vec<_> = changed_result.iter().filter(|l| l.path == path2).collect();
        let file2_added: Vec<_> = added_result.iter().filter(|l| l.path == path2).collect();
        prop_assert!(
            file2_changed.len() <= file2_added.len(),
            "File 2 Changed count ({}) should be <= Added count ({})",
            file2_changed.len(),
            file2_added.len()
        );
    }

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // Mixed diff with context lines: Changed is still subset of Added
    // **Validates: Requirements 2.2, 2.3**
    #[test]
    fn property_changed_subset_with_context(
        path in full_path_strategy(),
        ctx_before in prop::collection::vec(line_content_strategy(), 0..2),
        removed in prop::collection::vec(line_content_strategy(), 1..3),
        added in prop::collection::vec(line_content_strategy(), 1..3),
        ctx_after in prop::collection::vec(line_content_strategy(), 0..2),
    ) {
        // Filter out empty lines
        let non_empty_ctx_before: Vec<&str> = ctx_before.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_removed: Vec<&str> = removed.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_added: Vec<&str> = added.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_ctx_after: Vec<&str> = ctx_after.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_removed.is_empty());
        prop_assume!(!non_empty_added.is_empty());

        // Create a diff with context, removed, and added lines
        let diff = make_mixed_diff(
            &path,
            &non_empty_ctx_before,
            &non_empty_removed,
            &non_empty_added,
            &non_empty_ctx_after,
        );

        // Parse with both scopes
        let result_added = parse_unified_diff(&diff, Scope::Added);
        let result_changed = parse_unified_diff(&diff, Scope::Changed);

        prop_assert!(result_added.is_ok(), "Parsing with Scope::Added should succeed");
        prop_assert!(result_changed.is_ok(), "Parsing with Scope::Changed should succeed");

        let (added_result, _) = result_added.unwrap();
        let (changed_result, _) = result_changed.unwrap();

        // Property: Every line in changed_result must also be in added_result
        let added_set: std::collections::HashSet<_> = added_result
            .iter()
            .map(|l| (&l.path, l.line, &l.content))
            .collect();

        for changed_line in &changed_result {
            let key = (&changed_line.path, changed_line.line, &changed_line.content);
            prop_assert!(
                added_set.contains(&key),
                "Changed line {:?} at line {} should be in Added results",
                changed_line.content,
                changed_line.line
            );
        }

        // Property: Changed count should be <= Added count
        prop_assert!(
            changed_result.len() <= added_result.len(),
            "Changed count ({}) should be <= Added count ({})",
            changed_result.len(),
            added_result.len()
        );
    }

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // Interleaved additions: only additions after removals are in Changed
    // **Validates: Requirements 2.2, 2.3**
    #[test]
    fn property_interleaved_additions_correct_scope(
        path in full_path_strategy(),
        pure_added in prop::collection::vec(line_content_strategy(), 1..3),
        removed in prop::collection::vec(line_content_strategy(), 1..2),
        changed_added in prop::collection::vec(line_content_strategy(), 1..3),
    ) {
        // Filter out empty lines
        let non_empty_pure: Vec<&str> = pure_added.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_removed: Vec<&str> = removed.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_changed: Vec<&str> = changed_added.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_pure.is_empty());
        prop_assume!(!non_empty_removed.is_empty());
        prop_assume!(!non_empty_changed.is_empty());

        // Create a diff with interleaved content:
        // First pure additions, then removals, then changed additions
        let diff = make_interleaved_diff(
            &path,
            &non_empty_pure,
            &non_empty_removed,
            &non_empty_changed,
        );

        // Parse with both scopes
        let result_added = parse_unified_diff(&diff, Scope::Added);
        let result_changed = parse_unified_diff(&diff, Scope::Changed);

        prop_assert!(result_added.is_ok(), "Parsing with Scope::Added should succeed");
        prop_assert!(result_changed.is_ok(), "Parsing with Scope::Changed should succeed");

        let (added_result, _) = result_added.unwrap();
        let (changed_result, _) = result_changed.unwrap();

        // Property: Added should contain all added lines (pure + changed)
        let expected_added_count = non_empty_pure.len() + non_empty_changed.len();
        prop_assert_eq!(
            added_result.len(),
            expected_added_count,
            "Scope::Added should return {} lines (pure + changed), but got {}",
            expected_added_count,
            added_result.len()
        );

        // Property: Changed should only contain lines that followed removals
        prop_assert_eq!(
            changed_result.len(),
            non_empty_changed.len(),
            "Scope::Changed should return {} lines (only those after removals), but got {}",
            non_empty_changed.len(),
            changed_result.len()
        );

        // Property: Every line in changed_result must also be in added_result
        let added_set: std::collections::HashSet<_> = added_result
            .iter()
            .map(|l| (&l.path, l.line, &l.content))
            .collect();

        for changed_line in &changed_result {
            let key = (&changed_line.path, changed_line.line, &changed_line.content);
            prop_assert!(
                added_set.contains(&key),
                "Changed line {:?} at line {} should be in Added results",
                changed_line.content,
                changed_line.line
            );
        }
    }

    // Feature: comprehensive-test-coverage, Property 4: Scope Filtering Correctness
    // Empty diff: both scopes return empty
    // **Validates: Requirements 2.2, 2.3**
    #[test]
    fn property_empty_diff_both_scopes_empty(
        path in full_path_strategy(),
    ) {
        // Create a diff header with no hunks
        let diff = format!(
            "diff --git a/{path} b/{path}\n\
             index 0000000..1111111 100644\n\
             --- a/{path}\n\
             +++ b/{path}",
            path = path
        );

        // Parse with both scopes
        let result_added = parse_unified_diff(&diff, Scope::Added);
        let result_changed = parse_unified_diff(&diff, Scope::Changed);

        prop_assert!(result_added.is_ok(), "Parsing with Scope::Added should succeed");
        prop_assert!(result_changed.is_ok(), "Parsing with Scope::Changed should succeed");

        let (added_result, _) = result_added.unwrap();
        let (changed_result, _) = result_changed.unwrap();

        // Property: Both scopes should return empty for a diff with no hunks
        prop_assert!(
            added_result.is_empty(),
            "Scope::Added should return empty for diff with no hunks, but got {} lines",
            added_result.len()
        );
        prop_assert!(
            changed_result.is_empty(),
            "Scope::Changed should return empty for diff with no hunks, but got {} lines",
            changed_result.len()
        );
    }
}

// ============================================================================
// Property: Line Count Consistency
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Line Count Consistency
// For any well-formed diff, the DiffStats.lines count SHALL equal the number
// of DiffLine items returned.
// **Validates: Requirements 2.4**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_line_count_matches_stats(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..10),
    ) {
        // Filter out empty lines
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        // Create a well-formed diff
        let diff = make_diff_with_added_lines(&path, &non_empty_lines);

        // Parse the diff
        let result = parse_unified_diff(&diff, Scope::Added);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, stats) = result.unwrap();

        // Property: stats.lines should equal the number of DiffLine items
        prop_assert_eq!(
            stats.lines as usize,
            diff_lines.len(),
            "DiffStats.lines ({}) should equal number of DiffLine items ({})",
            stats.lines,
            diff_lines.len()
        );
    }

    #[test]
    fn property_file_count_matches_unique_paths(
        path1 in full_path_strategy(),
        path2 in full_path_strategy(),
        lines1 in prop::collection::vec(line_content_strategy(), 1..3),
        lines2 in prop::collection::vec(line_content_strategy(), 1..3),
    ) {
        // Ensure paths are different
        prop_assume!(path1 != path2);

        // Filter out empty lines
        let non_empty_lines1: Vec<&str> = lines1.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_lines2: Vec<&str> = lines2.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines1.is_empty());
        prop_assume!(!non_empty_lines2.is_empty());

        // Create a multi-file diff
        let diff1 = make_diff_with_added_lines(&path1, &non_empty_lines1);
        let diff2 = make_diff_with_added_lines(&path2, &non_empty_lines2);
        let combined = format!("{}\n{}", diff1, diff2);

        // Parse the diff
        let result = parse_unified_diff(&combined, Scope::Added);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, stats) = result.unwrap();

        // Count unique paths in diff_lines
        let unique_paths: std::collections::BTreeSet<&str> = diff_lines
            .iter()
            .map(|l| l.path.as_str())
            .collect();

        // Property: stats.files should equal number of unique paths
        prop_assert_eq!(
            stats.files as usize,
            unique_paths.len(),
            "DiffStats.files ({}) should equal number of unique paths ({})",
            stats.files,
            unique_paths.len()
        );
    }
}

// ============================================================================
// Property: No Panic on Valid UTF-8 Input
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Parser Robustness
// For any valid UTF-8 string input, `parse_unified_diff` SHALL not panic.
// **Validates: Requirements 2.5**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_no_panic_on_arbitrary_utf8(
        input in prop::string::string_regex("[\\x00-\\x7F\\u{0080}-\\u{FFFF}]{0,500}").expect("valid regex"),
    ) {
        // Parse arbitrary UTF-8 input - should never panic
        let _ = parse_unified_diff(&input, Scope::Added);
        let _ = parse_unified_diff(&input, Scope::Changed);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn property_no_panic_on_unicode_content(
        prefix in prop::string::string_regex("[a-zA-Z0-9_]{0,20}").expect("valid regex"),
        unicode_chars in prop::string::string_regex("[\\u{4E00}-\\u{9FFF}\\u{1F600}-\\u{1F64F}]{0,10}").expect("valid regex"),
        suffix in prop::string::string_regex("[a-zA-Z0-9_]{0,20}").expect("valid regex"),
    ) {
        // Create input with Unicode characters
        let input = format!("{}{}{}", prefix, unicode_chars, suffix);

        // Parse should not panic
        let _ = parse_unified_diff(&input, Scope::Added);
        let _ = parse_unified_diff(&input, Scope::Changed);
    }

    #[test]
    fn property_no_panic_on_special_characters(
        special in prop::sample::select(&[
            "\n", "\r", "\r\n", "\t", "\x00", "\\", "\"", "'", "`",
            "@@", "+++", "---", "diff", "Binary", "Subproject",
        ]),
        count in 1..20usize,
    ) {
        // Create input with repeated special characters
        let input = special.repeat(count);

        // Parse should not panic
        let _ = parse_unified_diff(&input, Scope::Added);
        let _ = parse_unified_diff(&input, Scope::Changed);
    }

    #[test]
    fn property_no_panic_on_malformed_hunk_headers(
        prefix in prop::string::string_regex("@@[^@]{0,50}").expect("valid regex"),
    ) {
        // Create potentially malformed hunk headers
        let input = format!(
            "diff --git a/file b/file\n\
             --- a/file\n\
             +++ b/file\n\
             {}\n\
             +some content",
            prefix
        );

        // Parse should not panic (may return error, but not panic)
        let _ = parse_unified_diff(&input, Scope::Added);
        let _ = parse_unified_diff(&input, Scope::Changed);
    }
}

// ============================================================================
// Property: Line Numbers are Monotonically Increasing Within Files
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Line Number Validity
// For any parsed diff, line numbers within the same file SHALL be in
// the order they appear in the diff (not necessarily strictly increasing
// but consistent with hunk structure).
// **Validates: Requirements 2.6**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_line_numbers_are_positive(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        let diff = make_diff_with_added_lines(&path, &non_empty_lines);
        let result = parse_unified_diff(&diff, Scope::Added);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, _) = result.unwrap();

        // Property: All line numbers should be positive (>= 1)
        for line in &diff_lines {
            prop_assert!(
                line.line >= 1,
                "Line number should be >= 1, but got {} for path '{}'",
                line.line,
                line.path
            );
        }
    }

    #[test]
    fn property_paths_are_non_empty(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        let diff = make_diff_with_added_lines(&path, &non_empty_lines);
        let result = parse_unified_diff(&diff, Scope::Added);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, _) = result.unwrap();

        // Property: All paths should be non-empty
        for line in &diff_lines {
            prop_assert!(
                !line.path.is_empty(),
                "Path should not be empty"
            );
        }
    }
}

// ============================================================================
// Property: ChangeKind Consistency
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: ChangeKind Validity
// For any diff line, the ChangeKind should be consistent with the scope used.
// **Validates: Requirements 2.7**

use diffguard_diff::ChangeKind;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_changed_scope_only_has_changed_kind(
        path in full_path_strategy(),
        removed_lines in prop::collection::vec(line_content_strategy(), 1..3),
        added_lines in prop::collection::vec(line_content_strategy(), 1..3),
    ) {
        let non_empty_removed: Vec<&str> = removed_lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();
        let non_empty_added: Vec<&str> = added_lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_removed.is_empty());
        prop_assume!(!non_empty_added.is_empty());

        let diff = make_changed_diff(&path, &non_empty_removed, &non_empty_added);
        let result = parse_unified_diff(&diff, Scope::Changed);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, _) = result.unwrap();

        // Property: All lines from Scope::Changed should have ChangeKind::Changed
        for line in &diff_lines {
            prop_assert_eq!(
                line.kind,
                ChangeKind::Changed,
                "Lines from Scope::Changed should have ChangeKind::Changed"
            );
        }
    }

    #[test]
    fn property_pure_additions_have_added_kind(
        path in full_path_strategy(),
        lines in prop::collection::vec(line_content_strategy(), 1..5),
    ) {
        let non_empty_lines: Vec<&str> = lines.iter()
            .filter(|l| !l.is_empty())
            .map(|s| s.as_str())
            .collect();

        prop_assume!(!non_empty_lines.is_empty());

        let diff = make_pure_addition_diff(&path, &non_empty_lines);
        let result = parse_unified_diff(&diff, Scope::Added);
        prop_assert!(result.is_ok(), "Parsing should succeed");

        let (diff_lines, _) = result.unwrap();

        // Property: Pure additions should have ChangeKind::Added
        for line in &diff_lines {
            prop_assert_eq!(
                line.kind,
                ChangeKind::Added,
                "Pure additions should have ChangeKind::Added"
            );
        }
    }
}
