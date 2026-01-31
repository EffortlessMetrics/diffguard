//! Property-based tests for diffguard-diff
//!
//! Feature: diffguard-completion
//!
//! These tests verify the enhanced diff parsing functionality for handling
//! special cases like binary files, submodules, renames, and malformed content.

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
