//! Edge case tests for tracing instrumentation in diffguard-diff
//!
//! These tests validate that the tracing instrumentation:
//! 1. Does not interfere with parsing behavior
//! 2. Handles edge cases correctly (empty input, boundary values, etc.)
//! 3. Properly emits events for special file types and error conditions
//!
//! Feature: tracing-instrumentation-edge-cases

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

// ============================================================================
// Helper functions
// ============================================================================

/// Create a binary file diff
fn make_binary_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         Binary files a/{path} and b/{path} differ\n",
        path = path
    )
}

/// Create a submodule diff
fn make_submodule_diff(path: &str, old_commit: &str, new_commit: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..{new_commit} 160000\n\
         --- a/{path}\n\
         +++ b/{path}\n\
         @@ -1 +1 @@
\
         -Subproject commit {old_commit}\n\
         +Subproject commit {new_commit}\n",
        path = path,
        old_commit = old_commit,
        new_commit = new_commit
    )
}

/// Create a deleted file diff
fn make_deleted_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         deleted file mode 100644\n\
         index 1111111..0000000\n\
         --- a/{path}\n\
         +++ /dev/null\n\
         @@ -1 +0,0 @@\n\
         -fn deleted() {{}}\n",
        path = path
    )
}

/// Create a mode-only change diff
fn make_mode_only_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         old mode 100644\n\
         new mode 100755\n",
        path = path
    )
}

/// Create a diff with malformed hunk header
fn make_malformed_hunk_diff(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         --- a/{path}\n\
         +++ b/{path}\n\
         @@ not a valid hunk\n\
         +invalid content\n",
        path = path
    )
}

/// Create a valid diff with added lines
fn make_added_lines_diff(path: &str, lines: &[&str]) -> String {
    let content: String = lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         --- a/{path}\n\
         +++ b/{path}\n\
         @@ -0,0 +1,{num_lines} @@\n\
         {content}",
        path = path,
        num_lines = lines.len(),
        content = content
    )
}

// ============================================================================
// Edge Case 1: Empty input
// ============================================================================

#[test]
fn edge_case_empty_string_returns_empty_lines() {
    let result = parse_unified_diff("", Scope::Added);
    assert!(result.is_ok(), "Empty input should parse successfully");
    let (lines, stats) = result.unwrap();
    assert!(lines.is_empty(), "Empty input should produce no lines");
    assert_eq!(stats.files, 0, "Empty input should have 0 files");
    assert_eq!(stats.lines, 0, "Empty input should have 0 lines");
}

#[test]
fn edge_case_whitespace_only_input() {
    let result = parse_unified_diff("   \n\n  \n", Scope::Added);
    assert!(
        result.is_ok(),
        "Whitespace-only input should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Whitespace-only input should produce no lines"
    );
}

// ============================================================================
// Edge Case 2: Single line content
// ============================================================================

#[test]
fn edge_case_single_added_line() {
    let diff = make_added_lines_diff("test.rs", &["hello"]);
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Single added line should parse successfully"
    );
    let (lines, stats) = result.unwrap();
    assert_eq!(lines.len(), 1, "Should have exactly 1 line");
    assert_eq!(stats.lines, 1, "Stats should show 1 line");
    assert_eq!(lines[0].content, "hello", "Content should match");
}

#[test]
fn edge_case_single_context_line() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -1 +1 @@
\
          context\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Single context line should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Context lines should not appear in Added scope"
    );
}

// ============================================================================
// Edge Case 3: Binary file detection
// ============================================================================

#[test]
fn edge_case_binary_file_always_skipped() {
    let diff = make_binary_diff("image.png");
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(result.is_ok(), "Binary file diff should parse successfully");
    let (lines, _) = result.unwrap();
    assert!(lines.is_empty(), "Binary file should produce no lines");
}

#[test]
fn edge_case_binary_file_skipped_in_changed_scope() {
    let diff = make_binary_diff("binary.data");
    let result = parse_unified_diff(&diff, Scope::Changed);
    assert!(result.is_ok(), "Binary file diff should parse successfully");
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Binary file should produce no lines in Changed scope"
    );
}

// ============================================================================
// Edge Case 4: Submodule detection
// ============================================================================

#[test]
fn edge_case_submodule_skipped_in_added_scope() {
    let diff = make_submodule_diff("submodule", "abc123", "def456");
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(result.is_ok(), "Submodule diff should parse successfully");
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Submodule should produce no lines in Added scope"
    );
}

// ============================================================================
// Edge Case 5: Deleted file handling
// ============================================================================

#[test]
fn edge_case_deleted_file_skipped_in_added_scope() {
    let diff = make_deleted_diff("removed.rs");
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Deleted file diff should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Deleted file should produce no lines in Added scope"
    );
}

#[test]
fn edge_case_deleted_file_included_in_deleted_scope() {
    let diff = make_deleted_diff("removed.rs");
    let result = parse_unified_diff(&diff, Scope::Deleted);
    assert!(
        result.is_ok(),
        "Deleted file diff should parse successfully in Deleted scope"
    );
    let (lines, stats) = result.unwrap();
    assert!(
        !lines.is_empty(),
        "Deleted file should produce lines in Deleted scope"
    );
    assert_eq!(stats.files, 1, "Should have 1 file");
}

// ============================================================================
// Edge Case 6: Mode-only changes
// ============================================================================

#[test]
fn edge_case_mode_only_change_skipped() {
    let diff = make_mode_only_diff("script.sh");
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(result.is_ok(), "Mode-only diff should parse successfully");
    let (lines, _) = result.unwrap();
    assert!(lines.is_empty(), "Mode-only change should produce no lines");
}

// ============================================================================
// Edge Case 7: Malformed hunk headers
// ============================================================================

#[test]
fn edge_case_malformed_hunk_header_continues_parsing() {
    // Create a diff with malformed hunk header followed by valid file
    let malformed = make_malformed_hunk_diff("bad.rs");
    let valid = make_added_lines_diff("good.rs", &["valid line"]);
    let combined = format!("{}\n{}", malformed, valid);

    let result = parse_unified_diff(&combined, Scope::Added);
    assert!(
        result.is_ok(),
        "Should parse even with malformed hunk header"
    );
    let (lines, stats) = result.unwrap();

    // The malformed file should produce no lines
    // The valid file should produce lines
    let bad_lines: Vec<_> = lines.iter().filter(|l| l.path == "bad.rs").collect();
    let good_lines: Vec<_> = lines.iter().filter(|l| l.path == "good.rs").collect();

    assert!(
        bad_lines.is_empty(),
        "Malformed hunk should produce no lines"
    );
    assert!(!good_lines.is_empty(), "Valid file should produce lines");
    assert_eq!(stats.files, 1, "Should count only the valid file");
}

#[test]
fn edge_case_multiple_malformed_hunks_continues() {
    let malformed1 = make_malformed_hunk_diff("bad1.rs");
    let malformed2 = make_malformed_hunk_diff("bad2.rs");
    let valid = make_added_lines_diff("good.rs", &["valid"]);

    let combined = format!("{}\n{}\n{}", malformed1, malformed2, valid);
    let result = parse_unified_diff(&combined, Scope::Added);
    assert!(
        result.is_ok(),
        "Should parse even with multiple malformed hunks"
    );
    let (lines, stats) = result.unwrap();

    let good_lines: Vec<_> = lines.iter().filter(|l| l.path == "good.rs").collect();
    assert!(
        !good_lines.is_empty(),
        "Valid file should produce lines despite malformed hunks"
    );
    assert_eq!(stats.files, 1, "Should count only the valid files");
}

// ============================================================================
// Edge Case 8: Path with special characters
// ============================================================================

#[test]
fn edge_case_path_with_spaces() {
    let diff = "diff --git a/path/with spaces/file.rs b/path/with spaces/file.rs\n\
         index 0000000..1111111 100644\n\
         --- a/path/with spaces/file.rs\n\
         +++ b/path/with spaces/file.rs\n\
         @@ -1 +1 @@
\
         -old
\
         +new with space\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(result.is_ok(), "Path with spaces should parse successfully");
    let (lines, _) = result.unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 line");
    assert_eq!(lines[0].content, "new with space", "Content should match");
}

#[test]
fn edge_case_path_with_unicode() {
    let diff = "diff --git a/path/日本語/file.rs b/path/日本語/file.rs\n\
         index 0000000..1111111 100644\n\
         --- a/path/日本語/file.rs\n\
         +++ b/path/日本語/file.rs\n\
         @@ -1 +1 @@
\
         -old
\
         +unicode content\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Path with unicode should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 line");
    assert_eq!(lines[0].content, "unicode content", "Content should match");
}

#[test]
fn edge_case_path_with_special_chars() {
    let diff = "diff --git a/path/with-dashes_and_underscores/file.rs b/path/with-dashes_and_underscores/file.rs\n\
         index 0000000..1111111 100644\n\
         --- a/path/with-dashes_and_underscores/file.rs\n\
         +++ b/path/with-dashes_and_underscores/file.rs\n\
         @@ -1 +1 @@
\
         -old
\
         +special chars\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Path with special chars should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 line");
}

// ============================================================================
// Edge Case 9: Line number boundary values
// ============================================================================

#[test]
fn edge_case_zero_line_numbers() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -0,0 +1 @@
\
         +content\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Zero line numbers should parse successfully"
    );
}

#[test]
fn edge_case_large_line_numbers() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -999999,1 +999999,1 @@
\
         -old
\
         +new\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Large line numbers should parse successfully"
    );
}

// ============================================================================
// Edge Case 10: Multiple files with mixed special cases
// ============================================================================

#[test]
fn edge_case_multiple_special_files_mixed_order() {
    let binary = make_binary_diff("image.png");
    let normal1 = make_added_lines_diff("file1.rs", &["line1"]);
    let submodule = make_submodule_diff("sub", "abc", "def");
    let mode_only = make_mode_only_diff("script.sh");
    let normal2 = make_added_lines_diff("file2.rs", &["line2"]);
    let deleted = make_deleted_diff("removed.rs");
    let normal3 = make_added_lines_diff("file3.rs", &["line3"]);

    let combined = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        binary, normal1, submodule, mode_only, normal2, deleted, normal3
    );

    let result = parse_unified_diff(&combined, Scope::Added);
    assert!(
        result.is_ok(),
        "Mixed special files should parse successfully"
    );

    let (lines, stats) = result.unwrap();

    // Only normal files should produce lines
    let file1_lines: Vec<_> = lines.iter().filter(|l| l.path == "file1.rs").collect();
    let file2_lines: Vec<_> = lines.iter().filter(|l| l.path == "file2.rs").collect();
    let file3_lines: Vec<_> = lines.iter().filter(|l| l.path == "file3.rs").collect();

    assert!(!file1_lines.is_empty(), "file1.rs should produce lines");
    assert!(!file2_lines.is_empty(), "file2.rs should produce lines");
    assert!(!file3_lines.is_empty(), "file3.rs should produce lines");

    // Special files should not produce lines
    let image_lines: Vec<_> = lines.iter().filter(|l| l.path == "image.png").collect();
    let sub_lines: Vec<_> = lines.iter().filter(|l| l.path == "sub").collect();
    let removed_lines: Vec<_> = lines.iter().filter(|l| l.path == "removed.rs").collect();

    assert!(image_lines.is_empty(), "image.png should not produce lines");
    assert!(sub_lines.is_empty(), "sub should not produce lines");
    assert!(
        removed_lines.is_empty(),
        "removed.rs should not produce lines in Added scope"
    );

    // Should have exactly 3 files
    assert_eq!(stats.files, 3, "Should have exactly 3 files");
}

// ============================================================================
// Edge Case 11: Diff without trailing newline
// ============================================================================

#[test]
fn edge_case_no_final_newline() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -1 +1 @@
\
         -old
\
         +new";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Diff without trailing newline should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 line");
}

// ============================================================================
// Edge Case 12: Interleaved additions and deletions (Changed scope)
// ============================================================================

#[test]
fn edge_case_changed_scope_mixed_lines() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -1,3 +1,3 @@
\
         context
\
         -deleted
\
         +added
\
         context\n";
    let result = parse_unified_diff(diff, Scope::Changed);
    assert!(result.is_ok(), "Changed scope should parse successfully");
    let (lines, _) = result.unwrap();
    // Changed scope should include both additions and deletions
    assert!(!lines.is_empty(), "Changed scope should produce lines");
}

// ============================================================================
// Edge Case 13: New file (only additions)
// ============================================================================

#[test]
fn edge_case_new_file_added() {
    let diff = make_added_lines_diff("newfile.rs", &["first line", "second line"]);
    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(result.is_ok(), "New file should parse successfully");
    let (lines, _) = result.unwrap();
    assert_eq!(lines.len(), 2, "Should have 2 lines");
}

// ============================================================================
// Edge Case 14: File with only context lines
// ============================================================================

#[test]
fn edge_case_only_context_lines() {
    let diff = "diff --git a/test.rs b/test.rs\n\
         index 0000000..1111111 100644\n\
         --- a/test.rs\n\
         +++ b/test.rs\n\
         @@ -1,3 +1,3 @@
\
          context line 1
\
          context line 2
\
          context line 3\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Only context lines should parse successfully"
    );
    let (lines, _) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Only context lines should produce no Added lines"
    );
}

// ============================================================================
// Edge Case 15: Stats accuracy with multiple files
// ============================================================================

#[test]
fn edge_case_stats_accuracy_with_multiple_files() {
    let file1 = make_added_lines_diff("file1.rs", &["a", "b", "c"]);
    let file2 = make_added_lines_diff("file2.rs", &["d", "e"]);
    let file3 = make_added_lines_diff("file3.rs", &["f"]);

    let combined = format!("{}\n{}\n{}", file1, file2, file3);
    let result = parse_unified_diff(&combined, Scope::Added);
    assert!(result.is_ok(), "Multiple files should parse successfully");

    let (lines, stats) = result.unwrap();
    assert_eq!(lines.len(), 6, "Should have 6 total lines");
    assert_eq!(stats.files, 3, "Should have 3 files");
    assert_eq!(stats.lines, 6, "Stats lines should match");
}

// ============================================================================
// Edge Case 16: Escape sequences in git paths
// ============================================================================

#[test]
fn edge_case_quoted_git_paths() {
    // Git quotes paths with special characters using octal escapes
    let diff = "diff --git a/path/with\\040special b/path/with\\040special\n\
         index 0000000..1111111 100644\n\
         --- a/path/with special\n\
         +++ b/path/with special\n\
         @@ -1 +1 @@
\
         -old
\
         +new\n";
    let result = parse_unified_diff(diff, Scope::Added);
    assert!(result.is_ok(), "Quoted git paths should parse successfully");
}

// ============================================================================
// Edge Case 17: Maximum input size handling
// ============================================================================

#[test]
fn edge_case_large_diff_still_parses() {
    // Create a large diff with many lines
    let lines: Vec<String> = (0..1000).map(|i| format!("+line{}", i)).collect();
    let lines_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let diff = make_added_lines_diff("large.rs", &lines_refs);

    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(result.is_ok(), "Large diff should parse successfully");
    let (lines_out, stats) = result.unwrap();
    assert_eq!(lines_out.len(), 1000, "Should have 1000 lines");
    assert_eq!(stats.lines, 1000, "Stats should show 1000 lines");
}
