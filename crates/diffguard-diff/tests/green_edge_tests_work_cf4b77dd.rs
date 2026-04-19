//! Green edge case tests for diffguard-diff detection functions
//!
//! These tests verify edge cases for the `#[must_use]` predicate functions
//! in unified.rs (issue #482 / PR #511).
//!
//! Edge cases covered:
//! - Malformed inputs to detection functions
//! - Boundary values (empty strings, whitespace-only)
//! - Unicode edge cases in detection function inputs
//! - Very long lines (stress testing)
//! - Lines that are similar to markers but not actually markers

use diffguard_diff::{is_binary_file, is_deleted_file, is_mode_change_only, is_submodule};
use diffguard_diff::{is_new_file, parse_rename_from, parse_rename_to};
use diffguard_diff::{parse_unified_diff, ChangeKind, DiffLine, Scope};

/// Edge case: is_binary_file with malformed inputs that are similar to but not exactly binary markers
#[test]
fn is_binary_file_rejects_malformed_variants() {
    // Missing "and" - common typo
    assert!(
        !is_binary_file("Binary files a/foo.png b/foo.png differ"),
        "Missing 'and' should not match"
    );

    // Missing space after "files"
    assert!(
        !is_binary_file("Binary filesa/foo.png and b/foo.png differ"),
        "Missing space after 'files' should not match"
    );

    // Wrong verb
    assert!(
        !is_binary_file("Binary files a/foo.png and b/foo.png different"),
        "Wrong verb 'different' should not match"
    );

    // Extra characters before "Binary"
    assert!(
        !is_binary_file("  Binary files a/foo.png and b/foo.png differ"),
        "Leading whitespace should not match (uses starts_with)"
    );

    // Trailing space before "differ"
    assert!(
        !is_binary_file("Binary files a/foo.png and b/foo.png differ "),
        "Trailing space after 'differ' should not match (uses contains)"
    );
}

/// Edge case: is_submodule with inputs that look like but aren't submodule commits
#[test]
fn is_submodule_rejects_similar_lines() {
    // Extra text before "Subproject"
    assert!(!is_submodule("Text before Subproject commit abc123"));

    // "SubProject" with capital P (case sensitive)
    assert!(!is_submodule("SubProject commit abc123"));

    // "Subproject" lowercase p (case sensitive)
    assert!(!is_submodule("Subproject commit abc123"));

    // Missing commit hash
    assert!(!is_submodule("Subproject commit "));

    // Empty after prefix
    assert!(!is_submodule("Subproject commit"));
}

/// Edge case: is_deleted_file with whitespace variations
#[test]
fn is_deleted_file_whitespace_variations() {
    // Leading whitespace should NOT match (uses starts_with)
    assert!(!is_deleted_file("  deleted file mode 100644"));
    assert!(!is_deleted_file("\tdeleted file mode 100644"));

    // Trailing whitespace should still match (starts_with matches prefix)
    assert!(is_deleted_file("deleted file mode 100644  "));
    assert!(is_deleted_file("deleted file mode 100644\t"));
}

/// Edge case: is_new_file with whitespace variations
#[test]
fn is_new_file_whitespace_variations() {
    // Leading whitespace should NOT match
    assert!(!is_new_file("  new file mode 100644"));
    assert!(!is_new_file("\tnew file mode 100644"));

    // Trailing whitespace should still match
    assert!(is_new_file("new file mode 100644  "));
    assert!(is_new_file("new file mode 100644\t"));
}

/// Edge case: is_mode_change_only with partial matches
#[test]
fn is_mode_change_only_rejects_partial_matches() {
    // "mode" without prefix
    assert!(!is_mode_change_only("mode 100644"));
    assert!(!is_mode_change_only("oldmode 100644")); // No space

    // Extra text before prefix
    assert!(!is_mode_change_only("the old mode 100644"));

    // Only "new" prefix
    assert!(!is_mode_change_only("new mode ")); // Trailing space, no number

    // Variations
    assert!(!is_mode_change_only("older mode 100644")); // Not "old"
    assert!(!is_mode_change_only("newer mode 100644")); // Not "new"
}

/// Edge case: parse_rename_from/to with whitespace-only paths
#[test]
fn parse_rename_path_rejects_whitespace_only() {
    // These should return None because whitespace-only is not a valid path
    assert_eq!(parse_rename_from("rename from    "), None, "Whitespace-only path should be None");
    assert_eq!(parse_rename_to("rename to    "), None, "Whitespace-only path should be None");
}

/// Edge case: Very long lines to detection functions
#[test]
fn detection_functions_handle_long_lines() {
    // Create a very long "Binary files" line (simulating pathological input)
    let long_path = "a/".repeat(10000);
    let long_binary = format!("Binary files {} and {} differ", long_path, long_path);
    assert!(is_binary_file(&long_binary));

    // Create a very long "Subproject commit" line
    let long_commit = format!("Subproject commit {}", "a".repeat(10000));
    assert!(is_submodule(&long_commit));

    // Create long paths for rename parsing
    let long_rename_path = "rename from " + &"a".repeat(10000);
    let result = parse_rename_from(&long_rename_path);
    assert!(result.is_some());
    assert_eq!(result.unwrap().len(), 10000);
}

/// Edge case: Unicode in detection function inputs
#[test]
fn detection_functions_handle_unicode_in_paths() {
    // Binary file with Unicode path (should still detect as binary)
    let binary_unicode = "Binary files a/日本語.png and b/日本語.png differ";
    assert!(is_binary_file(binary_unicode));

    // Submodule with various Unicode
    let sub_unicode = "Subproject commit abc123日本語def";
    assert!(is_submodule(sub_unicode));

    // Rename with Unicode path
    let rename_unicode = "rename from 日本語ファイル.rs";
    assert_eq!(parse_rename_from(rename_unicode), Some("日本語ファイル.rs".to_string()));
}

/// Edge case: NUL bytes and control characters
#[test]
fn detection_functions_handle_control_characters() {
    // NUL byte in binary marker - should still match as prefix check happens first
    let binary_nul = "Binary files a/foo\x00.png and b/foo.png differ";
    assert!(is_binary_file(binary_nul));

    // Tab character in "differ" position - won't match " differ" exact string
    let binary_tab = "Binary files a/foo.png and b/foo.png\tdiffer";
    assert!(!is_binary_file(binary_tab), "Tab breaks the contains check");

    // Newline in the middle of a line - this would be two lines in practice
    let binary_newline = "Binary files a/foo.png and b/foo.png differ\n";
    assert!(is_binary_file(binary_newline));
}

/// Edge case: parse_unified_diff with overflow potential
#[test]
fn parse_unified_diff_handles_many_files() {
    // Create a diff with many files to test stats overflow path
    // The actual overflow would require u32::MAX files which is impractical,
    // but we can verify the code path handles many files correctly
    let diff = (0..100)
        .map(|i| {
            format!(
                r#"diff --git a/file{}.rs b/file{}.rs
--- a/file{}.rs
+++ b/file{}.rs
@@ -1,1 +1,2 @@
 fn existing() {{}}
+fn added_{}() {{}}
"#,
                i, i, i, i, i
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let (lines, stats) = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert_eq!(stats.files, 100);
    assert_eq!(stats.lines, 100);
    assert_eq!(lines.len(), 100);
}

/// Edge case: Mixed scope parsing with changed detection
#[test]
fn changed_scope_only_after_removes() {
    // Verify that added lines after context (not removes) are NOT marked as Changed
    let diff = r#"
diff --git a/mixed.rs b/mixed.rs
--- a/mixed.rs
+++ b/mixed.rs
@@ -1,4 +1,5 @@
 fn a() {}
+fn added_pure() {}
 fn b() {}
"#;

    let (lines, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
    assert!(lines.is_empty(), "Pure additions without preceding removes should not be 'Changed'");

    // Now test with removes
    let diff2 = r#"
diff --git a/mixed.rs b/mixed.rs
--- a/mixed.rs
+++ b/mixed.rs
@@ -1,3 +1,3 @@
-fn removed() {}
+fn changed() {}
 fn existing() {}
"#;

    let (lines, _) = parse_unified_diff(diff2, Scope::Changed).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].kind, ChangeKind::Changed);
}

/// Edge case: Binary file with /dev/null variants
#[test]
fn binary_file_dev_null_variants() {
    // All these should be detected as binary
    assert!(is_binary_file("Binary files /dev/null and b/new.png differ"));
    assert!(is_binary_file("Binary files a/old.png and /dev/null differ"));
    assert!(is_binary_file("Binary files /dev/null and /dev/null differ"));

    // But these should NOT match
    assert!(!is_binary_file("Binary files /dev/null and b/new.png different")); // Wrong verb
    assert!(!is_binary_file("Binary files /dev/null b/new.png differ")); // Missing 'and'
}

/// Edge case: Mode change with various permission numbers
#[test]
fn is_mode_change_only_various_permissions() {
    // Standard permissions
    assert!(is_mode_change_only("old mode 100644"));
    assert!(is_mode_change_only("new mode 100755"));
    assert!(is_mode_change_only("old mode 100600"));

    // Symlink
    assert!(is_mode_change_only("old mode 120000"));
    assert!(is_mode_change_only("new mode 120000"));

    // Executable bit variations
    assert!(is_mode_change_only("old mode 100700"));
    assert!(is_mode_change_only("new mode 100700"));
}

/// Edge case: Empty and whitespace-only diff inputs
#[test]
fn parse_unified_diff_empty_and_whitespace() {
    // Empty string
    let (lines, stats) = parse_unified_diff("", Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);

    // Whitespace only
    let (lines, stats) = parse_unified_diff("   \n\n  \t  ", Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);

    // Just newlines
    let (lines, stats) = parse_unified_diff("\n\n\n", Scope::Added).unwrap();
    assert!(lines.is_empty());
}

/// Edge case: Files with plus/minus as first char in content
#[test]
fn parse_unified_diff_content_with_plus_minus() {
    // Content that looks like hunk markers but isn't
    let diff = r#"
diff --git a/hunks.rs b/hunks.rs
--- a/hunks.rs
+++ b/hunks.rs
@@ -1,2 +1,4 @@
 fn test() {}
+let s = "+ this is not a hunk";
+let t = "- neither is this";
+let u = "@@ not a hunk header";
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.lines, 3);
    assert_eq!(lines[0].content, "let s = \"+ this is not a hunk\";");
    assert_eq!(lines[1].content, "let t = \"- neither is this\";");
    assert_eq!(lines[2].content, "let u = \"@@ not a hunk header\";");
}
