//! Integration tests for parsing diffs with octal-escaped paths.
//!
//! These tests exercise the full pipeline: raw diff text with quoted paths
//! containing octal escape sequences → parse_unified_diff → DiffLine with
//! correctly unescaped paths.
//!
//! The change being tested: replacing `u8 as u32` with `u32::from(u8)` in
//! unescape_git_path's octal parsing branch. This is a lossless widening cast
//! that doesn't affect behavior, but these tests verify the full integration
//! path still works correctly.

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

/// Test: Full pipeline with a path containing an octal-escaped space.
/// Git outputs paths with spaces as `\040` (octal for space).
///
/// Flow: diff text with quoted path → parse_diff_git_line → tokenize_git_paths
///       → unquote_git_token → unescape_git_path → unescaped path in DiffLine
#[test]
fn test_parse_diff_with_octal_escaped_space_in_path() {
    // Git quotes paths with special characters and uses octal escapes for spaces
    // "\040" is octal for space (ASCII 32)
    let diff = r#"
diff --git "a/path\040with spaces/file.rs" "b/path with spaces/file.rs"
--- "a/path\040with spaces/file.rs"
+++ "b/path with spaces/file.rs"
@@ -1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // The path should be unescaped: \040 → ' '
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].path, "path with spaces/file.rs");
    assert_eq!(lines[0].content, "fn added() {}");
    assert_eq!(stats.files, 1);
    assert_eq!(stats.lines, 1);
}

/// Test: Full pipeline with embedded octal escapes in path.
/// Path contains multiple octal escapes representing different characters.
///
/// \041 = '!' (ASCII 33)
/// \040 = ' ' (ASCII 32)
#[test]
fn test_parse_diff_with_multiple_octal_escapes_in_path() {
    let diff = r#"
diff --git "a/file\041name\040here.rs" "b/file!name here.rs"
--- "a/file\041name\040here.rs"
+++ "b/file!name here.rs"
@@ -1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

    let (lines, _stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // All octal escapes should be properly decoded
    assert_eq!(lines[0].path, "file!name here.rs");
}

/// Test: Octal escapes at path boundaries (start, middle, end).
///
/// \143 = 'c' (ASCII 99) - octal for lowercase 'c'
#[test]
fn test_parse_diff_with_octal_escape_at_path_boundaries() {
    // \143 = 'c'
    let diff = r#"
diff --git "a/\143at.rs" "b/cat.rs"
--- "a/\143at.rs"
+++ "b/cat.rs"
@@ -1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

    let (lines, _stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(lines[0].path, "cat.rs");
}

/// Test: Three-digit octal escape at maximum value.
/// \177 = DEL (ASCII 127), \000 = NUL (ASCII 0)
#[test]
fn test_parse_diff_with_octal_edge_cases() {
    // \177 = 127 (DEL), \000 = 0 (NUL)
    // These are boundary cases for the u8→u32 cast
    let diff = r#"
diff --git "a/\177\000file.rs" "b/\177\000file.rs"
--- "a/\177\000file.rs"
+++ "b/\177\000file.rs"
@@ -1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

    let (lines, _stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    // The path should contain the raw bytes (non-printable but valid)
    assert_eq!(lines[0].path, "\x7F\x00file.rs");
}

/// Test: Renamed file with octal-escaped path.
/// When a file is renamed, the "rename to" path can also have octal escapes.
#[test]
fn test_parse_diff_rename_with_octal_escaped_path() {
    let diff = r#"
diff --git "a/old\040name.rs" "b/new\040name.rs"
rename from old name.rs
rename to new name.rs
--- "a/old\040name.rs"
+++ "b/new\040name.rs"
@@ -1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;

    let (lines, _stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    // The path should be unescaped
    assert_eq!(lines[0].path, "new name.rs");
}

/// Test: Multiple files with mixed quoted/unquoted paths.
#[test]
fn test_parse_diff_multiple_files_mixed_path_formats() {
    let diff = r#"
diff --git "a/quoted\040path.rs" "b/quoted path.rs"
--- "a/quoted\040path.rs"
+++ "b/quoted path.rs"
@@ -1 +1,2 @@
+added to quoted path
diff --git a/normal_path.rs b/normal_path.rs
--- a/normal_path.rs
+++ b/normal_path.rs
@@ -1 +1,2 @@
+added to normal path
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].path, "quoted path.rs");
    assert_eq!(lines[1].path, "normal_path.rs");
    assert_eq!(stats.files, 2);
    assert_eq!(stats.lines, 2);
}
