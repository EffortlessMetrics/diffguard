//! Snapshot tests for diffguard-diff parsing output.
//!
//! These tests capture the deterministic output of `parse_unified_diff` for
//! representative inputs. Any change in output will be immediately detected via
//! snapshot mismatch.
//!
//! Snapshot Strategy:
//! - Capture `Vec<DiffLine>` and `DiffStats` as debug-formatted strings
//! - Normalize line numbers where they would be non-deterministic across runs
//! - Cover happy path, edge cases, and error cases

use diffguard_diff::{DiffParseError, parse_unified_diff};
use diffguard_types::Scope;

/// Helper to format DiffLine output for snapshotting
fn format_diff_lines(lines: &[diffguard_diff::DiffLine]) -> String {
    if lines.is_empty() {
        return "[]".to_string();
    }
    let formatted: Vec<String> = lines
        .iter()
        .map(|l| {
            format!(
                "DiffLine {{ path: {:?}, line: {}, content: {:?}, kind: {:?} }}",
                l.path, l.line, l.content, l.kind
            )
        })
        .collect();
    formatted.join("\n")
}

/// Helper to format DiffStats for snapshotting
fn format_stats(stats: &diffguard_diff::DiffStats) -> String {
    format!(
        "DiffStats {{ files: {}, lines: {} }}",
        stats.files, stats.lines
    )
}

/// Helper to format full parse result for snapshotting

// =============================================================================
// Happy path snapshots
// =============================================================================

#[test]
fn snapshot_parse_added_lines_simple() {
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_added_lines_simple", snapshot);
}

#[test]
fn snapshot_parse_changed_lines() {
    // A line that was removed followed by a line that was added = Changed scope
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,1 @@
-fn a() { 1 }
+fn a() { 2 }
"#;
    let result = parse_unified_diff(diff, Scope::Changed).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_changed_lines", snapshot);
}

#[test]
fn snapshot_parse_deleted_lines() {
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,2 @@
 fn a() {}
-fn b() {}
-fn c() {}
+fn c() { println!("updated"); }
"#;
    let result = parse_unified_diff(diff, Scope::Deleted).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_deleted_lines", snapshot);
}

#[test]
fn snapshot_parse_multiple_files() {
    let diff = r#"
diff --git a/src/first.rs b/src/first.rs
--- a/src/first.rs
+++ b/src/first.rs
@@ -1,1 +1,2 @@
 fn first_existing() {}
+fn first_added() {}
diff --git a/src/second.rs b/src/second.rs
--- a/src/second.rs
+++ b/src/second.rs
@@ -1,1 +1,2 @@
 fn second_existing() {}
+fn second_added() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_multiple_files", snapshot);
}

// =============================================================================
// Edge case snapshots
// =============================================================================

#[test]
fn snapshot_parse_empty_diff() {
    let diff = "";
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_empty_diff", snapshot);
}

#[test]
fn snapshot_parse_whitespace_only_diff() {
    let diff = "   \n\n  \n";
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_whitespace_only_diff", snapshot);
}

#[test]
fn snapshot_parse_diff_header_only() {
    // A diff with only the header, no hunks
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_diff_header_only", snapshot);
}

#[test]
fn snapshot_parse_context_only_hunk() {
    // A hunk with only context lines (no additions or removals)
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 fn a() {}
 fn b() {}
 fn c() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_context_only_hunk", snapshot);
}

// =============================================================================
// Error case snapshots
// =============================================================================

#[test]
fn snapshot_parse_malformed_hunk_header() {
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ malformed
+fn a() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added);
    let snapshot = format!("{:?}", result.err());
    insta::assert_snapshot!("parse_malformed_hunk_header", snapshot);
}

#[test]
fn snapshot_parse_missing_hunk_header_plus_section() {
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2
+fn a() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added);
    let snapshot = format!("{:?}", result.err());
    insta::assert_snapshot!("parse_missing_hunk_header_plus_section", snapshot);
}

// =============================================================================
// Special case snapshots (binary, submodule, rename, mode-only)
// =============================================================================

#[test]
fn snapshot_parse_binary_file_skipped() {
    let diff = r#"
diff --git a/image.png b/image.png
index 0000000..1111111 100644
Binary files a/image.png and b/image.png differ
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_binary_file_skipped", snapshot);
}

#[test]
fn snapshot_parse_submodule_change_skipped() {
    let diff = r#"
diff --git a/vendor/lib b/vendor/lib
index abc1234..def5678 160000
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit abc1234567890abcdef1234567890abcdef123456
+Subproject commit def5678901234567890abcdef1234567890abcdef
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_submodule_change_skipped", snapshot);
}

#[test]
fn snapshot_parse_renamed_file_uses_new_path() {
    let diff = r#"
diff --git a/old/path.rs b/new/path.rs
similarity index 95%
rename from old/path.rs
rename to new/path.rs
--- a/old/path.rs
+++ b/new/path.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn added() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_renamed_file_uses_new_path", snapshot);
}

#[test]
fn snapshot_parse_mode_only_change_skipped() {
    let diff = r#"
diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;
    let result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_mode_only_change_skipped", snapshot);
}

#[test]
fn snapshot_parse_deleted_file_for_deleted_scope() {
    let diff = r#"
diff --git a/old_file.rs b/old_file.rs
deleted file mode 100644
index abc1234..0000000
--- a/old_file.rs
+++ /dev/null
@@ -1,3 +0,0 @@
-fn old() {}
-fn deprecated() {}
-fn removed() {}
"#;
    let result = parse_unified_diff(diff, Scope::Deleted).expect("Should parse");
    let (lines, stats) = &result;
    let snapshot = format!(
        "lines:\n{}\nstats:\n{}",
        format_diff_lines(lines),
        format_stats(stats)
    );
    insta::assert_snapshot!("parse_deleted_file_for_deleted_scope", snapshot);
}

// =============================================================================
// Scope behavior snapshots
// =============================================================================

#[test]
fn snapshot_scope_added_vs_changed_vs_deleted_same_diff() {
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,4 +1,4 @@
 fn a() {}
-fn b() {}
+fn b() { 2 }
 fn c() {}
+fn d() {}
"#;

    let added_result = parse_unified_diff(diff, Scope::Added).expect("Should parse");
    let (added_lines, added_stats) = &added_result;
    let changed_result = parse_unified_diff(diff, Scope::Changed).expect("Should parse");
    let (changed_lines, changed_stats) = &changed_result;
    let deleted_result = parse_unified_diff(diff, Scope::Deleted).expect("Should parse");
    let (deleted_lines, deleted_stats) = &deleted_result;

    let snapshot = format!(
        "Added:\n{}\n{}\n\nChanged:\n{}\n{}\n\nDeleted:\n{}\n{}",
        format_diff_lines(added_lines),
        format_stats(added_stats),
        format_diff_lines(changed_lines),
        format_stats(changed_stats),
        format_diff_lines(deleted_lines),
        format_stats(deleted_stats)
    );
    insta::assert_snapshot!("scope_added_vs_changed_vs_deleted_same_diff", snapshot);
}

// =============================================================================
// DiffParseError snapshots
// =============================================================================

#[test]
fn snapshot_error_malformed_hunk_header() {
    let err = DiffParseError::MalformedHunkHeader("@@ -1 +x @@".to_string());
    insta::assert_snapshot!("error_malformed_hunk_header", format!("{:?}", err));
}

#[test]
fn snapshot_error_overflow() {
    let err = DiffParseError::Overflow("too many lines (> 4294967295)".to_string());
    insta::assert_snapshot!("error_overflow", format!("{:?}", err));
}
