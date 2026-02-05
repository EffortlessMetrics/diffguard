use std::path::Path;

use diffguard_types::Scope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Changed,
}

// ============================================================================
// Detection functions for special diff content
// ============================================================================

/// Detects if a line indicates a binary file in the diff.
///
/// Binary files are marked with lines like:
/// - "Binary files a/foo.png and b/foo.png differ"
/// - "Binary files /dev/null and b/foo.png differ"
///
/// Requirements: 4.1
pub fn is_binary_file(line: &str) -> bool {
    line.starts_with("Binary files ") && line.contains(" differ")
}

/// Detects if a line indicates a submodule change.
///
/// Submodule changes are marked with lines like:
/// - "Subproject commit abc123..."
///
/// Requirements: 4.2
pub fn is_submodule(line: &str) -> bool {
    line.starts_with("Subproject commit ")
}

/// Detects if a line indicates a deleted file mode.
///
/// Deleted files are marked with lines like:
/// - "deleted file mode 100644"
///
/// Requirements: 4.5
pub fn is_deleted_file(line: &str) -> bool {
    line.starts_with("deleted file mode ")
}

/// Detects if a line indicates a new file mode.
///
/// New files are marked with lines like:
/// - "new file mode 100644"
pub fn is_new_file(line: &str) -> bool {
    line.starts_with("new file mode ")
}

/// Detects if a diff section represents a mode-only change (no content changes).
///
/// Mode-only changes have lines like:
/// - "old mode 100644"
/// - "new mode 100755"
///
/// This function checks for the "old mode" marker which indicates a mode change.
/// A mode-only change is one where only the file permissions changed, not the content.
///
/// Requirements: 4.4
pub fn is_mode_change_only(line: &str) -> bool {
    line.starts_with("old mode ") || line.starts_with("new mode ")
}

/// Parses a rename line and extracts the source path.
///
/// Rename lines look like:
/// - "rename from path/to/old/file.rs"
///
/// Returns the path after "rename from " if the line matches, None otherwise.
///
/// Requirements: 4.3
pub fn parse_rename_from(line: &str) -> Option<String> {
    let rest = line.strip_prefix("rename from ")?;
    parse_rename_path(rest)
}

/// Parses a rename line and extracts the destination path.
///
/// Rename lines look like:
/// - "rename to path/to/new/file.rs"
///
/// Returns the path after "rename to " if the line matches, None otherwise.
///
/// Requirements: 4.3
pub fn parse_rename_to(line: &str) -> Option<String> {
    let rest = line.strip_prefix("rename to ")?;
    parse_rename_path(rest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub path: String,
    pub line: u32,
    pub content: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiffStats {
    pub files: u32,
    pub lines: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DiffParseError {
    #[error("malformed hunk header: {0}")]
    MalformedHunkHeader(String),
}

/// Parse a unified diff (git-style) and return added/changed lines in diff order.
///
/// `scope` controls whether we return:
/// - `Scope::Added`: all added lines
/// - `Scope::Changed`: only added lines that directly follow at least one removed line in the same hunk
///
/// Special cases handled:
/// - Binary files: skipped (no lines extracted)
/// - Submodule changes: skipped (no lines extracted)
/// - Deleted files: skipped (no lines extracted)
/// - Mode-only changes: skipped (no lines extracted)
/// - Renamed files: uses the new (destination) path
/// - Malformed content: continues processing subsequent files
pub fn parse_unified_diff(
    diff_text: &str,
    scope: Scope,
) -> Result<(Vec<DiffLine>, DiffStats), DiffParseError> {
    let mut out: Vec<DiffLine> = Vec::new();
    let mut current_path: Option<String> = None;

    let mut new_line_no: u32 = 0;
    let mut in_hunk = false;

    // For "changed" scope: we treat '+' lines as changed if a '-' was seen since the last context line.
    let mut pending_removed = false;

    // Track special file status for the current file
    let mut skip_current_file = false;
    let mut rename_to_path: Option<String> = None;

    for raw in diff_text.lines() {
        if raw.starts_with("diff --git ") {
            // Reset state for new file
            in_hunk = false;
            pending_removed = false;
            skip_current_file = false;
            rename_to_path = None;

            // Example: diff --git a/foo b/foo
            if let Some(p) = parse_diff_git_line(raw) {
                current_path = Some(p);
            }
            continue;
        }

        // Detect binary files (Requirements 4.1)
        if is_binary_file(raw) {
            skip_current_file = true;
            continue;
        }

        // Detect submodule changes (Requirements 4.2)
        if is_submodule(raw) {
            skip_current_file = true;
            continue;
        }

        // Detect deleted files (Requirements 4.5)
        if is_deleted_file(raw) {
            skip_current_file = true;
            continue;
        }

        // Detect mode changes (Requirements 4.4)
        // Mode-only changes are skipped - they have no content to scan
        if is_mode_change_only(raw) {
            continue;
        }

        // Detect renamed files (Requirements 4.3)
        if let Some(to_path) = parse_rename_to(raw) {
            rename_to_path = Some(to_path);
            continue;
        }

        // Skip "rename from" lines (we only care about the destination)
        if parse_rename_from(raw).is_some() {
            continue;
        }

        if raw.starts_with("+++ ") {
            // Prefer the +++ path if present, unless we have a rename_to path
            if rename_to_path.is_none() {
                if let Some(p) = parse_plus_plus_plus(raw) {
                    current_path = Some(p);
                }
            } else {
                // Use the rename_to path for renamed files
                current_path = rename_to_path.take();
            }
            continue;
        }

        if raw.starts_with("@@") {
            if skip_current_file {
                continue;
            }

            // Try to parse the hunk header, but continue processing on error (Requirements 4.6)
            match parse_hunk_header(raw) {
                Ok(hdr) => {
                    new_line_no = hdr.new_start;
                    in_hunk = true;
                    pending_removed = false;
                }
                Err(_) => {
                    // Malformed hunk header - skip this hunk but continue processing
                    // This allows subsequent files to be processed (Requirements 4.6)
                    in_hunk = false;
                }
            }
            continue;
        }

        // Skip if we're not in a hunk or if the current file should be skipped
        if !in_hunk || skip_current_file {
            continue;
        }

        let Some(path) = current_path.as_deref() else {
            continue;
        };

        // Skip file marker lines
        if raw.starts_with("+++") || raw.starts_with("---") {
            continue;
        }

        if raw.starts_with('\\') {
            // "\\ No newline at end of file"
            continue;
        }

        let first = raw.as_bytes().first().copied();
        match first {
            Some(b'+') => {
                // Check if this is a submodule content line (Requirements 4.2)
                let content = &raw[1..];
                if is_submodule(content) {
                    skip_current_file = true;
                    in_hunk = false;
                    continue;
                }

                // Added line.
                let is_changed = pending_removed;
                let include = match scope {
                    Scope::Added => true,
                    Scope::Changed => is_changed,
                };

                if include {
                    out.push(DiffLine {
                        path: path.to_string(),
                        line: new_line_no,
                        content: content.to_string(),
                        kind: if is_changed {
                            ChangeKind::Changed
                        } else {
                            ChangeKind::Added
                        },
                    });
                }

                new_line_no = new_line_no.saturating_add(1);
            }
            Some(b'-') => {
                // Check if this is a submodule content line (Requirements 4.2)
                let content = &raw[1..];
                if is_submodule(content) {
                    skip_current_file = true;
                    in_hunk = false;
                    continue;
                }

                // Removed line.
                pending_removed = true;
            }
            Some(b' ') => {
                // Context line.
                pending_removed = false;
                new_line_no = new_line_no.saturating_add(1);
            }
            _ => {}
        }
    }

    let mut files = std::collections::BTreeSet::<String>::new();
    for l in &out {
        files.insert(l.path.clone());
    }

    let stats = DiffStats {
        files: files.len() as u32,
        lines: out.len() as u32,
    };

    Ok((out, stats))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HunkHeader {
    new_start: u32,
}

fn parse_hunk_header(line: &str) -> Result<HunkHeader, DiffParseError> {
    // Formats:
    // @@ -1,2 +3,4 @@
    // @@ -1 +3 @@
    let plus = line
        .split_whitespace()
        .nth(2)
        .ok_or_else(|| DiffParseError::MalformedHunkHeader(line.to_string()))?;

    // plus is like "+3,4" or "+3"
    let plus = plus
        .strip_prefix('+')
        .ok_or_else(|| DiffParseError::MalformedHunkHeader(line.to_string()))?;
    let start_str = plus.split(',').next().unwrap_or(plus);
    let new_start: u32 = start_str
        .parse()
        .map_err(|_| DiffParseError::MalformedHunkHeader(line.to_string()))?;

    Ok(HunkHeader { new_start })
}

fn parse_diff_git_line(line: &str) -> Option<String> {
    // diff --git a/foo b/foo
    let rest = line.strip_prefix("diff --git ")?;
    let tokens = tokenize_git_paths(rest, 2);
    if tokens.len() < 2 {
        return None;
    }
    let b = unquote_git_token(&tokens[1]);
    strip_prefix_path(&b)
}

fn parse_plus_plus_plus(line: &str) -> Option<String> {
    // +++ b/foo
    let rest = line.strip_prefix("+++ ")?;
    let token = parse_single_git_path(rest)?;
    if token == "/dev/null" {
        return None;
    }
    strip_prefix_path(&token)
}

fn strip_prefix_path(p: &str) -> Option<String> {
    // strips a/ or b/
    let p = p.trim();
    let p = p
        .strip_prefix("a/")
        .or_else(|| p.strip_prefix("b/"))
        .unwrap_or(p);

    // Normalize to forward slashes for receipts.
    let normalized = Path::new(p)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

#[derive(Debug, Clone)]
struct GitPathToken {
    value: String,
    quoted: bool,
}

fn tokenize_git_paths(input: &str, limit: usize) -> Vec<GitPathToken> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    let mut quoted = false;
    let mut in_quote = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quote {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    buf.push('\\');
                    buf.push(next);
                } else {
                    buf.push('\\');
                }
                continue;
            }

            if ch == '"' {
                in_quote = false;
                continue;
            }

            buf.push(ch);
            continue;
        }

        if ch.is_whitespace() {
            if !buf.is_empty() {
                tokens.push(GitPathToken {
                    value: buf.clone(),
                    quoted,
                });
                buf.clear();
                quoted = false;
                if tokens.len() >= limit {
                    return tokens;
                }
            }
            continue;
        }

        if ch == '"' {
            in_quote = true;
            quoted = true;
            continue;
        }

        buf.push(ch);
    }

    if !buf.is_empty() && tokens.len() < limit {
        tokens.push(GitPathToken { value: buf, quoted });
    }

    tokens
}

fn parse_single_git_path(input: &str) -> Option<String> {
    let tokens = tokenize_git_paths(input, 1);
    tokens.first().map(unquote_git_token)
}

fn parse_rename_path(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('"') {
        return parse_single_git_path(trimmed);
    }

    Some(trimmed.to_string())
}

fn unquote_git_token(token: &GitPathToken) -> String {
    if token.quoted {
        unescape_git_path(&token.value)
    } else {
        token.value.clone()
    }
}

fn unescape_git_path(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut iter = s.as_bytes().iter().copied().peekable();

    while let Some(b) = iter.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }

        let Some(next) = iter.next() else {
            out.push(b'\\');
            break;
        };

        match next {
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b' ' => out.push(b' '),
            b'0'..=b'7' => {
                let mut val = (next - b'0') as u32;
                for _ in 0..2 {
                    match iter.peek().copied() {
                        Some(d) if (b'0'..=b'7').contains(&d) => {
                            val = val * 8 + (d - b'0') as u32;
                            iter.next();
                        }
                        _ => break,
                    }
                }
                out.push((val & 0xFF) as u8);
            }
            _ => {
                out.push(b'\\');
                out.push(next);
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_added_lines() {
        let diff = r#"

diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() { let _ = 1; }
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "src/lib.rs");
        assert_eq!(lines[0].line, 2);
        assert!(matches!(lines[0].kind, ChangeKind::Added));
    }

    #[test]
    fn parses_changed_lines_only_when_requested() {
        let diff = r#"

diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,1 @@
-fn a() { 1 }
+fn a() { 2 }
"#;

        let (added, _) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(added.len(), 1);

        let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
        assert_eq!(changed.len(), 1);
        assert!(matches!(changed[0].kind, ChangeKind::Changed));
    }

    #[test]
    fn does_not_treat_pure_additions_as_changed() {
        let diff = r#"

diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1,1 @@
+hello
"#;

        let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
        assert_eq!(changed.len(), 0);
    }

    // ========================================================================
    // Tests for detection functions (Requirements 4.1-4.5)
    // ========================================================================

    #[test]
    fn is_binary_file_detects_binary_markers() {
        // Standard binary file marker
        assert!(is_binary_file(
            "Binary files a/image.png and b/image.png differ"
        ));
        // Binary file added from /dev/null
        assert!(is_binary_file(
            "Binary files /dev/null and b/new.bin differ"
        ));
        // Binary file deleted to /dev/null
        assert!(is_binary_file(
            "Binary files a/old.bin and /dev/null differ"
        ));
    }

    #[test]
    fn is_binary_file_rejects_non_binary_lines() {
        assert!(!is_binary_file("diff --git a/foo b/foo"));
        assert!(!is_binary_file("+++ b/foo"));
        assert!(!is_binary_file("Binary files")); // Missing " differ"
        assert!(!is_binary_file("Some binary files differ")); // Wrong prefix
        assert!(!is_binary_file("")); // Empty line
    }

    #[test]
    fn is_submodule_detects_submodule_commits() {
        assert!(is_submodule("Subproject commit abc123def456"));
        assert!(is_submodule(
            "Subproject commit 0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn is_submodule_rejects_non_submodule_lines() {
        assert!(!is_submodule("diff --git a/foo b/foo"));
        assert!(!is_submodule("Subproject")); // Incomplete
        assert!(!is_submodule("commit abc123")); // Wrong prefix
        assert!(!is_submodule("")); // Empty line
    }

    #[test]
    fn is_deleted_file_detects_deleted_mode() {
        assert!(is_deleted_file("deleted file mode 100644"));
        assert!(is_deleted_file("deleted file mode 100755"));
        assert!(is_deleted_file("deleted file mode 120000")); // Symlink
    }

    #[test]
    fn is_deleted_file_rejects_non_deleted_lines() {
        assert!(!is_deleted_file("new file mode 100644"));
        assert!(!is_deleted_file("diff --git a/foo b/foo"));
        assert!(!is_deleted_file("deleted file")); // Incomplete
        assert!(!is_deleted_file("")); // Empty line
    }

    #[test]
    fn is_new_file_detects_new_mode() {
        assert!(is_new_file("new file mode 100644"));
        assert!(is_new_file("new file mode 100755"));
        assert!(is_new_file("new file mode 120000")); // Symlink
    }

    #[test]
    fn is_new_file_rejects_non_new_lines() {
        assert!(!is_new_file("deleted file mode 100644"));
        assert!(!is_new_file("diff --git a/foo b/foo"));
        assert!(!is_new_file("new file")); // Incomplete
        assert!(!is_new_file("")); // Empty line
    }

    #[test]
    fn is_mode_change_only_detects_mode_changes() {
        assert!(is_mode_change_only("old mode 100644"));
        assert!(is_mode_change_only("new mode 100755"));
        assert!(is_mode_change_only("old mode 100755"));
        assert!(is_mode_change_only("new mode 100644"));
    }

    #[test]
    fn is_mode_change_only_rejects_non_mode_lines() {
        assert!(!is_mode_change_only("diff --git a/foo b/foo"));
        assert!(!is_mode_change_only("deleted file mode 100644"));
        assert!(!is_mode_change_only("new file mode 100644"));
        assert!(!is_mode_change_only("mode 100644")); // Missing old/new prefix
        assert!(!is_mode_change_only("")); // Empty line
    }

    #[test]
    fn parse_rename_from_extracts_source_path() {
        assert_eq!(
            parse_rename_from("rename from src/old/path.rs"),
            Some("src/old/path.rs".to_string())
        );
        assert_eq!(
            parse_rename_from("rename from file.txt"),
            Some("file.txt".to_string())
        );
        assert_eq!(
            parse_rename_from("rename from path/with spaces/file.rs"),
            Some("path/with spaces/file.rs".to_string())
        );
        assert_eq!(
            parse_rename_from("rename from \"path/with spaces/file.rs\""),
            Some("path/with spaces/file.rs".to_string())
        );
    }

    #[test]
    fn parse_rename_from_returns_none_for_non_rename_lines() {
        assert_eq!(parse_rename_from("rename to src/new/path.rs"), None);
        assert_eq!(parse_rename_from("diff --git a/foo b/foo"), None);
        assert_eq!(parse_rename_from("rename from"), None); // Empty path is still valid
        assert_eq!(parse_rename_from(""), None);
    }

    #[test]
    fn parse_rename_to_extracts_destination_path() {
        assert_eq!(
            parse_rename_to("rename to src/new/path.rs"),
            Some("src/new/path.rs".to_string())
        );
        assert_eq!(
            parse_rename_to("rename to file.txt"),
            Some("file.txt".to_string())
        );
        assert_eq!(
            parse_rename_to("rename to path/with spaces/file.rs"),
            Some("path/with spaces/file.rs".to_string())
        );
        assert_eq!(
            parse_rename_to("rename to \"path/with spaces/file.rs\""),
            Some("path/with spaces/file.rs".to_string())
        );
    }

    #[test]
    fn parse_rename_to_returns_none_for_non_rename_lines() {
        assert_eq!(parse_rename_to("rename from src/old/path.rs"), None);
        assert_eq!(parse_rename_to("diff --git a/foo b/foo"), None);
        assert_eq!(parse_rename_to("rename to"), None); // Empty path is still valid
        assert_eq!(parse_rename_to(""), None);
    }

    #[test]
    fn parse_diff_git_line_parses_paths() {
        assert_eq!(
            parse_diff_git_line("diff --git a/src/lib.rs b/src/lib.rs"),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(
            parse_diff_git_line(r#"diff --git "a/dir name/file.rs" "b/dir name/file.rs""#),
            Some("dir name/file.rs".to_string())
        );
        assert_eq!(
            parse_diff_git_line(
                r#"diff --git "a/dir\ name/\"file\".rs" "b/dir\ name/\"file\".rs""#
            ),
            Some("dir name/\"file\".rs".to_string())
        );
        assert_eq!(parse_diff_git_line("diff --git a/only"), None);
    }

    #[test]
    fn parse_plus_plus_plus_parses_paths() {
        assert_eq!(
            parse_plus_plus_plus("+++ b/src/lib.rs"),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(parse_plus_plus_plus("+++ /dev/null"), None);
        assert_eq!(
            parse_plus_plus_plus(r#"+++ "b/dir name/file.rs""#),
            Some("dir name/file.rs".to_string())
        );
        assert_eq!(
            parse_plus_plus_plus(r#"+++ "b/dir\ name/\"file\".rs""#),
            Some("dir name/\"file\".rs".to_string())
        );
    }

    #[test]
    fn tokenize_git_paths_respects_quotes_and_limits() {
        let tokens = tokenize_git_paths(r#"a/one "b/two two" c/three"#, 2);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].value, "a/one");
        assert!(!tokens[0].quoted);
        assert_eq!(tokens[1].value, "b/two two");
        assert!(tokens[1].quoted);

        let tokens = tokenize_git_paths("   a b", 2);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].value, "a");
        assert_eq!(tokens[1].value, "b");

        let tokens = tokenize_git_paths("a ", 2);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value, "a");

        let tokens = tokenize_git_paths("a", 0);
        assert!(tokens.is_empty());

        let tokens = tokenize_git_paths("a b c", 1);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value, "a");
    }

    #[test]
    fn unescape_git_path_handles_common_escapes() {
        assert_eq!(
            unescape_git_path(r#"dir\ name\"quote\"\\tab\tnewline\ncarriage\rend"#),
            "dir name\"quote\"\\tab\tnewline\ncarriage\rend"
        );
        assert_eq!(unescape_git_path(r#"octal\141\040space"#), "octala space");
        assert_eq!(unescape_git_path(r#"weird\q"#), "weird\\q");
        assert_eq!(unescape_git_path("endswith\\"), "endswith\\");
    }

    #[test]
    fn unescape_git_path_handles_octal_limits_and_control_chars() {
        assert_eq!(unescape_git_path(r#"\7"#).as_bytes(), &[7]);
        assert_eq!(unescape_git_path(r#"\1234"#), "S4");
        assert_eq!(
            unescape_git_path(r#"a\rb"#).as_bytes(),
            &[b'a', b'\r', b'b']
        );
        assert_eq!(unescape_git_path(r#"\12x"#).as_bytes(), &[b'\n', b'x']);
    }

    // ========================================================================
    // Tests for parse_unified_diff special case handling (Requirements 4.1-4.6)
    // ========================================================================

    #[test]
    fn skips_binary_files() {
        // Binary file should be skipped, but subsequent text file should be parsed
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

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "src/lib.rs");
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn skips_submodule_changes() {
        // Submodule change should be skipped, but subsequent file should be parsed
        let diff = r#"
diff --git a/vendor/lib b/vendor/lib
index abc1234..def5678 160000
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit abc1234567890abcdef1234567890abcdef123456
+Subproject commit def5678901234567890abcdef1234567890abcdef
diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,1 +1,2 @@
 fn main() {}
+fn helper() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "src/main.rs");
        assert_eq!(lines[0].content, "fn helper() {}");
    }

    #[test]
    fn skips_deleted_files() {
        // Deleted file should be skipped, but subsequent file should be parsed
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
diff --git a/new_file.rs b/new_file.rs
new file mode 100644
--- /dev/null
+++ b/new_file.rs
@@ -0,0 +1,1 @@
+fn new() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "new_file.rs");
        assert_eq!(lines[0].content, "fn new() {}");
    }

    #[test]
    fn skips_mode_only_changes() {
        // Mode-only change (chmod) should be skipped, but subsequent file should be parsed
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

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "src/lib.rs");
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn uses_new_path_for_renamed_files() {
        // Renamed file should use the new path
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

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "new/path.rs");
        assert_eq!(lines[0].content, "fn added() {}");
    }

    #[test]
    fn parses_quoted_paths_in_headers() {
        let diff = r#"
diff --git "a/dir name/file.rs" "b/dir name/file.rs"
--- "a/dir name/file.rs"
+++ "b/dir name/file.rs"
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "dir name/file.rs");
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn ignores_lines_outside_hunks() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
+fn should_not_be_seen()
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn skips_file_markers_inside_hunks() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,3 @@
 fn a() {}
++++not_a_marker
+fn b() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn continues_after_malformed_hunk_header() {
        // Malformed hunk header should not stop processing of subsequent files
        let diff = r#"
diff --git a/bad.rs b/bad.rs
--- a/bad.rs
+++ b/bad.rs
@@ malformed hunk header
+this line should be skipped
diff --git a/good.rs b/good.rs
--- a/good.rs
+++ b/good.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);
        assert_eq!(lines[0].path, "good.rs");
        assert_eq!(lines[0].content, "fn b() {}");
    }

    #[test]
    fn handles_multiple_special_cases_in_one_diff() {
        // Multiple special cases should all be handled correctly
        let diff = r#"
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
diff --git a/vendor/lib b/vendor/lib
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit abc123
+Subproject commit def456
diff --git a/old.rs b/old.rs
deleted file mode 100644
--- a/old.rs
+++ /dev/null
@@ -1 +0,0 @@
-fn old() {}
diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
diff --git a/renamed.rs b/newname.rs
rename from renamed.rs
rename to newname.rs
--- a/renamed.rs
+++ b/newname.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn in_renamed() {}
diff --git a/normal.rs b/normal.rs
--- a/normal.rs
+++ b/normal.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn in_normal() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.lines, 2);

        // Check renamed file uses new path
        let renamed_line = lines.iter().find(|l| l.content == "fn in_renamed() {}");
        assert!(renamed_line.is_some());
        assert_eq!(renamed_line.unwrap().path, "newname.rs");

        // Check normal file is parsed
        let normal_line = lines.iter().find(|l| l.content == "fn in_normal() {}");
        assert!(normal_line.is_some());
        assert_eq!(normal_line.unwrap().path, "normal.rs");
    }

    #[test]
    fn binary_file_added_from_dev_null() {
        // New binary file should be skipped
        let diff = r#"
diff --git a/new_image.png b/new_image.png
new file mode 100644
Binary files /dev/null and b/new_image.png differ
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(lines[0].path, "src/lib.rs");
    }

    #[test]
    fn renamed_file_with_no_content_changes() {
        // Pure rename with no content changes should still use new path if there are hunks
        let diff = r#"
diff --git a/old.rs b/new.rs
similarity index 100%
rename from old.rs
rename to new.rs
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        // No content changes, so no lines extracted
        assert_eq!(stats.files, 0);
        assert_eq!(stats.lines, 0);
        assert!(lines.is_empty());
    }

    // ========================================================================
    // Edge case tests (Requirements 9.1, 9.2, 9.6)
    // ========================================================================

    /// Tests for empty hunks - hunks with no added/removed lines (Requirement 9.1)
    #[test]
    fn handles_empty_hunk_context_only() {
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

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.lines, 0);
        assert!(lines.is_empty());
    }

    #[test]
    fn handles_empty_hunk_zero_lines() {
        // A hunk header indicating zero lines in the new file
        let diff = r#"
diff --git a/empty.rs b/empty.rs
new file mode 100644
--- /dev/null
+++ b/empty.rs
@@ -0,0 +0,0 @@
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.lines, 0);
        assert!(lines.is_empty());
    }

    #[test]
    fn handles_multiple_empty_hunks() {
        // Multiple hunks with only context lines
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,2 @@
 fn a() {}
 fn b() {}
@@ -10,2 +10,2 @@
 fn x() {}
 fn y() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.lines, 0);
        assert!(lines.is_empty());
    }

    /// Tests for multiple files in a single diff (Requirement 9.2)
    #[test]
    fn parses_multiple_files_in_single_diff() {
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
diff --git a/src/third.rs b/src/third.rs
--- a/src/third.rs
+++ b/src/third.rs
@@ -1,1 +1,2 @@
 fn third_existing() {}
+fn third_added() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 3);
        assert_eq!(stats.lines, 3);

        // Verify each file is parsed correctly
        let first = lines.iter().find(|l| l.path == "src/first.rs");
        assert!(first.is_some());
        assert_eq!(first.unwrap().content, "fn first_added() {}");
        assert_eq!(first.unwrap().line, 2);

        let second = lines.iter().find(|l| l.path == "src/second.rs");
        assert!(second.is_some());
        assert_eq!(second.unwrap().content, "fn second_added() {}");
        assert_eq!(second.unwrap().line, 2);

        let third = lines.iter().find(|l| l.path == "src/third.rs");
        assert!(third.is_some());
        assert_eq!(third.unwrap().content, "fn third_added() {}");
        assert_eq!(third.unwrap().line, 2);
    }

    #[test]
    fn parses_multiple_files_with_multiple_hunks_each() {
        let diff = r#"
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,1 +1,2 @@
 fn a1() {}
+fn a2() {}
@@ -10,1 +11,2 @@
 fn a10() {}
+fn a11() {}
diff --git a/src/b.rs b/src/b.rs
--- a/src/b.rs
+++ b/src/b.rs
@@ -1,1 +1,2 @@
 fn b1() {}
+fn b2() {}
@@ -20,1 +21,2 @@
 fn b20() {}
+fn b21() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.lines, 4);

        // Verify lines from file a
        let a_lines: Vec<_> = lines.iter().filter(|l| l.path == "src/a.rs").collect();
        assert_eq!(a_lines.len(), 2);
        assert!(a_lines
            .iter()
            .any(|l| l.content == "fn a2() {}" && l.line == 2));
        assert!(a_lines
            .iter()
            .any(|l| l.content == "fn a11() {}" && l.line == 12));

        // Verify lines from file b
        let b_lines: Vec<_> = lines.iter().filter(|l| l.path == "src/b.rs").collect();
        assert_eq!(b_lines.len(), 2);
        assert!(b_lines
            .iter()
            .any(|l| l.content == "fn b2() {}" && l.line == 2));
        assert!(b_lines
            .iter()
            .any(|l| l.content == "fn b21() {}" && l.line == 22));
    }

    #[test]
    fn parses_multiple_files_preserves_order() {
        let diff = r#"
diff --git a/z.rs b/z.rs
--- a/z.rs
+++ b/z.rs
@@ -1,1 +1,2 @@
 fn z() {}
+fn z_added() {}
diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn a_added() {}
diff --git a/m.rs b/m.rs
--- a/m.rs
+++ b/m.rs
@@ -1,1 +1,2 @@
 fn m() {}
+fn m_added() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 3);
        assert_eq!(stats.lines, 3);

        // Verify order is preserved (z, a, m - not alphabetically sorted)
        assert_eq!(lines[0].path, "z.rs");
        assert_eq!(lines[1].path, "a.rs");
        assert_eq!(lines[2].path, "m.rs");
    }

    /// Tests for Unicode content in diff lines (Requirement 9.6)
    #[test]
    fn handles_unicode_in_added_lines() {
        let diff = r#"
diff --git a/src/i18n.rs b/src/i18n.rs
--- a/src/i18n.rs
+++ b/src/i18n.rs
@@ -1,1 +1,4 @@
 fn greet() {}
+let hello_jp = "こんにちは";
+let hello_cn = "你好";
+let hello_kr = "안녕하세요";
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 3);

        assert_eq!(lines[0].content, "let hello_jp = \"こんにちは\";");
        assert_eq!(lines[1].content, "let hello_cn = \"你好\";");
        assert_eq!(lines[2].content, "let hello_kr = \"안녕하세요\";");
    }

    #[test]
    fn handles_unicode_emojis_in_diff() {
        let diff = r#"
diff --git a/src/emoji.rs b/src/emoji.rs
--- a/src/emoji.rs
+++ b/src/emoji.rs
@@ -1,1 +1,3 @@
 fn emoji() {}
+let rocket = "🚀";
+let thumbs_up = "👍🏽";
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 2);

        assert_eq!(lines[0].content, "let rocket = \"🚀\";");
        assert_eq!(lines[1].content, "let thumbs_up = \"👍🏽\";");
    }

    #[test]
    fn handles_unicode_in_file_paths() {
        let diff = r#"
diff --git a/src/日本語.rs b/src/日本語.rs
--- a/src/日本語.rs
+++ b/src/日本語.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn 新しい関数() {}
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);

        assert_eq!(lines[0].path, "src/日本語.rs");
        assert_eq!(lines[0].content, "fn 新しい関数() {}");
    }

    #[test]
    fn handles_unicode_special_characters() {
        // Test various Unicode categories: math symbols, arrows, box drawing, etc.
        let diff = r#"
diff --git a/src/symbols.rs b/src/symbols.rs
--- a/src/symbols.rs
+++ b/src/symbols.rs
@@ -1,1 +1,5 @@
 fn symbols() {}
+let math = "∑∏∫∂∇";
+let arrows = "→←↑↓↔";
+let box_drawing = "┌─┐│└─┘";
+let currency = "€£¥₹₽";
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 4);

        assert_eq!(lines[0].content, "let math = \"∑∏∫∂∇\";");
        assert_eq!(lines[1].content, "let arrows = \"→←↑↓↔\";");
        assert_eq!(lines[2].content, "let box_drawing = \"┌─┐│└─┘\";");
        assert_eq!(lines[3].content, "let currency = \"€£¥₹₽\";");
    }

    #[test]
    fn handles_mixed_unicode_and_ascii() {
        let diff = r#"
diff --git a/src/mixed.rs b/src/mixed.rs
--- a/src/mixed.rs
+++ b/src/mixed.rs
@@ -1,1 +1,2 @@
 fn mixed() {}
+let message = "Hello 世界! Welcome to Rust 🦀";
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);

        assert_eq!(
            lines[0].content,
            "let message = \"Hello 世界! Welcome to Rust 🦀\";"
        );
    }

    #[test]
    fn handles_unicode_in_changed_lines() {
        // Test that Unicode works correctly with Scope::Changed
        let diff = r#"
diff --git a/src/i18n.rs b/src/i18n.rs
--- a/src/i18n.rs
+++ b/src/i18n.rs
@@ -1,1 +1,1 @@
-let greeting = "Hello";
+let greeting = "Привет";
"#;

        let (lines, stats) = parse_unified_diff(diff, Scope::Changed).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(stats.lines, 1);

        assert_eq!(lines[0].content, "let greeting = \"Привет\";");
        assert!(matches!(lines[0].kind, ChangeKind::Changed));
    }
}
