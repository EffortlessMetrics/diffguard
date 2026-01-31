use std::path::Path;

use diffguard_types::Scope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Changed,
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
pub fn parse_unified_diff(diff_text: &str, scope: Scope) -> Result<(Vec<DiffLine>, DiffStats), DiffParseError> {
    let mut out: Vec<DiffLine> = Vec::new();
    let mut current_path: Option<String> = None;

    let mut new_line_no: u32 = 0;
    let mut in_hunk = false;

    // For "changed" scope: we treat '+' lines as changed if a '-' was seen since the last context line.
    let mut pending_removed = false;

    for raw in diff_text.lines() {
        if raw.starts_with("diff --git ") {
            in_hunk = false;
            pending_removed = false;
            // Example: diff --git a/foo b/foo
            if let Some(p) = parse_diff_git_line(raw) {
                current_path = Some(p);
            }
            continue;
        }

        if raw.starts_with("+++ ") {
            // Prefer the +++ path if present.
            if let Some(p) = parse_plus_plus_plus(raw) {
                current_path = Some(p);
            }
            continue;
        }

        if raw.starts_with("@@") {
            let hdr = parse_hunk_header(raw)?;
            new_line_no = hdr.new_start;
            in_hunk = true;
            pending_removed = false;
            continue;
        }

        if !in_hunk {
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
                        content: raw[1..].to_string(),
                        kind: if is_changed { ChangeKind::Changed } else { ChangeKind::Added },
                    });
                }

                new_line_no = new_line_no.saturating_add(1);
            }
            Some(b'-') => {
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

    Ok((
        out,
        DiffStats {
            files: files.len() as u32,
            lines: out.len() as u32,
        },
    ))
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
    let plus = plus.strip_prefix('+').ok_or_else(|| DiffParseError::MalformedHunkHeader(line.to_string()))?;
    let start_str = plus.split(',').next().unwrap_or(plus);
    let new_start: u32 = start_str
        .parse()
        .map_err(|_| DiffParseError::MalformedHunkHeader(line.to_string()))?;

    Ok(HunkHeader { new_start })
}

fn parse_diff_git_line(line: &str) -> Option<String> {
    // diff --git a/foo b/foo
    let mut it = line.split_whitespace();
    if it.next()? != "diff" {
        return None;
    }
    if it.next()? != "--git" {
        return None;
    }
    let _a = it.next()?;
    let b = it.next()?;
    strip_prefix_path(b)
}

fn parse_plus_plus_plus(line: &str) -> Option<String> {
    // +++ b/foo
    let rest = line.strip_prefix("+++ ")?;
    let first = rest.split('\t').next().unwrap_or(rest);
    if first == "/dev/null" {
        return None;
    }
    strip_prefix_path(first)
}

fn strip_prefix_path(p: &str) -> Option<String> {
    // strips a/ or b/
    let p = p.trim();
    let p = p.strip_prefix("a/").or_else(|| p.strip_prefix("b/")).unwrap_or(p);

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
}
