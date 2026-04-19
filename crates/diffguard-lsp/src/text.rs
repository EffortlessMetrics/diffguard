//! Text diffing and LSP text manipulation utilities.
//!
//! This module provides functions for comparing text documents, building synthetic
//! diffs for LSP diagnostics, and applying incremental text changes using the LSP
//! TextDocumentContentChangeEvent format.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines, handling the common diff format.
///
/// Splits on newline characters (`\n`). Unlike `str::lines()`, this does not
/// trim trailing newlines — a trailing newline produces an additional empty string
/// element at the end of the returned vector.
///
/// # Examples
/// ```
/// # use diffguard_lsp::text::split_lines;
/// assert_eq!(split_lines("a\nb\n"), vec!["a", "b", ""]);
/// assert_eq!(split_lines(""), Vec::<&str>::new());
/// ```
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Compares two text documents and returns the line numbers that differ.
///
/// Performs a line-by-line comparison between `before` and `after`, returning
/// a sorted set of 1-indexed line numbers where the content differs.
///
/// # Overflow Handling
///
/// Line numbers are stored as `u32` (max ~4.29 billion). For files with more
/// lines than `u32::MAX`, line numbers at `u32::MAX + 1` and beyond are
/// saturated to `u32::MAX` and a warning is emitted to stderr. This prevents
/// silent truncation that would cause incorrect diff results.
///
/// # Differences from `str::lines()`
///
/// Uses `split('\n')` rather than `lines()` to preserve trailing newlines,
/// which is important for diff accuracy.
///
/// # Arguments
///
/// * `before` - The original text content
/// * `after` - The modified text content
///
/// # Returns
///
/// A `BTreeSet<u32>` containing 1-indexed line numbers of changed lines.
/// Empty set if the documents are identical.
pub fn changed_lines_between(before: &str, after: &str) -> BTreeSet<u32> {
    let before_lines = split_lines(before);
    let after_lines = split_lines(after);
    let mut changed = BTreeSet::new();
    let max_len = before_lines.len().max(after_lines.len());

    for index in 0..max_len {
        let before_line = before_lines.get(index);
        let after_line = after_lines.get(index);
        if before_line != after_line && index < after_lines.len() {
            let line_number = (index + 1) as u32;
            if line_number as usize != index + 1 {
                // index + 1 overflowed u32 — cap at u32::MAX and warn
                changed.insert(u32::MAX);
                eprintln!(
                    "changed_lines_between: line number overflow (>{}), capping at u32::MAX",
                    u32::MAX
                );
            } else {
                changed.insert(line_number);
            }
        }
    }

    changed
}

/// Builds a synthetic unified diff showing only the specified changed lines.
///
/// Creates a minimal diff in unified format that contains only the hunks for lines
/// marked as changed. Used to generate diagnostics showing what changed in a document.
///
/// # Diff Format
///
/// Produces a unified diff with:
/// - A single file header with the given path
/// - One hunk per changed line (`@@ -0,0 +N,1 @@`)
/// - The new content prefixed with `+`
///
/// # Skipped Lines
///
/// Lines with number 0 are skipped (reserved for "no newline at end of file").
/// Lines beyond the text length are silently skipped (defensive handling).
///
/// # Arguments
///
/// * `path` - The file path to use in the diff header
/// * `text` - The full document text (used to look up line content)
/// * `changed_lines` - Set of 1-indexed line numbers that changed
///
/// # Returns
///
/// A `String` containing the unified diff format output.
#[must_use]
pub fn build_synthetic_diff(path: &str, text: &str, changed_lines: &BTreeSet<u32>) -> String {
    let mut diff = format!(
        "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n",
        path = path
    );
    let lines = split_lines(text);

    for line_number in changed_lines {
        if *line_number == 0 {
            continue;
        }

        let index = (*line_number as usize).saturating_sub(1);
        if index >= lines.len() {
            continue;
        }

        diff.push_str(&format!("@@ -0,0 +{},1 @@\n", line_number));
        diff.push('+');
        diff.push_str(lines[index]);
        diff.push('\n');
    }

    diff
}

/// Applies an incremental LSP text change to a document.
///
/// Implements the LSP TextDocumentContentChangeEvent apply logic:
/// - If no range is specified, the entire document is replaced
/// - If a range is specified, only that byte range is replaced
///
/// Uses `byte_offset_at_position` to convert LSP positions to byte offsets,
/// which correctly handles UTF-16 character offsets used by LSP.
///
/// # Arguments
///
/// * `text` - The document text to modify (in place)
/// * `change` - The LSP change event to apply
///
/// # Returns
///
/// Returns `Ok(())` on success. Returns an error if the position is invalid
/// (outside document bounds or malformed range).
///
/// # Errors
///
/// - Invalid start/end position (out of bounds)
/// - Start position comes after end position
pub fn apply_incremental_change(
    text: &mut String,
    change: &TextDocumentContentChangeEvent,
) -> Result<()> {
    let Some(range) = change.range else {
        *text = change.text.clone();
        return Ok(());
    };

    let start = byte_offset_at_position(text, range.start).with_context(|| {
        format!(
            "invalid start position line={}, character={}",
            range.start.line, range.start.character
        )
    })?;
    let end = byte_offset_at_position(text, range.end).with_context(|| {
        format!(
            "invalid end position line={}, character={}",
            range.end.line, range.end.character
        )
    })?;

    if start > end {
        bail!("invalid edit range: start {} is after end {}", start, end);
    }

    text.replace_range(start..end, &change.text);
    Ok(())
}

/// Converts an LSP Position to a byte offset in the document.
///
/// The Language Server Protocol uses UTF-16 code units for character positions.
/// This function correctly maps LSP positions to byte offsets in Rust strings,
/// handling multi-byte UTF-8 characters that span multiple UTF-16 code units.
///
/// # LSP Position Semantics
///
/// A Position represents a character offset within a line, counted in UTF-16
/// code units. For ASCII text, byte offset and UTF-16 offset are equivalent.
/// For emoji and other complex characters, they differ.
///
/// # Arguments
///
/// * `text` - The document text
/// * `position` - The LSP Position (line + UTF-16 character offset)
///
/// # Returns
///
/// `Some(byte_offset)` if the position is valid, `None` if the position
/// is beyond the document or on a character boundary that doesn't exist.
///
/// # Examples
///
/// ```
/// # use diffguard_lsp::text::byte_offset_at_position;
/// # use lsp_types::Position;
/// let text = "hello";
/// assert_eq!(byte_offset_at_position(text, Position::new(0, 0)), Some(0));
/// assert_eq!(byte_offset_at_position(text, Position::new(0, 2)), Some(2));
/// ```
pub fn byte_offset_at_position(text: &str, position: Position) -> Option<usize> {
    let mut current_line: u32 = 0;
    let mut current_character_utf16: u32 = 0;

    for (index, ch) in text.char_indices() {
        if current_line == position.line && current_character_utf16 == position.character {
            return Some(index);
        }

        if ch == '\n' {
            if current_line == position.line && current_character_utf16 == position.character {
                return Some(index);
            }
            current_line = current_line.saturating_add(1);
            current_character_utf16 = 0;
            continue;
        }

        if current_line == position.line {
            current_character_utf16 = current_character_utf16.saturating_add(ch.len_utf16() as u32);
            if current_character_utf16 > position.character {
                return None;
            }
        }
    }

    if current_line == position.line && current_character_utf16 == position.character {
        Some(text.len())
    } else {
        None
    }
}

/// Calculates the length of text in UTF-16 code units.
///
/// LSP uses UTF-16 code units for character positions. This function computes
/// the UTF-16 length, which is needed when reporting diagnostics or creating
/// LSP positions for documents containing non-ASCII characters.
///
/// # Arguments
///
/// * `text` - The text to measure
///
/// # Returns
///
/// The number of UTF-16 code units in the text. For ASCII text, this equals
/// the byte length. For emoji and complex scripts, this may be larger.
#[must_use]
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{Position, Range, TextDocumentContentChangeEvent};

    #[test]
    fn changed_lines_between_marks_modified_line() {
        let before = "one\ntwo\nthree\n";
        let after = "one\nTWO\nthree\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2]));
    }

    #[test]
    fn build_synthetic_diff_emits_hunks_for_changed_lines() {
        let changed = BTreeSet::from([2_u32, 3_u32]);
        let diff = build_synthetic_diff("src/lib.rs", "one\ntwo\nthree\n", &changed);
        assert!(diff.contains("@@ -0,0 +2,1 @@"));
        assert!(diff.contains("@@ -0,0 +3,1 @@"));
        assert!(diff.contains("+two"));
        assert!(diff.contains("+three"));
    }

    #[test]
    fn apply_incremental_change_replaces_range() {
        let mut text = "alpha\nbeta\n".to_string();
        let change = TextDocumentContentChangeEvent {
            range: Some(Range::new(Position::new(1, 0), Position::new(1, 4))),
            range_length: None,
            text: "gamma".to_string(),
        };

        apply_incremental_change(&mut text, &change).expect("apply");
        assert_eq!(text, "alpha\ngamma\n");
    }
}
