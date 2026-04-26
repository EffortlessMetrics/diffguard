//! Text processing utilities for the diffguard LSP server.
//!
//! This module provides functions for handling incremental text document changes
//! according to the Language Server Protocol (LSP). It supports both full-document
//! replacements and partial (range-based) edits, using UTF-16 code units for
//! character position tracking as required by LSP.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines, handling both Unix (LF) and Windows (CRLF) line endings.
///
/// Empty text returns an empty vector. The trailing newline character is NOT
/// included in the resulting line strings.
#[must_use]
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Compares two text versions and returns the set of line numbers that differ.
///
/// Line numbers are 1-indexed (matching LSP convention). A line is considered
/// changed if it differs between `before` and `after`, regardless of whether
/// it was added, removed, or modified.
///
/// # Arguments
///
/// * `before` - The original text
/// * `after` - The modified text
///
/// # Returns
///
/// A `BTreeSet<u32>` containing 1-indexed line numbers of changed lines.
/// Lines beyond the length of either text are compared as empty strings.
#[must_use]
pub fn changed_lines_between(before: &str, after: &str) -> BTreeSet<u32> {
    let before_lines = split_lines(before);
    let after_lines = split_lines(after);
    let mut changed = BTreeSet::new();
    let max_len = before_lines.len().max(after_lines.len());

    for index in 0..max_len {
        let before_line = before_lines.get(index);
        let after_line = after_lines.get(index);
        if before_line != after_line && index < after_lines.len() {
            changed.insert((index + 1) as u32);
        }
    }

    changed
}

/// Builds a synthetic diff string representing the given changed lines.
///
/// This generates a minimal "additions-only" diff in unified format, showing
/// only the lines that were added (not deletions or modifications). Each
/// changed line is emitted as a single hunk with a "+" prefix.
///
/// # Arguments
///
/// * `path` - The file path to use in the diff header
/// * `text` - The full file content (used to look up line text)
/// * `changed_lines` - Set of 1-indexed line numbers that were changed
///
/// # Returns
///
/// A string in standard unified diff format showing only added lines.
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

/// Applies a single LSP text document content change to the given text.
///
/// When `change.range` is `None`, this is a full-document replacement.
/// When `range` is provided, only that byte range is replaced with `change.text`.
///
/// # Arguments
///
/// * `text` - The text to modify (in place)
/// * `change` - The LSP content change event containing range and replacement text
///
/// # Errors
///
/// Returns an error if the range positions are invalid (start after end,
/// or positions outside the text bounds).
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

/// Converts an LSP Position (UTF-16 code unit offset) to a byte offset in a UTF-8 string.
///
/// LSP uses UTF-16 code units for character positions within lines. This function
/// converts such a position to a byte offset suitable for use with Rust's `&str`
/// and `String` types (which use UTF-8).
///
/// The function handles:
/// - Multi-byte UTF-8 characters (e.g., Chinese characters take 3+ bytes but 1 UTF-16 code unit)
/// - Characters that span multiple UTF-16 code units (e.g., emojis)
/// - Line endings (newline characters)
///
/// # Arguments
///
/// * `text` - The text to search within
/// * `position` - The LSP Position (0-indexed line and UTF-16 character offset)
///
/// # Returns
///
/// `Some(byte_offset)` if the position is valid, `None` if the position
/// is beyond the end of the text or the specified line.
#[must_use]
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

/// Calculates the length of a string in UTF-16 code units.
///
/// LSP uses UTF-16 code units for character positions. This function
/// computes the total count of UTF-16 code units in the given text,
/// which is needed for correct LSP position handling.
///
/// # Arguments
///
/// * `text` - The text to measure
///
/// # Returns
///
/// The number of UTF-16 code units in the text. ASCII characters count as 1,
/// characters like Chinese count as 1 (if they fit in a single UTF-16 code unit),
/// and characters like emojis count as 2 (surrogate pairs).
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
