//! Text processing utilities for the diffguard LSP server.
//!
//! This module handles LSP-specific text manipulation, including:
//! - Converting between LSP positions (UTF-16) and byte offsets
//! - Computing which lines changed between two text versions
//! - Applying incremental text document changes

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines, without trailing newlines on each line.
///
/// Unlike `str::lines()`, this preserves empty lines correctly and handles
/// trailing newlines consistently.
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Computes the set of line numbers (1-indexed) that differ between two text versions.
///
/// Compares line-by-line at the same index position. Lines that appear only in `after`
/// (beyond the length of `before`) are NOT marked as changed — only lines at matching
/// indices are compared.
///
/// # Arguments
/// * `before` - The original text
/// * `after` - The modified text
///
/// # Returns
/// A `BTreeSet` of 1-indexed line numbers where the content differs
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

/// Builds a synthetic diff that shows only the specified changed lines as additions.
///
/// This is used when we don't have a real git diff but want to run diffguard on
/// in-memory changes. Each changed line is emitted as a new "+" line in a
/// single-line hunk format (`@@ -0,0 +N,1 @@`).
///
/// # Arguments
/// * `path` - The file path to use in the diff header
/// * `text` - The current file text
/// * `changed_lines` - Set of 1-indexed line numbers that were modified
///
/// # Returns
/// A string in unified diff format showing only the changed lines
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

/// Applies an incremental text document change to a mutable string in-place.
///
/// This is the core function for handling LSP `textDocument/didChange` notifications.
/// When the LSP client sends an incremental change with a `range`, this function
/// converts the UTF-16 based range positions to byte offsets in the Rust `String`
/// and performs a direct in-place replacement — avoiding the prior O(n) full-document
/// clone that occurred on every keystroke.
///
/// If the change has no range (full sync), the entire text is replaced.
///
/// # Arguments
/// * `text` - The current document text (will be mutated)
/// * `change` - The LSP text document content change event
///
/// # Returns
/// `Ok(())` on success, or an error if the position was invalid
pub fn apply_incremental_change(
    text: &mut String,
    change: &TextDocumentContentChangeEvent,
) -> Result<()> {
    let Some(range) = change.range else {
        // Full document sync — replace everything
        *text = change.text.clone();
        return Ok(());
    };

    // Convert UTF-16 LSP positions to byte offsets for String::replace_range
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

/// Converts an LSP `Position` (UTF-16 code unit offset) to a byte offset in a Rust string.
///
/// LSP uses UTF-16 code units for character positions, but Rust strings are UTF-8.
/// This function walks the string by character indices, tracking the current line
/// and UTF-16 character offset until reaching the target position.
///
/// The function handles:
/// - Multi-byte UTF-8 characters (e.g., emoji, non-ASCII)
/// - Characters that occupy multiple UTF-16 code units (e.g., emoji = 2 UTF-16 units)
/// - Position at end-of-string (returns `Some(text.len())`)
///
/// # Arguments
/// * `text` - The UTF-8 string to search
/// * `position` - The LSP position (line + UTF-16 character offset)
///
/// # Returns
/// `Some(byte_offset)` if the position is valid, or `None` if the position is beyond the text
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

/// Computes the length of a string in UTF-16 code units.
///
/// LSP uses UTF-16 for character positions and ranges, so this conversion
/// is frequently needed when creating LSP `Range` objects from Rust strings.
///
/// # Arguments
/// * `text` - The UTF-8 string to measure
///
/// # Returns
/// The number of UTF-16 code units in the string
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
