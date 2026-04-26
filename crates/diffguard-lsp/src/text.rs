use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines by `\n` characters.
///
/// Unlike `str::lines()`, this preserves trailing empty strings (e.g., `"a\n"` returns
/// `["a", ""]` rather than `["a"]`). This is important for LSP operations where
/// accurate line counts are required.
///
/// # Arguments
///
/// * `text` - The text to split into lines
///
/// # Returns
///
/// A vector of string slices, one per line. Empty input returns an empty vector.
#[must_use]
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Compares two text snapshots and returns the line numbers that differ.
///
/// Line numbers are 1-indexed to match conventional diff output. Only lines present
/// in the `after` text are considered changed if they differ from `before`. This is
/// useful for detecting which lines were modified in a text edit operation.
///
/// # Arguments
///
/// * `before` - The original text
/// * `after` - The modified text
///
/// # Returns
///
/// A `BTreeSet` of 1-indexed line numbers that differ between the two texts.
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

/// Builds a synthetic unified diff showing only the added lines for given changed line numbers.
///
/// This creates a minimal diff representation suitable for display or analysis, containing
/// only the lines that were added or modified (not context lines). Each changed line is
/// emitted as a separate hunk with format `@@ -0,0 +N,1 @@` followed by the line content.
///
/// # Arguments
///
/// * `path` - The file path to use in the diff header
/// * `text` - The full file text (used to look up line content)
/// * `changed_lines` - Set of 1-indexed line numbers that were changed
///
/// # Returns
///
/// A string in unified diff format containing only the added lines.
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

/// Applies an LSP `TextDocumentContentChangeEvent` to a text string.
///
/// This handles both full document replacements (when `range` is `None`) and
/// incremental edits (when `range` is `Some`). For incremental edits, the
/// LSP position (UTF-16 code units) is converted to byte offsets for Rust strings.
///
/// # Arguments
///
/// * `text` - The text to modify (in-place)
/// * `change` - The LSP change event to apply
///
/// # Returns
///
/// `Ok(())` on success, or an error if the range is invalid (start after end).
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

/// Converts an LSP `Position` to a byte offset in a UTF-8 text string.
///
/// LSP uses UTF-16 code units for positions, but Rust strings are UTF-8.
/// This function performs the conversion by iterating through the text and
/// tracking both the current line (by `\n` characters) and the UTF-16 character offset.
///
/// # Arguments
///
/// * `text` - The UTF-8 text to search in
/// * `position` - The LSP position (line and UTF-16 character index)
///
/// # Returns
///
/// `Some(byte_offset)` if the position is valid, or `None` if the position
/// is past the end of the text or the character offset is invalid.
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

/// Returns the length of a string in UTF-16 code units.
///
/// LSP uses UTF-16 code units for character positions and lengths. This function
/// computes that length by summing `len_utf16()` for each character. This is
/// necessary when communicating with LSP clients since Rust strings are UTF-8
/// but the LSP protocol expects UTF-16.
///
/// # Arguments
///
/// * `text` - The text to measure
///
/// # Returns
///
/// The number of UTF-16 code units in the text.
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
