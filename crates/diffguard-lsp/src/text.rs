use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines, returning a vector of string slices.
///
/// Splits on newline characters (`\n`) and preserves the order of lines.
/// The newline characters themselves are not included in the result.
///
/// # Return Value
///
/// Returns an empty `Vec` when `text` is empty. Otherwise returns all
/// lines in document order. Line indices in the returned vector are
/// 0-based (line 1 of the document is at index 0).
///
/// # Why `#[must_use]`?
///
/// Callers that discard the return value silently lose all line-split
/// information. The `#[must_use]` attribute ensures the compiler emits
/// a warning if the result is not used.
#[must_use]
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Compares two text documents line-by-line and returns the line numbers that differ.
///
/// Performs a line-by-line comparison between `before` and `after`.
/// Line numbers are 1-based (matching LSP convention) and returned in a
/// `BTreeSet` for deterministic ordering.
///
/// # Line Numbering
///
/// Line numbers are 1-based: the first line of the document is line 1.
/// This matches LSP's `Position` line numbering.
///
/// # Added vs Modified Lines
///
/// Only lines present in `after` are reported as changed. If a line exists
/// in `before` but not in `after` (i.e., `after` is shorter and differs at
/// that position), it is not included in the changed set.
///
/// # Differences Detection
///
/// Two lines are considered different if their string contents differ.
/// Trailing newline differences are handled naturally since `split_lines`
/// does not include the newline character in the line content.
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

/// Builds a synthetic unified diff that adds the specified changed lines.
///
/// This constructs a minimal "diff --git" format diff showing lines that were
/// added or modified in a document. The diff is synthetic because it generates
/// the diff from in-memory text rather than comparing two files on disk.
///
/// # Parameters
///
/// - `path`: The file path to use in the diff header (e.g., `"src/lib.rs"`).
/// - `text`: The full document text (used to look up line content).
/// - `changed_lines`: A set of 1-based line numbers that were changed.
///
/// # Diff Format
///
/// Each changed line produces a hunk header `@@ -0,0 +N,1 @@` followed by
/// the line content prefixed with `+`. The hunk format indicates "no context
/// before, one line of added content" which is appropriate for showing new
/// or modified lines.
///
/// # Why Synthetic?
///
/// This is used to generate diffs for display or analysis when the actual
/// on-disk files may not exist yet (e.g., for LSP diagnostics before save).
/// It produces diff-like output for changed lines only.
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

        // Convert from 1-based line numbers (LSP convention) to 0-based array indices.
        // saturating_sub ensures that if line_number is somehow 0 (skipped above),
        // we get 0 instead of underflowing.
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

/// Applies an LSP incremental text document change to a string in-place.
///
/// Implements the LSP `TextDocumentContentChangeEvent` semantics:
/// - If `change.range` is `None`, the entire document content is replaced.
/// - If `range` is provided, only that byte range is replaced.
///
/// # Error Handling
///
/// Returns an error if the position translation fails (invalid UTF-16 offset)
/// or if the range is invalid (start after end). The function uses
/// `byte_offset_at_position` to translate LSP's UTF-16 based positions
/// to byte offsets in the Rust `String`.
///
/// # Performance
///
/// Uses `String::replace_range` for O(n) replacement where n is the
/// distance from start to end of the changed range.
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

/// Translates an LSP `Position` (UTF-16 code unit offset) to a byte offset in a `&str`.
///
/// LSP specifies character positions as UTF-16 code units, but Rust strings are
/// UTF-8 internally. This function bridges that gap by iterating through the
/// text and counting UTF-16 code units until the target position is reached.
///
/// # Parameters
///
/// - `text`: The document text to search within.
/// - `position`: The LSP `Position` containing a 0-based `line` and a
///   `character` offset measured in UTF-16 code units.
///
/// # Return Value
///
/// Returns `Some(byte_offset)` where `byte_offset` is the byte index in `text`
/// that corresponds to the given UTF-16 position. Returns `None` if:
/// - The target line does not exist in the text
/// - The target character offset is past the end of that line
///
/// # Why UTF-16?
///
/// The Language Server Protocol (LSP) uses UTF-16 code units for character
/// positions because it was designed around languages where string indexing
/// is O(1) (e.g., JavaScript, TypeScript). Many editors and IDEs that
/// implement LSP also use UTF-16 internally.
///
/// # Edge Cases
///
/// - Position at end of line (character == line length): returns the byte
///   offset of the newline character, or `text.len()` if it's the last line.
/// - Position at start of line (character == 0): returns the byte offset
///   of the first character in that line.
pub fn byte_offset_at_position(text: &str, position: Position) -> Option<usize> {
    let mut current_line: u32 = 0;
    let mut current_character_utf16: u32 = 0;

    for (index, ch) in text.char_indices() {
        if current_line == position.line && current_character_utf16 == position.character {
            return Some(index);
        }

        if ch == '\n' {
            // Check again after the newline: the position could be at the newline
            // character itself (e.g., cursor at end of line before the newline).
            // If we don't check here, we'd increment current_line and miss this
            // position forever.
            if current_line == position.line && current_character_utf16 == position.character {
                return Some(index);
            }
            current_line = current_line.saturating_add(1);
            current_character_utf16 = 0;
            continue;
        }

        if current_line == position.line {
            current_character_utf16 = current_character_utf16.saturating_add(ch.len_utf16() as u32);
            // If we've overshot the target character, the position is invalid
            // (character is between two characters on this line).
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
/// LSP uses UTF-16 code units for character positions. This function computes
/// the length a string would have in UTF-16 encoding, which is needed for
/// translating between LSP character positions and Rust string indices.
///
/// # Why UTF-16 Length?
///
/// Most characters encode to a single UTF-16 code unit (2 bytes), but:
/// - Characters outside the Basic Multilingual Plane (BMP) encode to 2 code
///   units (4 bytes total) as a surrogate pair in UTF-16
/// - In UTF-8, such characters encode to 4 bytes
///
/// For example, emoji like `🚀` count as 2 UTF-16 code units but 1 Rust `char`.
///
/// # Return Value
///
/// Returns the total count of UTF-16 code units in the string.
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

    // ─────────────────────────────────────────────────────────────────────────
    // split_lines() edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn split_lines_empty_string_returns_empty_vec() {
        let lines = split_lines("");
        assert!(lines.is_empty());
    }

    #[test]
    fn split_lines_single_line_no_newline() {
        let lines = split_lines("hello world");
        assert_eq!(lines, vec!["hello world"]);
    }

    #[test]
    fn split_lines_only_newline_returns_two_empty_strings() {
        // "\n".split('\n') produces ["", ""] — empty string before and after the newline
        let lines = split_lines("\n");
        assert_eq!(lines, vec!["", ""]);
    }

    #[test]
    fn split_lines_multiple_consecutive_newlines() {
        let lines = split_lines("\n\n\n");
        // Three newlines produce four empty strings
        assert_eq!(lines, vec!["", "", "", ""]);
    }

    #[test]
    fn split_lines_trailing_newline() {
        // "a\nb\n" split gives ["a", "b", ""] — empty string after the last newline
        let lines = split_lines("a\nb\n");
        assert_eq!(lines, vec!["a", "b", ""]);
    }

    #[test]
    fn split_lines_leading_newline() {
        // "\na\nb" split gives ["", "a", "b"] — empty string before the first newline
        let lines = split_lines("\na\nb");
        assert_eq!(lines, vec!["", "a", "b"]);
    }

    #[test]
    fn split_lines_windows_crlf_includes_cr_in_line() {
        // Windows "\r\n" is two characters; split on '\n' only, so '\r' stays in the line
        let lines = split_lines("line1\r\nline2\r\nline3");
        assert_eq!(lines, vec!["line1\r", "line2\r", "line3"]);
    }

    #[test]
    fn split_lines_unicode_emoji_handled_correctly() {
        let text = "hello\nworld 🚀\n";
        let lines = split_lines(text);
        assert_eq!(lines, vec!["hello", "world 🚀", ""]);
    }

    #[test]
    fn split_lines_mixed_whitespace() {
        let text = "  spaced\n\ttabbed\n\nempty line";
        let lines = split_lines(text);
        assert_eq!(lines, vec!["  spaced", "\ttabbed", "", "empty line"]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // changed_lines_between() edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn changed_lines_between_identical_texts_returns_empty() {
        let text = "one\ntwo\nthree\n";
        let changed = changed_lines_between(text, text);
        assert!(changed.is_empty());
    }

    #[test]
    fn changed_lines_between_empty_before_and_after() {
        let changed = changed_lines_between("", "");
        assert!(changed.is_empty());
    }

    #[test]
    fn changed_lines_between_added_lines_at_end() {
        // after has one more line than before
        let before = "one\ntwo\n";
        let after = "one\ntwo\nthree\n";
        let changed = changed_lines_between(before, after);
        // max_len = 4 (after has 4 elements: "one", "two", "three", "")
        // At index 2: before_lines[2] = Some(""), after_lines[2] = Some("three") → insert 3
        // At index 3: before_lines[3] = None, after_lines[3] = Some("") → insert 4
        assert_eq!(changed, BTreeSet::from([3, 4]));
    }

    #[test]
    fn changed_lines_between_removed_lines_after_shorter() {
        // after is shorter — lines in before beyond after's length are not reported
        let before = "one\ntwo\nthree\nfour\n";
        let after = "one\ntwo\n";
        let changed = changed_lines_between(before, after);
        // max_len = 5 (before has 5 elements: "one", "two", "three", "four", "")
        // At index 2: before_lines[2] = Some("three"), after_lines[2] = Some("") → insert 3
        // At index 3: before_lines[3] = Some("four"), after_lines[3] = None → index 3 < 3 is FALSE → skip
        assert_eq!(changed, BTreeSet::from([3]));
    }

    #[test]
    fn changed_lines_between_multiple_changes() {
        let before = "a\nb\nc\nd\ne\n";
        let after = "a\nX\nc\nY\ne\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2, 4]));
    }

    #[test]
    fn changed_lines_between_all_lines_changed() {
        let before = "old\nold\nold\n";
        let after = "new\nnew\nnew\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([1, 2, 3]));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // build_synthetic_diff() edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn build_synthetic_diff_empty_changed_lines() {
        let diff = build_synthetic_diff("test.rs", "one\ntwo\nthree\n", &BTreeSet::new());
        assert!(diff.contains("diff --git"));
        // Should only have the header, no hunks
        assert!(!diff.contains("@@"));
    }

    #[test]
    fn build_synthetic_diff_line_number_exceeds_text_length() {
        // Line 99 doesn't exist in a 3-line document — should be skipped silently
        let changed = BTreeSet::from([99_u32]);
        let diff = build_synthetic_diff("test.rs", "one\ntwo\nthree\n", &changed);
        // Should not contain any hunk for line 99
        assert!(!diff.contains("+99"));
    }

    #[test]
    fn build_synthetic_diff_single_line_text() {
        let changed = BTreeSet::from([1_u32]);
        let diff = build_synthetic_diff("test.rs", "only one line\n", &changed);
        assert!(diff.contains("+only one line"));
    }

    #[test]
    fn build_synthetic_diff_zero_line_number_skipped() {
        // Line 0 should be skipped per implementation
        let changed = BTreeSet::from([0_u32, 1_u32, 2_u32]);
        let diff = build_synthetic_diff("test.rs", "a\nb\n", &changed);
        // Should contain lines 1 and 2 but not 0
        assert!(diff.contains("+a"));
        assert!(diff.contains("+b"));
        // Should not contain hunk header for line 0
        assert!(!diff.contains("@@ -0,0 +0,1 @@"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // byte_offset_at_position() edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn byte_offset_at_position_start_of_line() {
        let text = "hello\nworld";
        // Position (0, 0) is the start of "hello"
        let offset = byte_offset_at_position(text, Position::new(0, 0));
        assert_eq!(offset, Some(0));
    }

    #[test]
    fn byte_offset_at_position_end_of_line() {
        let text = "hello\nworld";
        // Position (0, 5) is after "hello" (at the \n)
        let offset = byte_offset_at_position(text, Position::new(0, 5));
        assert_eq!(offset, Some(5));
    }

    #[test]
    fn byte_offset_at_position_past_end_of_text() {
        let text = "hello";
        // Position (0, 100) is past the end of "hello"
        let offset = byte_offset_at_position(text, Position::new(0, 100));
        assert_eq!(offset, None);
    }

    #[test]
    fn byte_offset_at_position_nonexistent_line() {
        let text = "hello\nworld";
        // Line 99 doesn't exist
        let offset = byte_offset_at_position(text, Position::new(99, 0));
        assert_eq!(offset, None);
    }

    #[test]
    fn byte_offset_at_position_emoji_two_utf16_units() {
        // Emoji '🚀' is 1 Rust char but 2 UTF-16 code units
        // In "a🚀b": 'a'=UTF16:0, emoji first unit=1, emoji second unit=2, 'b'=3
        let text = "a🚀b";
        // Position (0, 1) should be at byte 1 ('a' ends, emoji starts)
        assert_eq!(byte_offset_at_position(text, Position::new(0, 1)), Some(1));
        // Position (0, 3) should be at byte 5 ('b')
        assert_eq!(byte_offset_at_position(text, Position::new(0, 3)), Some(5));
        // Position (0, 2) is in the middle of emoji's surrogate pair — invalid UTF-16
        assert_eq!(byte_offset_at_position(text, Position::new(0, 2)), None);
    }

    #[test]
    fn byte_offset_at_position_last_line_without_newline() {
        let text = "line1\nline2";
        // Last line without trailing newline — position at end of "line2"
        assert_eq!(byte_offset_at_position(text, Position::new(1, 5)), Some(11));
        // Past the end
        assert_eq!(byte_offset_at_position(text, Position::new(1, 100)), None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // utf16_length() edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn utf16_length_ascii_only() {
        // ASCII chars are 1 UTF-16 code unit each
        assert_eq!(utf16_length("hello"), 5);
        assert_eq!(utf16_length(""), 0);
        assert_eq!(utf16_length("a"), 1);
    }

    #[test]
    fn utf16_length_emoji_counts_as_two() {
        // Emoji '🚀' counts as 2 UTF-16 code units
        assert_eq!(utf16_length("🚀"), 2);
        assert_eq!(utf16_length("a🚀b"), 4); // a=1, 🚀=2, b=1
    }

    #[test]
    fn utf16_length_mixed_text() {
        // "hi 🚀" → 'h'=1, 'i'=1, ' '=1, '🚀'=2 = 5
        assert_eq!(utf16_length("hi 🚀"), 5);
    }

    #[test]
    fn utf16_length_cjk_characters() {
        // CJK characters in BMP are 1 Rust char but 1 UTF-16 code unit
        assert_eq!(utf16_length("中文"), 2);
    }
}
