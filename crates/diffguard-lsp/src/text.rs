use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

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

    #[test]
    fn split_lines_returns_empty_for_empty_input() {
        assert!(split_lines("").is_empty());
    }

    #[test]
    fn split_lines_handles_single_line_without_newline() {
        assert_eq!(split_lines("hello"), vec!["hello"]);
    }

    #[test]
    fn changed_lines_between_returns_empty_for_identical_text() {
        let same = "a\nb\nc\n";
        assert!(changed_lines_between(same, same).is_empty());
    }

    #[test]
    fn changed_lines_between_marks_truncation_boundary_only() {
        // When `after` is shorter than `before`, only indices that still exist in `after`
        // can be reported. The trailing empty string from a final newline counts as an index.
        let before = "a\nb\nc\nd\n";
        let after = "a\nb\n";
        // before split = ["a","b","c","d",""], after split = ["a","b",""].
        // Differences within after's range: index 2 ("c" vs "") -> reports line 3.
        assert_eq!(
            changed_lines_between(before, after),
            BTreeSet::from([3_u32])
        );
    }

    #[test]
    fn build_synthetic_diff_skips_line_number_zero() {
        let changed = BTreeSet::from([0_u32, 1_u32]);
        let diff = build_synthetic_diff("src/lib.rs", "one\ntwo\n", &changed);
        assert!(!diff.contains("@@ -0,0 +0,"));
        assert!(diff.contains("@@ -0,0 +1,1 @@"));
        assert!(diff.contains("+one"));
    }

    #[test]
    fn build_synthetic_diff_skips_out_of_range_lines() {
        let changed = BTreeSet::from([1_u32, 99_u32]);
        let diff = build_synthetic_diff("src/lib.rs", "only\n", &changed);
        assert!(diff.contains("+only"));
        assert!(!diff.contains("+99"));
        assert_eq!(diff.matches("@@ -0,0").count(), 1);
    }

    #[test]
    fn build_synthetic_diff_emits_header_even_with_no_changes() {
        let changed = BTreeSet::new();
        let diff = build_synthetic_diff("src/lib.rs", "x\n", &changed);
        assert!(diff.contains("diff --git a/src/lib.rs b/src/lib.rs"));
        assert!(diff.contains("--- a/src/lib.rs"));
        assert!(diff.contains("+++ b/src/lib.rs"));
        assert!(!diff.contains("@@"));
    }

    #[test]
    fn apply_incremental_change_with_no_range_replaces_whole_text() {
        let mut text = "old contents".to_string();
        let change = TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "new contents".to_string(),
        };
        apply_incremental_change(&mut text, &change).expect("apply");
        assert_eq!(text, "new contents");
    }

    #[test]
    fn apply_incremental_change_errors_on_invalid_start_position() {
        let mut text = "alpha\n".to_string();
        let change = TextDocumentContentChangeEvent {
            range: Some(Range::new(Position::new(99, 0), Position::new(99, 0))),
            range_length: None,
            text: "x".to_string(),
        };
        let err = apply_incremental_change(&mut text, &change).expect_err("must err");
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid start position"), "got: {msg}");
    }

    #[test]
    fn apply_incremental_change_errors_on_invalid_end_position() {
        let mut text = "alpha\nbeta\n".to_string();
        let change = TextDocumentContentChangeEvent {
            range: Some(Range::new(Position::new(0, 0), Position::new(99, 0))),
            range_length: None,
            text: "x".to_string(),
        };
        let err = apply_incremental_change(&mut text, &change).expect_err("must err");
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid end position"), "got: {msg}");
    }

    #[test]
    fn apply_incremental_change_errors_when_start_after_end() {
        // Build a text where line 1 has character 5 valid but line 0 has only character 0.
        // Then craft start=(1,0), end=(0,0) so start > end after resolving offsets.
        let mut text = "ab\ncd\n".to_string();
        let change = TextDocumentContentChangeEvent {
            range: Some(Range::new(Position::new(1, 0), Position::new(0, 0))),
            range_length: None,
            text: "x".to_string(),
        };
        let err = apply_incremental_change(&mut text, &change).expect_err("must err");
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid edit range"), "got: {msg}");
    }

    #[test]
    fn byte_offset_at_position_returns_end_for_position_at_text_end() {
        let text = "abc";
        let pos = Position::new(0, 3);
        assert_eq!(byte_offset_at_position(text, pos), Some(text.len()));
    }

    #[test]
    fn byte_offset_at_position_returns_none_for_past_end() {
        let text = "abc";
        let pos = Position::new(0, 10);
        assert_eq!(byte_offset_at_position(text, pos), None);
    }

    #[test]
    fn byte_offset_at_position_returns_none_for_past_last_line() {
        let text = "abc\n";
        let pos = Position::new(5, 0);
        assert_eq!(byte_offset_at_position(text, pos), None);
    }

    #[test]
    fn byte_offset_at_position_returns_none_for_character_beyond_line_length() {
        let text = "abc\ndef\n";
        let pos = Position::new(0, 10);
        assert_eq!(byte_offset_at_position(text, pos), None);
    }

    #[test]
    fn byte_offset_at_position_handles_multibyte_characters() {
        // "café" — 'é' is two UTF-16 code units only when it's a surrogate pair, but here it's one.
        // Use a non-BMP character to exercise the utf16 width path: '𝄞' (U+1D11E) is 2 utf16 units.
        let text = "a𝄞b";
        assert_eq!(byte_offset_at_position(text, Position::new(0, 0)), Some(0));
        assert_eq!(byte_offset_at_position(text, Position::new(0, 1)), Some(1));
        // After 'a' (1 utf16 unit) + '𝄞' (2 utf16 units) we are at character 3 of line 0.
        assert_eq!(
            byte_offset_at_position(text, Position::new(0, 3)),
            Some("a𝄞".len())
        );
    }

    #[test]
    fn utf16_length_counts_surrogate_pairs() {
        assert_eq!(utf16_length(""), 0);
        assert_eq!(utf16_length("abc"), 3);
        // '𝄞' (U+1D11E) is encoded as a surrogate pair in UTF-16 (length 2).
        assert_eq!(utf16_length("a𝄞b"), 4);
    }
}
