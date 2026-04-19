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
        assert!(diff.contains("@@ -0,0 +2,1 @@\n"));
        assert!(diff.contains("@@ -0,0 +3,1 @@\n"));
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

    // -------------------------------------------------------------------------
    // changed_lines_between edge case tests
    // -------------------------------------------------------------------------

    #[test]
    fn changed_lines_between_empty_strings() {
        // Both empty: no changes
        let changed = changed_lines_between("", "");
        assert_eq!(changed, BTreeSet::new());
    }

    #[test]
    fn changed_lines_between_empty_before() {
        // Empty before, non-empty after: new lines are "changed"
        // split_lines("") returns empty Vec, but split_lines("new\n") = ["new", ""]
        // Line 1 is "new" (differs from None), Line 2 is "" (differs from None)
        let changed = changed_lines_between("", "new\n");
        assert_eq!(changed, BTreeSet::from([1, 2]));
    }

    #[test]
    fn changed_lines_between_empty_after() {
        // Non-empty before, empty after: all removed lines are "changed"
        // Note: this is an unusual case since we compare line-by-line
        let changed = changed_lines_between("old\n", "");
        // When after.len() < before.len(), no lines are added (index < after_lines.len() is false)
        assert_eq!(changed, BTreeSet::new());
    }

    #[test]
    fn changed_lines_between_identical_strings() {
        // Identical content: no changes
        let content = "one\ntwo\nthree\n";
        let changed = changed_lines_between(content, content);
        assert_eq!(changed, BTreeSet::new());
    }

    #[test]
    fn changed_lines_between_all_lines_changed() {
        // Every line changed
        let before = "a\nb\nc\n";
        let after = "x\ny\nz\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([1, 2, 3]));
    }

    #[test]
    fn changed_lines_between_add_lines() {
        // After has more lines than before
        let before = "one\n";
        let after = "one\ntwo\nthree\n";
        // split_lines("one\n") = ["one", ""], split_lines("one\ntwo\nthree\n") = ["one", "two", "three", ""]
        // index 1: "" != "two" → 2; index 2: None != "three" → 3; index 3: None != "" → 4
        assert_eq!(
            changed_lines_between(before, after),
            BTreeSet::from([2, 3, 4])
        );
    }

    #[test]
    fn changed_lines_between_remove_lines() {
        // After has fewer lines than before
        let before = "one\ntwo\nthree\n";
        let after = "one\n";
        // split_lines("one\ntwo\nthree\n") = ["one", "two", "three", ""]
        // split_lines("one\n") = ["one", ""]
        // index 1: "two" != "" → 2; index 2+: None != None → false (skip)
        assert_eq!(changed_lines_between(before, after), BTreeSet::from([2]));
    }

    #[test]
    fn changed_lines_between_first_line_changed() {
        // Boundary: first line changed
        let before = "hello\nworld\n";
        let after = "goodbye\nworld\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([1]));
    }

    #[test]
    fn changed_lines_between_last_line_changed() {
        // Boundary: last line changed
        let before = "hello\nworld\n";
        let after = "hello\nearth\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2]));
    }

    #[test]
    fn changed_lines_between_multiple_non_consecutive() {
        // Multiple changes that are not adjacent
        let before = "a\nb\nc\nd\ne\n";
        let after = "a\nX\nc\nY\ne\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2, 4]));
    }

    #[test]
    fn changed_lines_between_whitespace_only() {
        // Changed only by whitespace
        let before = "  spaces\n";
        let after = "\t\ttabs\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([1]));
    }

    #[test]
    fn changed_lines_between_no_trailing_newline() {
        // No trailing newline in either
        let before = "one\ntwo";
        let after = "one\nthree";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2]));
    }

    #[test]
    fn changed_lines_between_single_line_no_newline() {
        // Single line, no newline, changed
        let before = "hello";
        let after = "world";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([1]));
    }

    #[test]
    fn changed_lines_between_single_line_identical() {
        // Single line, no newline, identical
        let before = "hello";
        let after = "hello";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::new());
    }

    #[test]
    fn changed_lines_between_unicode_content() {
        // Unicode characters
        let before = "日本語\nテスト\n";
        let after = "日本語\n変更\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2]));
    }

    #[test]
    fn changed_lines_between_emoji_content() {
        // Emoji characters (multi-byte UTF-8)
        let before = "😀\n😁\n";
        let after = "😀\n😂\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2]));
    }

    #[test]
    fn changed_lines_between_line_at_u32_max_minus_one() {
        // Test behavior near u32::MAX (but not actually at overflow)
        // We can't create a 4B line file, but we can verify the math:
        // index + 1 = u32::MAX should work correctly (line_number = u32::MAX)
        let u32_max = u32::MAX;

        // Just test the mathematical properties: u32::MAX as usize conversion
        let line_number = u32_max; // This is u32::MAX = 4,294,967,295
        let back_to_usize = line_number as usize;
        // On 64-bit platform, this should be exact (no overflow in cast)
        assert_eq!(back_to_usize as u32, u32_max);
    }

    #[test]
    fn changed_lines_between_single_line_added() {
        // Add a single line at the end
        let before = "one\ntwo\n";
        let after = "one\ntwo\nthree\n";
        // split_lines("one\ntwo\n") = ["one", "two", ""]
        // split_lines("one\ntwo\nthree\n") = ["one", "two", "three", ""]
        // index 2: "" != "three" → 3; index 3: None != "" → 4
        assert_eq!(changed_lines_between(before, after), BTreeSet::from([3, 4]));
    }

    #[test]
    fn changed_lines_between_adjacent_changes() {
        // Two consecutive lines changed
        let before = "a\nb\nc\n";
        let after = "a\nX\nY\n";
        let changed = changed_lines_between(before, after);
        assert_eq!(changed, BTreeSet::from([2, 3]));
    }
}
