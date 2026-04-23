use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use lsp_types::{Position, TextDocumentContentChangeEvent};

/// Splits text into lines by newline characters, preserving the lines themselves.
///
/// Unlike `str::lines()`, this does not trim trailing empty strings when the
/// text ends with a newline. Returns an empty vector for empty input.
pub fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').collect()
    }
}

/// Returns the set of line numbers (1-indexed) that differ between `before` and `after`.
///
/// Compares the two texts line-by-line and returns a `BTreeSet` of line numbers
/// (starting from 1) that exist in `after` but differ from the corresponding line
/// in `before`.
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

/// Builds a synthetic unified diff that marks the given lines as added.
///
/// The returned diff marks each line in `changed_lines` as a new addition in a
/// unified diff format. This is used to synthesize diff content for LSP
/// diagnostics when only line-change information is available.
///
/// Returns a string that must be used (not ignored), as discarding it loses
/// the diagnostic information.
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

/// Applies a text document content change event to the given text in-place.
///
/// This handles both full document replacements (when `range` is `None`) and
/// incremental range edits. The `change.range` and `change.range_length` are
/// interpreted as UTF-16 code units, consistent with the LSP specification.
///
/// Returns an error if the range boundaries are invalid (start after end or
/// past the end of the text).
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

/// Converts an LSP character position (UTF-16 code units) to a byte offset in the string.
///
/// The LSP specification uses UTF-16 code units for character positions within a line.
/// This function converts that position to a byte offset that can be used with Rust's
/// string slicing. Returns `None` if the position is beyond the text.
///
/// When the position falls within a multi-byte UTF-8 character, the byte offset
/// returned points to the start of that character.
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

/// Returns the length of the text in UTF-16 code units.
///
/// This is the number of code units needed to represent the text in UTF-16 encoding,
/// which is what the LSP specification uses for character positions. For ASCII text,
/// this equals the number of characters; for text containing non-ASCII characters,
/// this will be larger than the number of Rust `char` values.
///
/// The return value must be used — ignoring it means the caller may not correctly
/// handle text content when interfacing with LSP clients.
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

    // === utf16_length edge case tests ===

    #[test]
    fn utf16_length_empty_string_returns_zero() {
        assert_eq!(utf16_length(""), 0);
    }

    #[test]
    fn utf16_length_ascii_only_returns_char_count() {
        // ASCII chars: each is exactly 1 UTF-16 code unit
        assert_eq!(utf16_length("a"), 1);
        assert_eq!(utf16_length("hello"), 5);
        assert_eq!(utf16_length("Hello, World!"), 13);
    }

    #[test]
    fn utf16_length_bmp_non_ascii_returns_correct_count() {
        // Latin-1 Supplement characters (U+00C0-U+00FF): 1 UTF-16 code unit each
        assert_eq!(utf16_length("é"), 1);
        assert_eq!(utf16_length("ñ"), 1);
        assert_eq!(utf16_length("ü"), 1);
        assert_eq!(utf16_length("Ç"), 1);

        // Cyrillic: 1 UTF-16 code unit per char
        assert_eq!(utf16_length("Привет"), 6);

        // Chinese characters (BMP): 1 UTF-16 code unit per char
        assert_eq!(utf16_length("中文"), 2);

        // Japanese Hiragana: 1 UTF-16 code unit per char
        assert_eq!(utf16_length("こんにちは"), 5);
    }

    #[test]
    fn utf16_length_emoji_requires_two_code_units() {
        // Emoji U+1F600 (Grinning Face) is beyond U+FFFF → requires surrogate pair → 2 UTF-16 code units
        assert_eq!(utf16_length("😀"), 2);
        // Multiple emoji
        assert_eq!(utf16_length("😀😀"), 4);
        // Mixed emoji and ASCII: h(1) + i(1) + 😀(2) = 4
        assert_eq!(utf16_length("hi😀"), 4);
    }

    #[test]
    fn utf16_length_mixed_scripts_returns_correct_count() {
        // "Héllo世界😀": H(1)+é(1)+l(1)+l(1)+o(1)+世(1)+界(1)+😀(2) = 9 UTF-16 code units
        assert_eq!(utf16_length("Héllo世界😀"), 9);
    }

    #[test]
    fn utf16_length_newlines_and_whitespace() {
        // \n is 1 UTF-16 code unit
        assert_eq!(utf16_length("\n"), 1);
        assert_eq!(utf16_length("a\nb"), 3);
        // tab
        assert_eq!(utf16_length("\t"), 1);
        assert_eq!(utf16_length("a\tb"), 3);
    }

    #[test]
    fn utf16_length_combining_characters() {
        // Precomposed é (U+00E9) → 1 UTF-16 code unit
        assert_eq!(utf16_length("é"), 1);
        // Decomposed: e (U+0065) + combining acute (U+0301) → 2 UTF-16 code units
        assert_eq!(utf16_length("e\u{0301}"), 2);
    }

    #[test]
    fn utf16_length_zero_width_and_control_characters() {
        // Zero-width space (U+200B) → 1 UTF-16 code unit
        assert_eq!(utf16_length("\u{200B}"), 1);
        // BOM (U+FEFF) → 1 UTF-16 code unit
        assert_eq!(utf16_length("\u{FEFF}"), 1);
        // Null character → 1 UTF-16 code unit
        assert_eq!(utf16_length("\0"), 1);
    }

    #[test]
    fn utf16_length_surrogate_pair_characters_beyond_bmp() {
        // Musical G clef symbol (U+1D11E) → requires surrogate pair → 2 UTF-16 code units
        assert_eq!(utf16_length("\u{1D11E}"), 2);
        // Gothic letter (U+10330) → 2 UTF-16 code units
        assert_eq!(utf16_length("\u{10330}"), 2);
    }

    // === Property-based tests (proptest) ===

    #[test]
    fn utf16_length_equals_manual_char_sum() {
        // utf16_length(s) must equal sum of each char's len_utf16
        use proptest::prelude::*;
        proptest!(|(s in ".*")| {
            let expected: u32 = s.chars().map(|ch| ch.len_utf16() as u32).sum();
            prop_assert_eq!(utf16_length(&s), expected);
        });
    }

    #[test]
    fn utf16_length_ascii_equals_byte_length() {
        // For ASCII-only strings, utf16_length == byte length
        use proptest::prelude::*;
        proptest!(|(s in ".*")| {
            // Check only for strings that are purely ASCII
            if s.is_ascii() {
                prop_assert_eq!(utf16_length(&s), s.len() as u32);
            }
        });
    }

    #[test]
    fn utf16_length_additive_concatenation() {
        // utf16_length(a ++ b) == utf16_length(a) + utf16_length(b)
        use proptest::prelude::*;
        proptest!(|
            (a in ".*", b in ".*")|
        {
            let combined = format!("{}{}", a, b);
            prop_assert_eq!(
                utf16_length(&combined),
                utf16_length(&a).saturating_add(utf16_length(&b))
            );
        });
    }

    #[test]
    fn utf16_length_bounded_by_char_count() {
        // For any string: char_count <= utf16_length <= char_count * 2
        // (each char is at least 1 UTF-16 unit, at most 2)
        use proptest::prelude::*;
        proptest!(|(s in ".*")| {
            let char_count = s.chars().count() as u32;
            let result = utf16_length(&s);
            prop_assert!(result >= char_count, "utf16_length {} < char_count {}", result, char_count);
            prop_assert!(result <= char_count.saturating_mul(2), "utf16_length {} > char_count * 2 {}", result, char_count);
        });
    }

    #[test]
    fn utf16_length_bounded_by_byte_length() {
        // utf16_length(s) <= bytes * 2 (worst case: every byte is a leading byte of a 4-byte char)
        use proptest::prelude::*;
        proptest!(|(s in ".*")| {
            let byte_len = s.len() as u32;
            let result = utf16_length(&s);
            prop_assert!(result <= byte_len.saturating_mul(2),
                "utf16_length {} > bytes * 2 = {}", result, byte_len * 2);
        });
    }

    #[test]
    fn utf16_length_non_empty_positive() {
        // Non-empty strings must have utf16_length >= 1
        use proptest::prelude::*;
        proptest!(|(s in "[^\\x00]{1,200}")| {
            prop_assert!(utf16_length(&s) >= 1, "non-empty string has utf16_length 0");
        });
    }

    #[test]
    fn utf16_length_returns_u32_compatible_value() {
        // utf16_length returns u32, which is what LSP uses for character positions
        // This is a compile-time verification - no runtime test needed
        // The return type itself guarantees u32 compatibility
    }

    #[test]
    fn utf16_length_single_bmp_char_is_one() {
        // Any single BMP character (U+0000 to U+FFFF, excluding surrogates) has utf16_length == 1
        use proptest::prelude::*;
        // Generate a random BMP char (not a surrogate) by filtering the full u32 range
        proptest!(|(ch in 0x0000u32..0xFFFFu32)| {
            // Skip surrogate range 0xD800..0xE000
            if (0xD800..0xE000).contains(&ch) {
                return Ok(());
            }
            if let Some(c) = char::from_u32(ch) {
                let s = c.to_string();
                prop_assert_eq!(utf16_length(&s), 1,
                    "BMP char U+{:04X} expected len 1, got {}", ch, utf16_length(&s));
            }
        });
    }

    #[test]
    fn utf16_length_single_non_bmp_char_is_two() {
        // Any single non-BMP character (U+10000+) has utf16_length == 2
        use proptest::prelude::*;
        // Generate a random non-BMP char
        proptest!(|(ch in 0x10000u32..0x10FFFFu32)| {
            let s = char::from_u32(ch).unwrap().to_string();
            prop_assert_eq!(utf16_length(&s), 2,
                "Non-BMP char U+{:04X} expected len 2, got {}", ch, utf16_length(&s));
        });
    }
}
