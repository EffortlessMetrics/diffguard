//! Green Edge Case Tests for diffguard-lsp text processing
//!
//! These tests verify edge cases in the text processing functions used by the LSP server.
//! They complement the behavioral tests in the red test file and the unit tests in text.rs.
//!
//! Edge cases covered:
//! - Empty text handling in split_lines
//! - Empty and boundary cases in changed_lines_between
//! - Full-document replacement (range=None) in apply_incremental_change
//! - UTF-16 length calculation for various Unicode scenarios
//! - Byte offset calculation for UTF-8/UTF-16 mismatches
//! - Synthetic diff generation with edge case line numbers

use diffguard_lsp::text::{
    apply_incremental_change, build_synthetic_diff, byte_offset_at_position, changed_lines_between,
    split_lines, utf16_length,
};
use lsp_types::{Position, Range, TextDocumentContentChangeEvent};
use std::collections::BTreeSet;

// ============================================================================
// split_lines edge cases
// Note: split_lines uses text.split('\n').collect(), so "\n" gives ["", ""]
// ============================================================================

#[test]
fn test_split_lines_empty_string() {
    let result = split_lines("");
    assert_eq!(result, Vec::<&str>::new());
}

#[test]
fn test_split_lines_only_newline() {
    // "\n" split by '\n' gives ["", ""] - before and after the newline
    let result = split_lines("\n");
    assert_eq!(result, vec!["", ""]);
}

#[test]
fn test_split_lines_multiple_empty_lines() {
    // "\n\n\n" gives ["", "", "", ""]
    let result = split_lines("\n\n\n");
    assert_eq!(result, vec!["", "", "", ""]);
}

#[test]
fn test_split_lines_trailing_newline() {
    // "line1\nline2\n" gives ["line1", "line2", ""]
    let result = split_lines("line1\nline2\n");
    assert_eq!(result, vec!["line1", "line2", ""]);
}

#[test]
fn test_split_lines_no_newline() {
    let result = split_lines("no newline at end");
    assert_eq!(result, vec!["no newline at end"]);
}

#[test]
fn test_split_lines_single_line_no_newline() {
    let result = split_lines("single");
    assert_eq!(result, vec!["single"]);
}

// ============================================================================
// changed_lines_between edge cases
// The function marks lines as changed if they differ AND index < after_lines.len()
// ============================================================================

#[test]
fn test_changed_lines_between_identical_text() {
    let text = "same\ncontent\nhere\n";
    let changed = changed_lines_between(text, text);
    assert!(changed.is_empty());
}

#[test]
fn test_changed_lines_between_empty_to_content() {
    // "" -> ["new", "content", ""] = 3 lines
    // All 3 lines are marked changed
    let before = "";
    let after = "new\ncontent\n";
    let changed = changed_lines_between(before, after);
    assert_eq!(changed, BTreeSet::from([1, 2, 3]));
}

#[test]
fn test_changed_lines_between_content_to_empty() {
    // "some\ncontent\n" -> [] = 0 lines
    // No lines marked because index < 0 is never true
    let before = "some\ncontent\n";
    let after = "";
    let changed = changed_lines_between(before, after);
    assert!(changed.is_empty());
}

#[test]
fn test_changed_lines_between_add_lines_at_end() {
    // "line1\nline2\n" has 3 split lines (last is empty after trailing \n)
    // "line1\nline2\nline3\n" has 4 split lines
    let before = "line1\nline2\n";
    let after = "line1\nline2\nline3\n";
    let changed = changed_lines_between(before, after);
    // Line 3 (empty to "line3") and line 4 (None to empty) are both different
    assert_eq!(changed, BTreeSet::from([3, 4]));
}

#[test]
fn test_changed_lines_between_remove_last_line() {
    let before = "line1\nline2\nline3\n";
    let after = "line1\nline2\n";
    let changed = changed_lines_between(before, after);
    // Line 3 changed, line 4 doesn't exist in after so not marked
    assert_eq!(changed, BTreeSet::from([3]));
}

#[test]
fn test_changed_lines_between_replace_multiple_contiguous_lines() {
    let before = "line1\nline2\nline3\nline4\n";
    let after = "line1\nnew2\nnew3\nline4\n";
    let changed = changed_lines_between(before, after);
    assert_eq!(changed, BTreeSet::from([2, 3]));
}

#[test]
fn test_changed_lines_between_all_lines_changed() {
    let before = "original\ncontent\nhere\n";
    let after = "completely\ndifferent\nnow\n";
    let changed = changed_lines_between(before, after);
    assert_eq!(changed, BTreeSet::from([1, 2, 3]));
}

#[test]
fn test_changed_lines_between_single_line_to_different_single_line() {
    // "a\n" -> ["a", ""], "b\n" -> ["b", ""]
    let before = "a\n";
    let after = "b\n";
    let changed = changed_lines_between(before, after);
    // Both line 1 (a->b) and line 2 (empty->empty? no wait)
    // Let me trace: before_lines=["a",""], after_lines=["b",""]
    // index 0: "a" != "b" and 0 < 2 -> insert 1
    // index 1: "" == "" -> not insert
    assert_eq!(changed, BTreeSet::from([1]));
}

// ============================================================================
// apply_incremental_change edge cases
// ============================================================================

#[test]
fn test_apply_incremental_change_full_document_empty_to_content() {
    let mut text = String::new();
    let change = TextDocumentContentChangeEvent {
        range: None,
        range_length: None,
        text: "new content".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "new content");
}

#[test]
fn test_apply_incremental_change_full_document_content_to_empty() {
    let mut text = "some content".to_string();
    let change = TextDocumentContentChangeEvent {
        range: None,
        range_length: None,
        text: String::new(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "");
}

#[test]
fn test_apply_incremental_change_full_document_unicode() {
    let mut text = "日本語テスト".to_string();
    let change = TextDocumentContentChangeEvent {
        range: None,
        range_length: None,
        text: "変更された内容".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "変更された内容");
}

#[test]
fn test_apply_incremental_change_full_document_emoji() {
    let mut text = "Hello 👋 World".to_string();
    let change = TextDocumentContentChangeEvent {
        range: None,
        range_length: None,
        text: "Goodbye 👋👋".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "Goodbye 👋👋");
}

#[test]
fn test_apply_incremental_change_full_document_multiline() {
    let mut text = "line1\nline2\nline3".to_string();
    let change = TextDocumentContentChangeEvent {
        range: None,
        range_length: None,
        text: "modified\nmulti\nline\ncontent\n".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "modified\nmulti\nline\ncontent\n");
}

#[test]
fn test_apply_incremental_change_insert_at_beginning() {
    let mut text = "existing content".to_string();
    let change = TextDocumentContentChangeEvent {
        range: Some(Range::new(Position::new(0, 0), Position::new(0, 0))),
        range_length: None,
        text: "prefix ".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "prefix existing content");
}

#[test]
fn test_apply_incremental_change_insert_at_end() {
    let mut text = "original".to_string();
    let change = TextDocumentContentChangeEvent {
        range: Some(Range::new(Position::new(0, 8), Position::new(0, 8))),
        range_length: None,
        text: " suffix".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "original suffix");
}

#[test]
fn test_apply_incremental_change_delete_range() {
    // "hello world", delete "world" (positions 6..11)
    let mut text = "hello world".to_string();
    let change = TextDocumentContentChangeEvent {
        range: Some(Range::new(Position::new(0, 6), Position::new(0, 11))),
        range_length: None,
        text: String::new(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "hello ");
}

#[test]
fn test_apply_incremental_change_replace_exact_text() {
    // "hello world", replace "world" with "rust":
    // "hello " = 6 chars, "world" = positions 6..11
    let mut text = "hello world".to_string();
    let change = TextDocumentContentChangeEvent {
        range: Some(Range::new(Position::new(0, 6), Position::new(0, 11))),
        range_length: None,
        text: "rust".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "hello rust");
}

#[test]
fn test_apply_incremental_change_multiline_insert() {
    let mut text = "line1\nline2".to_string();
    let change = TextDocumentContentChangeEvent {
        range: Some(Range::new(Position::new(1, 0), Position::new(1, 0))),
        range_length: None,
        text: "inserted\n".to_string(),
    };
    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "line1\ninserted\nline2");
}

// ============================================================================
// utf16_length edge cases
// ============================================================================

#[test]
fn test_utf16_length_empty_string() {
    assert_eq!(utf16_length(""), 0);
}

#[test]
fn test_utf16_length_ascii() {
    assert_eq!(utf16_length("hello"), 5);
}

#[test]
fn test_utf16_length_multibyte_characters() {
    // "日本語" has 3 characters
    // Each CJK character is 1 UTF-16 code unit
    assert_eq!(utf16_length("日本語"), 3);
}

#[test]
fn test_utf16_length_emoji() {
    // Emoji like 👋 are surrogate pairs in UTF-16 (2 code units)
    assert_eq!(utf16_length("👋"), 2);
}

#[test]
fn test_utf16_length_mixed_ascii_and_emoji() {
    // "Hi 👋" -> H(1)+i(1)+space(1)+👋(2) = 5
    assert_eq!(utf16_length("Hi 👋"), 5);
}

#[test]
fn test_utf16_length_multiple_emoji() {
    // "👋👋" -> 2 + 2 = 4
    assert_eq!(utf16_length("👋👋"), 4);
}

#[test]
fn test_utf16_length_japanese_and_emoji() {
    // "日本語👋" -> 3 + 2 = 5
    assert_eq!(utf16_length("日本語👋"), 5);
}

// ============================================================================
// byte_offset_at_position edge cases
// ============================================================================

#[test]
fn test_byte_offset_at_position_start_of_text() {
    let text = "hello";
    let offset = byte_offset_at_position(text, Position::new(0, 0));
    assert_eq!(offset, Some(0));
}

#[test]
fn test_byte_offset_at_position_middle_of_text() {
    let text = "hello";
    let offset = byte_offset_at_position(text, Position::new(0, 2));
    assert_eq!(offset, Some(2));
}

#[test]
fn test_byte_offset_at_position_end_of_text() {
    let text = "hello";
    let offset = byte_offset_at_position(text, Position::new(0, 5));
    assert_eq!(offset, Some(5));
}

#[test]
fn test_byte_offset_at_position_newline() {
    let text = "line1\nline2";
    // Position at start of line2 (after newline at byte 6)
    let offset = byte_offset_at_position(text, Position::new(1, 0));
    assert_eq!(offset, Some(6));
}

#[test]
fn test_byte_offset_at_position_utf8_multibyte() {
    let text = "日本語"; // Each char is 3 bytes in UTF-8
    // Position at first character
    let offset = byte_offset_at_position(text, Position::new(0, 0));
    assert_eq!(offset, Some(0));
    // Position at second character (byte 3)
    let offset = byte_offset_at_position(text, Position::new(0, 1));
    assert_eq!(offset, Some(3));
    // Position at third character (byte 6)
    let offset = byte_offset_at_position(text, Position::new(0, 2));
    assert_eq!(offset, Some(6));
}

#[test]
fn test_byte_offset_at_position_past_end_returns_none() {
    let text = "hello";
    let offset = byte_offset_at_position(text, Position::new(0, 10));
    assert_eq!(offset, None);
}

#[test]
fn test_byte_offset_at_position_past_line_end_returns_none() {
    let text = "hello";
    let offset = byte_offset_at_position(text, Position::new(0, 100));
    assert_eq!(offset, None);
}

#[test]
fn test_byte_offset_at_position_second_line_past_end() {
    let text = "line1\nline2";
    let offset = byte_offset_at_position(text, Position::new(1, 100));
    assert_eq!(offset, None);
}

// ============================================================================
// build_synthetic_diff edge cases
// ============================================================================

#[test]
fn test_build_synthetic_diff_empty_set() {
    let diff = build_synthetic_diff("test.txt", "some content", &BTreeSet::new());
    assert!(diff.contains("diff --git a/test.txt b/test.txt"));
}

#[test]
fn test_build_synthetic_diff_single_line() {
    let diff = build_synthetic_diff("test.txt", "content", &BTreeSet::from([1]));
    assert!(diff.contains("+content"));
}

#[test]
fn test_build_synthetic_diff_skips_line_zero() {
    // Line 0 should be skipped per the function's implementation
    let diff = build_synthetic_diff("test.txt", "line1\nline2", &BTreeSet::from([0, 1, 2]));
    // Line 0 is skipped, lines 1 and 2 are included
    assert!(diff.contains("+line1"));
    assert!(diff.contains("+line2"));
    // Should NOT contain hunk for line 0
    assert!(!diff.contains("@@ -0,0 +0,1 @@"));
}

#[test]
fn test_build_synthetic_diff_skips_past_end_lines() {
    let diff = build_synthetic_diff(
        "test.txt",
        "line1\nline2",
        &BTreeSet::from([1, 2, 100]), // 100 is past the end
    );
    assert!(diff.contains("+line1"));
    assert!(diff.contains("+line2"));
    // Should not have hunk for line 100 (past end of content)
    assert!(!diff.contains("+100"));
}

#[test]
fn test_build_synthetic_diff_multiple_lines() {
    let changed = BTreeSet::from([1_u32, 3_u32, 5_u32]);
    let diff = build_synthetic_diff("test.txt", "l1\nl2\nl3\nl4\nl5\n", &changed);
    assert!(diff.contains("+l1"));
    assert!(diff.contains("+l3"));
    assert!(diff.contains("+l5"));
}

// ============================================================================
// Integration: DocumentState-like workflow tests
// ============================================================================

#[test]
fn test_changed_lines_after_multiple_edits() {
    // Simulate: open doc -> edit line 2 -> edit line 5 -> save -> check changed lines
    let baseline = "line1\nline2\nline3\nline4\nline5\n";

    // After editing lines 2 and 5
    let after_edit = "line1\nMODIFIED\nline3\nline4\nMODIFIED\n";
    let changed = changed_lines_between(baseline, after_edit);
    assert_eq!(changed, BTreeSet::from([2, 5]));
}

#[test]
fn test_full_document_replacement_preserves_changed_lines_tracking() {
    // When full document replacement happens, all lines are potentially changed
    let baseline = "l1\nl2\nl3\n";
    let after_full_replace = "completely\ndifferent\ncontent\n";
    let changed = changed_lines_between(baseline, after_full_replace);
    assert_eq!(changed, BTreeSet::from([1, 2, 3]));
}

#[test]
fn test_split_lines_handles_cr_lf_windows_line_endings() {
    // split('\n') on "a\r\nb" gives ["a\r", "b"]
    let result = split_lines("line1\r\nline2");
    assert_eq!(result, vec!["line1\r", "line2"]);
}
