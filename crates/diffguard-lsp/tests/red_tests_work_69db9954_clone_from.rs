//! Red tests for clone_from() optimization in diffguard-lsp
//!
//! These tests verify that:
//! 1. Full-document replacement in `apply_incremental_change` works correctly
//! 2. The source code uses `clone_from()` instead of direct assignment for capacity reuse
//!
//! The `clone_from()` optimization reduces memory allocations when the target string
//! has sufficient capacity. These tests will FAIL until the implementation uses
//! `clone_from()` in the two identified locations:
//! - text.rs:63: `*text = change.text.clone();` → `text.clone_from(&change.text);`
//! - server.rs:92: `self.text = text;` → `self.text.clone_from(&text);`

use diffguard_lsp::text::apply_incremental_change;
use lsp_types::TextDocumentContentChangeEvent;
use std::fs;
use std::path::PathBuf;

// ============================================================================
// Behavioral Tests: Full-Document Replacement
// ============================================================================

/// Test that apply_incremental_change correctly handles full-document replacement
/// when range is None (full content replacement).
#[test]
fn test_apply_incremental_change_full_document_replacement() {
    let mut text = "original content\nwith multiple\nlines".to_string();

    let change = TextDocumentContentChangeEvent {
        range: None, // None means full-document replacement
        range_length: None,
        text: "completely new\ncontent".to_string(),
    };

    apply_incremental_change(&mut text, &change).expect("apply should succeed");
    assert_eq!(text, "completely new\ncontent");
}

/// Test that full-document replacement preserves content exactly
#[test]
fn test_apply_incremental_change_full_replacement_preserves_content() {
    let test_cases: Vec<(&str, &str)> = vec![
        ("", "hello world"),
        ("hello", ""),
        ("short", "a much longer string that is different"),
        ("a much longer string that is different", "short"),
        (
            "line1\nline2\nline3\nline4\nline5",
            "modified\nline2\nline3\nline4\nline5",
        ),
        ("123", "456"),
        ("日本語テスト", " changed"),
    ];

    for (initial, replacement) in test_cases {
        let mut text = initial.to_string();
        let change = TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: replacement.to_string(),
        };

        apply_incremental_change(&mut text, &change).expect("apply should succeed");
        assert_eq!(
            text, replacement,
            "Full replacement should preserve content exactly: '{}' -> '{}'",
            initial, replacement
        );
    }
}

// ============================================================================
// Source Code Inspection Tests: Verify clone_from() Usage
// ============================================================================

/// Returns the path to the diffguard-lsp source directory
fn lsp_source_path() -> PathBuf {
    // Use the manifest directory which is set by Cargo for tests
    // CARGO_MANIFEST_DIR for tests in crates/diffguard-lsp/tests/ is crates/diffguard-lsp
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Extracts the relevant line from source code at the given path and line number
fn get_source_line(path: &PathBuf, line_number: usize) -> String {
    let content = fs::read_to_string(path).expect("Failed to read source file");
    content
        .lines()
        .nth(line_number.saturating_sub(1)) // Lines are 1-indexed
        .unwrap_or("")
        .to_string()
}

/// Test that text.rs:63 uses clone_from() for full-document replacement
///
/// This line:
///   *text = change.text.clone();
/// Should be changed to:
///   text.clone_from(&change.text);
///
/// This test will FAIL if direct assignment is still used.
#[test]
fn test_text_rs_uses_clone_from_for_full_document_replacement() {
    let text_rs_path = lsp_source_path().join("text.rs");
    let line_63 = get_source_line(&text_rs_path, 63);

    // The correct implementation should use clone_from()
    assert!(
        line_63.contains("clone_from"),
        "text.rs:63 should use clone_from() for capacity reuse, but found: '{}'.\n\
         Expected something like: text.clone_from(&change.text);",
        line_63
    );

    // And should NOT use direct clone assignment
    assert!(
        !line_63.contains("change.text.clone()"),
        "text.rs:63 should NOT use change.text.clone() with direct assignment.\n\
         Found: '{}'",
        line_63
    );
}

/// Test that server.rs:92 uses clone_from() in mark_saved()
///
/// This line:
///   self.text = text;
/// Should be changed to:
///   self.text.clone_from(&text);
///
/// This test will FAIL if direct assignment is still used.
#[test]
fn test_server_rs_uses_clone_from_in_mark_saved() {
    let server_rs_path = lsp_source_path().join("server.rs");
    let line_92 = get_source_line(&server_rs_path, 92);

    // The correct implementation should use clone_from()
    assert!(
        line_92.contains("clone_from"),
        "server.rs:92 should use clone_from() for capacity reuse, but found: '{}'.\n\
         Expected something like: self.text.clone_from(&text);",
        line_92
    );

    // And should NOT use direct assignment
    assert!(
        !line_92.trim().starts_with("self.text = text"),
        "server.rs:92 should NOT use direct assignment 'self.text = text'.\n\
         Found: '{}'",
        line_92
    );
}

/// Verify that server.rs:77 (apply_changes) already uses clone_from() correctly
///
/// This is a consistency check - if this fails, it means the codebase has
/// an inconsistent pattern.
#[test]
fn test_server_rs_apply_changes_already_uses_clone_from() {
    let server_rs_path = lsp_source_path().join("server.rs");
    let line_77 = get_source_line(&server_rs_path, 77);

    assert!(
        line_77.contains("clone_from"),
        "server.rs:77 (apply_changes) should already use clone_from().\n\
         This is the reference implementation. Found: '{}'",
        line_77
    );
}
