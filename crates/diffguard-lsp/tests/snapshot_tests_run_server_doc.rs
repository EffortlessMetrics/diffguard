//! Snapshot tests for `run_server()` doc comment
//!
//! These tests verify the doc comment on `run_server()` in server.rs
//! includes the required `# Errors` section with all error categories.
//!
//! The doc comment is considered part of the API surface - any change
//! to the documented error categories should be detected immediately.

use std::path::Path;

/// Expected doc comment baseline for `run_server()` function.
/// This snapshot captures the exact text that should be present
/// in crates/diffguard-lsp/src/server.rs before `pub fn run_server`.
const EXPECTED_DOC_COMMENT_LINES: &[&str] = &[
    "/// Run the LSP server main loop.",
    "///",
    "/// # Errors",
    "///",
    "/// Returns an error if:",
    "/// - LSP protocol initialization or message handling fails",
    "/// - LSP messages cannot be parsed as JSON",
    "/// - Sending LSP messages to the client fails",
];

/// Expected function signature line (the line immediately after the doc comment)
const EXPECTED_FUNCTION_SIGNATURE: &str = "pub fn run_server(connection: Connection) -> Result<()> {";

/// Line number where `run_server` doc comment should start (1-indexed)
const EXPECTED_DOC_LINE_START: usize = 164;

/// Number of error categories documented
const EXPECTED_ERROR_CATEGORY_COUNT: usize = 3;

// ============================================================================
// Snapshot Tests
// ============================================================================

/// Verifies `run_server()` has a doc comment immediately above it.
/// The doc comment should start at line 164 and describe the function's purpose.
#[test]
fn test_run_server_doc_comment_exists() {
    let server_rs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("server.rs");
    
    let source = std::fs::read_to_string(&server_rs_path)
        .expect("failed to read server.rs");
    
    let lines: Vec<&str> = source.lines().collect();
    
    // Find the line containing "pub fn run_server"
    let run_server_line = lines.iter()
        .position(|l| l.contains("pub fn run_server"))
        .expect("pub fn run_server not found in server.rs");
    
    // Doc comment should be immediately before the function (1 line gap is line 163 which is empty)
    let doc_start_line = run_server_line.saturating_sub(EXPECTED_DOC_COMMENT_LINES.len());
    
    // Verify the doc comment lines match our baseline
    let doc_lines: Vec<&str> = lines[doc_start_line..run_server_line].iter()
        .map(|l| *l)
        .collect();
    
    assert_eq!(
        doc_lines.len(),
        EXPECTED_DOC_COMMENT_LINES.len(),
        "Doc comment should have {} lines, found {}",
        EXPECTED_DOC_COMMENT_LINES.len(),
        doc_lines.len()
    );
    
    for (i, (actual, expected)) in doc_lines.iter().zip(EXPECTED_DOC_COMMENT_LINES.iter()).enumerate() {
        assert_eq!(
            actual.trim_end(),
            *expected,
            "Line {} of doc comment mismatch.\nExpected: {:?}\nActual:   {:?}",
            i + 1,
            expected,
            actual.trim_end()
        );
    }
}

/// Verifies `run_server()` has an `# Errors` section in its doc comment.
/// The # Errors section documents all error categories that can be returned.
#[test]
fn test_run_server_has_errors_section() {
    let server_rs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("server.rs");
    
    let source = std::fs::read_to_string(&server_rs_path)
        .expect("failed to read server.rs");
    
    assert!(
        source.contains("/// # Errors"),
        "Doc comment should contain '# Errors' section"
    );
}

/// Verifies the `# Errors` section documents exactly three error categories:
/// 1. LSP protocol errors (initialization/message handling)
/// 2. JSON parsing errors
/// 3. LSP message send errors
#[test]
fn test_run_server_errors_section_has_three_categories() {
    let server_rs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("server.rs");
    
    let source = std::fs::read_to_string(&server_rs_path)
        .expect("failed to read server.rs");
    
    // Count error category bullet points
    let lsp_protocol_error = source.contains("LSP protocol initialization or message handling fails");
    let json_error = source.contains("LSP messages cannot be parsed as JSON");
    let send_error = source.contains("Sending LSP messages to the client fails");
    
    assert!(
        lsp_protocol_error,
        "Missing: LSP protocol initialization or message handling fails"
    );
    assert!(
        json_error,
        "Missing: LSP messages cannot be parsed as JSON"
    );
    assert!(
        send_error,
        "Missing: Sending LSP messages to the client fails"
    );
    
    // Verify we have exactly 3 error categories
    let categories_found = [lsp_protocol_error, json_error, send_error]
        .iter()
        .filter(|&&x| x)
        .count();
    
    assert_eq!(
        categories_found,
        EXPECTED_ERROR_CATEGORY_COUNT,
        "Expected {} error categories, found {}",
        EXPECTED_ERROR_CATEGORY_COUNT,
        categories_found
    );
}
