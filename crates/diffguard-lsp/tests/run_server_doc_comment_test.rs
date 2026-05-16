//! Tests verifying that `run_server()` has proper documentation per Rust API Guidelines C409.
//!
//! These tests verify that the `run_server()` function in `server.rs` has:
//! 1. A doc comment describing what the function does
//! 2. An `# Errors` section enumerating all error categories

use std::fs;
use std::path::Path;

/// Test that `run_server()` has a doc comment immediately preceding its declaration.
#[test]
fn test_run_server_has_doc_comment() {
    let server_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
    let content = fs::read_to_string(&server_rs).expect("failed to read server.rs");

    // Find the line with "pub fn run_server"
    let lines: Vec<&str> = content.lines().collect();
    let run_server_line = lines
        .iter()
        .position(|line| line.contains("pub fn run_server"))
        .expect("pub fn run_server not found in server.rs");

    // Check that there's a doc comment on the line(s) immediately before
    // Count backwards from run_server_line to find the doc comment
    let mut doc_line_idx = run_server_line;
    while doc_line_idx > 0 {
        let prev_line = lines[doc_line_idx - 1].trim();
        if prev_line.is_empty() {
            // Empty line before doc comment - that's the separator
            break;
        }
        if prev_line.starts_with("///") || prev_line.starts_with("//!") {
            doc_line_idx -= 1;
        } else {
            // No doc comment found before this non-doc, non-empty line
            panic!(
                "No doc comment found before `pub fn run_server` at line {}. \
                 Found line: {:?}",
                run_server_line + 1,
                lines[doc_line_idx.saturating_sub(1)]
            );
        }
    }

    // Verify the doc comment exists (at least one line starting with ///)
    let has_doc_comment = (0..=run_server_line).any(|i| lines[i].trim().starts_with("///"));
    assert!(
        has_doc_comment,
        "run_server() at line {} must have a doc comment (/// ...)",
        run_server_line + 1
    );
}

/// Test that `run_server()` has an `# Errors` section in its doc comment.
#[test]
fn test_run_server_has_errors_section() {
    let server_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
    let content = fs::read_to_string(&server_rs).expect("failed to read server.rs");

    // Extract the doc comment for run_server
    let lines: Vec<&str> = content.lines().collect();
    let run_server_line = lines
        .iter()
        .position(|line| line.contains("pub fn run_server"))
        .expect("pub fn run_server not found in server.rs");

    // Collect all doc comment lines before run_server
    let mut doc_lines = Vec::new();
    for i in (0..run_server_line).rev() {
        let line = lines[i].trim();
        if line.starts_with("///") {
            doc_lines.push(line);
        } else if line.is_empty() {
            // Skip empty lines in the doc comment
            continue;
        } else {
            break;
        }
    }

    // Reverse to get natural order
    doc_lines.reverse();

    // Join all doc lines to search for # Errors
    let full_doc = doc_lines.join("\n");

    assert!(
        full_doc.contains("# Errors"),
        "run_server() doc comment must contain '# Errors' section.\n\
         Found doc comment:\n{}",
        full_doc
    );
}

/// Test that the `# Errors` section in `run_server()` documents all three error categories:
/// 1. LSP protocol errors
/// 2. JSON parse/serialization errors
/// 3. LSP message send errors
#[test]
fn test_run_server_errors_section_has_three_categories() {
    let server_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
    let content = fs::read_to_string(&server_rs).expect("failed to read server.rs");

    // Extract the doc comment for run_server
    let lines: Vec<&str> = content.lines().collect();
    let run_server_line = lines
        .iter()
        .position(|line| line.contains("pub fn run_server"))
        .expect("pub fn run_server not found in server.rs");

    // Collect all doc comment lines before run_server
    let mut doc_lines = Vec::new();
    for i in (0..run_server_line).rev() {
        let line = lines[i].trim();
        if line.starts_with("///") {
            doc_lines.push(line);
        } else if line.is_empty() {
            continue;
        } else {
            break;
        }
    }
    doc_lines.reverse();
    let full_doc = doc_lines.join("\n");

    // Check for the three error categories
    let has_lsp_protocol_errors = full_doc.to_lowercase().contains("lsp protocol")
        || full_doc.to_lowercase().contains("initialize")
        || full_doc.to_lowercase().contains("shutdown");
    let has_json_errors = full_doc.to_lowercase().contains("json")
        || full_doc.to_lowercase().contains("parse")
        || full_doc.to_lowercase().contains("serialization")
        || full_doc.to_lowercase().contains("serde");
    let has_message_send_errors =
        full_doc.to_lowercase().contains("send") || full_doc.to_lowercase().contains("message");

    assert!(
        has_lsp_protocol_errors,
        "run_server() # Errors section must document LSP protocol errors (initialization, handling).\n\
         Found doc comment:\n{}",
        full_doc
    );

    assert!(
        has_json_errors,
        "run_server() # Errors section must document JSON parse/serialization errors.\n\
         Found doc comment:\n{}",
        full_doc
    );

    assert!(
        has_message_send_errors,
        "run_server() # Errors section must document LSP message send errors.\n\
         Found doc comment:\n{}",
        full_doc
    );
}
