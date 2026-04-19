//! Tests for markdown escaping in diffguard output
//!
//! Issue #490: escape_md in main.rs was missing character escapes that existed
//! in render.rs:126. Specifically, main.rs only escaped `|` and `` ` `` while
//! render.rs escaped the complete set including `#`, `*`, `_`, `[`, `]`, `>`, `\r`, `\n`.
//!
//! Both escape_md functions are now identical after the fix in PR #524.

use diffguard_core::render_markdown_for_receipt;
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus,
};

/// Creates a test receipt with a single finding containing special characters
fn make_receipt_with_finding(
    rule_id: &str,
    message: &str,
    path: &str,
    snippet: &str,
) -> CheckReceipt {
    CheckReceipt {
        schema: "check.schema.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 1,
        },
        findings: vec![Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Warn,
            message: message.to_string(),
            path: path.to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: snippet.to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 0,
                ..Default::default()
            },
            reasons: vec![],
        },
        timing: None,
    }
}

/// Tests that asterisk (*) is properly escaped in markdown output
/// Issue #490: asterisks were not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_asterisk_in_rule_id() {
    let receipt = make_receipt_with_finding(
        "rust*no*unwrap",
        "test message",
        "src/lib.rs",
        "test snippet",
    );
    let md = render_markdown_for_receipt(&receipt);
    // Asterisks should be escaped to prevent markdown emphasis
    assert!(
        md.contains("rust\\*no\\*unwrap"),
        "asterisks in rule_id should be escaped with backslash. Output:\n{}",
        md
    );
}

/// Tests that underscore (_) is properly escaped in markdown output
/// Issue #490: underscores were not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_underscore_in_rule_id() {
    let receipt = make_receipt_with_finding(
        "rust_no_unwrap",
        "test message",
        "src/lib.rs",
        "test snippet",
    );
    let md = render_markdown_for_receipt(&receipt);
    // Underscores should be escaped to prevent markdown emphasis
    assert!(
        md.contains("rust\\_no\\_unwrap"),
        "underscores in rule_id should be escaped with backslash. Output:\n{}",
        md
    );
}

/// Tests that hash (#) is properly escaped in markdown output
/// Issue #490: hash was not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_hash_in_rule_id() {
    let receipt =
        make_receipt_with_finding("rule#123", "test message", "src/lib.rs", "test snippet");
    let md = render_markdown_for_receipt(&receipt);
    // Hash should be escaped to prevent markdown headers
    assert!(
        md.contains("rule\\#123"),
        "hash in rule_id should be escaped with backslash. Output:\n{}",
        md
    );
}

/// Tests that open bracket ([) is properly escaped in markdown output
/// Issue #490: brackets were not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_open_bracket_in_message() {
    let receipt = make_receipt_with_finding(
        "test",
        "message with [brackets]",
        "src/lib.rs",
        "test snippet",
    );
    let md = render_markdown_for_receipt(&receipt);
    // Open bracket should be escaped
    assert!(
        md.contains("message with \\[brackets\\]"),
        "brackets in message should be escaped with backslash. Output:\n{}",
        md
    );
}

/// Tests that greater-than (>) is properly escaped in markdown output
/// Issue #490: greater-than was not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_greater_than_in_snippet() {
    let receipt = make_receipt_with_finding("test", "test message", "src/lib.rs", "value > other");
    let md = render_markdown_for_receipt(&receipt);
    // Greater-than should be escaped to prevent markdown blockquotes
    assert!(
        md.contains("value \\> other"),
        "greater-than in snippet should be escaped with backslash. Output:\n{}",
        md
    );
}

/// Tests that newline (\n) is properly escaped in markdown output
/// Issue #490: newlines were not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_newline_in_message() {
    let receipt = make_receipt_with_finding("test", "line1\nline2", "src/lib.rs", "test snippet");
    let md = render_markdown_for_receipt(&receipt);
    // Newline should be escaped to prevent breaking table structure
    assert!(
        md.contains("line1\\nline2"),
        "newline in message should be escaped as \\n. Output:\n{}",
        md
    );
}

/// Tests that carriage return (\r) is properly escaped in markdown output
/// Issue #490: carriage returns were not escaped in main.rs escape_md
#[test]
fn test_markdown_escapes_carriage_return_in_message() {
    let receipt = make_receipt_with_finding("test", "line1\rline2", "src/lib.rs", "test snippet");
    let md = render_markdown_for_receipt(&receipt);
    // Carriage return should be escaped to prevent breaking table structure
    assert!(
        md.contains("line1\\rline2"),
        "carriage return in message should be escaped as \\r. Output:\n{}",
        md
    );
}

/// Tests that pipe and backtick are properly escaped (these were already working)
#[test]
fn test_markdown_escapes_pipe_and_backtick() {
    let receipt = make_receipt_with_finding(
        "rule|id`tick",
        "message with | and `ticks`",
        "src/lib|name`.rs",
        "snippet with `code` | pipe",
    );
    let md = render_markdown_for_receipt(&receipt);

    // Pipe should be escaped
    assert!(
        md.contains("rule\\|id\\`tick"),
        "pipe and backtick in rule_id should be escaped. Output:\n{}",
        md
    );
    assert!(
        md.contains("src/lib\\|name\\`.rs:1"),
        "pipe and backtick in path should be escaped. Output:\n{}",
        md
    );
}

/// Tests that all markdown special characters together don't break the table
/// This is a comprehensive test for the issue #490 fix
#[test]
fn test_markdown_all_special_characters_preserved_in_output() {
    let receipt = make_receipt_with_finding(
        "rule#1*important_test",
        "msg with | ` # * _ [ ] > and \r\n linebreaks",
        "src/path[1]_name.rs",
        "code > value",
    );
    let md = render_markdown_for_receipt(&receipt);

    // All special characters should be escaped
    assert!(
        md.contains("rule\\#1\\*important\\_test"),
        "special chars in rule_id should be escaped. Output:\n{}",
        md
    );
    // Note: path is rendered as `src/path[1]_name.rs:1` with escaped special chars
    assert!(
        md.contains("src/path\\[1\\]\\_name.rs:1"),
        "special chars in path should be escaped. Output:\n{}",
        md
    );
    assert!(
        md.contains("msg with \\| \\` \\# \\* \\_ \\[ \\] \\> and \\r\\n linebreaks"),
        "all special chars in message should be escaped. Output:\n{}",
        md
    );
    assert!(
        md.contains("code \\> value"),
        "greater-than in snippet should be escaped. Output:\n{}",
        md
    );
}
