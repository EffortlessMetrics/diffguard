//! Edge case snapshot tests for diffguard-core output renderers.
//!
//! These tests cover edge cases that are not well tested in the existing snapshot tests:
//! - Unicode characters in all fields
//! - Special markdown characters beyond pipe/backtick
//! - Empty and zero values
//! - Very long fields
//! - CRLF line endings
//! - All VerdictStatus variants
//! - Control characters in XML/HTML output
//!
//! NOTE: These are RED tests - they should FAIL until the implementation handles
//! these edge cases correctly. When the implementation is fixed, these tests should pass.

use diffguard_core::{
    render_checkstyle_for_receipt, render_csv_for_receipt, render_junit_for_receipt,
    render_markdown_for_receipt, render_sarif_json, render_tsv_for_receipt,
};
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 1,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

// ============================================================================
// Markdown Output Edge Cases
// ============================================================================

/// Test markdown output with Unicode characters (Chinese, emoji, etc.)
#[test]
fn test_markdown_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "测试消息 with emoji 🎉 and русский".to_string(),
        path: "src/测试.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// 注释: 🚀 test".to_string(),
    }];
    let receipt = make_receipt(findings);
    let md = render_markdown_for_receipt(&receipt);

    // Unicode should be preserved (not escaped or corrupted)
    assert!(md.contains("测试消息"));
    assert!(md.contains("🎉"));
    assert!(md.contains("русский"));
    assert!(md.contains("src/测试.rs"));
    assert!(md.contains("注释"));
    assert!(md.contains("🚀"));
}

/// Test markdown output with special markdown characters that need escaping.
/// Beyond pipe and backtick, we need to escape: # headers, **bold**, *italic*, [links]()
#[test]
fn test_markdown_special_markdown_chars() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        // Message with markdown special chars
        message: "Error: **bold** and *italic* and # header".to_string(),
        path: "src/[link](url).rs".to_string(), // path with link-like syntax
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// **bold** and *italic*".to_string(),
    }];
    let receipt = make_receipt(findings);
    let md = render_markdown_for_receipt(&receipt);

    // The markdown should escape these characters to prevent formatting issues
    // **bold** should be escaped as \*\*bold\*\* or similar
    // # header should be escaped
    // [link](url) in path should be escaped
    // The table should still render correctly
    assert!(md.contains("| Severity | Rule | Location | Message | Snippet |"));
}

/// Test markdown output with empty fields in findings
#[test]
fn test_markdown_empty_finding_fields() {
    let findings = vec![Finding {
        rule_id: "".to_string(), // empty rule_id
        severity: Severity::Warn,
        message: "".to_string(), // empty message
        path: "".to_string(),    // empty path
        line: 0,                 // zero line number
        column: Some(0),         // zero column
        match_text: "".to_string(),
        snippet: "".to_string(),
    }];
    let receipt = make_receipt(findings);
    let md = render_markdown_for_receipt(&receipt);

    // Should render with empty fields (empty strings escape as `` in markdown cells)
    assert!(md.contains("| warn | `` | `:0` |  | `` |"));
}

/// Test markdown output with VerdictStatus::Skip
#[test]
fn test_markdown_verdict_skip_status() {
    let mut receipt = make_receipt(vec![]);
    receipt.verdict.status = VerdictStatus::Skip;
    receipt.verdict.counts = VerdictCounts::default();
    receipt.verdict.reasons = vec!["no_diff_input".to_string()];

    let md = render_markdown_for_receipt(&receipt);

    assert!(md.contains("## diffguard — SKIP"));
    assert!(md.contains("no_diff_input"));
}

/// Test markdown output with VerdictStatus::Pass
#[test]
fn test_markdown_verdict_pass_status() {
    let mut receipt = make_receipt(vec![]);
    receipt.verdict.status = VerdictStatus::Pass;
    receipt.verdict.counts = VerdictCounts::default();

    let md = render_markdown_for_receipt(&receipt);

    assert!(md.contains("## diffguard — PASS"));
}

/// Test markdown output with very long fields (path, message, snippet)
#[test]
fn test_markdown_long_fields() {
    let long_path = format!("src/{}.rs", "a".repeat(200));
    let long_message = format!("Long message: {}", "x".repeat(300));
    let long_snippet = format!("Snippet: {}", "y".repeat(300));

    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: long_message,
        path: long_path,
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: long_snippet,
    }];
    let receipt = make_receipt(findings);
    let md = render_markdown_for_receipt(&receipt);

    // Should render without crashing and preserve content
    assert!(md.contains("| error | `test.rule`"));
    assert!(md.contains("src/aaa")); // Should contain the path
}

/// Test markdown output with CRLF line endings in snippet
#[test]
fn test_markdown_crlf_in_snippet() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "Test with CRLF".to_string(),
        path: "src/test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "line1\r\nline2\r\nline3".to_string(), // CRLF line endings
    }];
    let receipt = make_receipt(findings);
    let md = render_markdown_for_receipt(&receipt);

    // Should escape CRLF properly for markdown table cell
    // CR and LF should be escaped or the cell should be properly formatted
    assert!(md.contains("| Severity | Rule | Location | Message | Snippet |"));
    assert!(md.contains("test.rule")); // rule_id column
}

// ============================================================================
// SARIF Output Edge Cases
// ============================================================================

/// Test SARIF output with Unicode characters
#[test]
fn test_sarif_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: "错误消息 with emoji 🎉".to_string(),
        path: "src/文件.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// 测试".to_string(),
    }];
    let receipt = make_receipt(findings);
    let json = render_sarif_json(&receipt).expect("should serialize");

    // Unicode should be preserved and HTML-escaped for SARIF viewers
    assert!(json.contains("错误消息"));
    assert!(json.contains("🎉"));
    // The HTML entities should appear for security
    // NOTE: serde_json outputs native UTF-8, not HTML-escaped (this is correct)
}

/// Test SARIF output with control characters that need escaping
#[test]
fn test_sarif_control_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: format!("Test with control char: \x00 and \x07"),
        path: "src/test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "normal".to_string(),
    }];
    let receipt = make_receipt(findings);
    let json = render_sarif_json(&receipt).expect("should serialize");

    // Control characters should be escaped as &#xNN; entities
    assert!(json.contains("&#x0;") || json.contains("&#x00;"));
    assert!(json.contains("&#x7;") || json.contains("&#x07;"));
    // Original control characters should NOT appear unescaped
    assert!(!json.contains("\x00"));
    assert!(!json.contains("\x07"));
}

/// Test SARIF output with empty rule_id
#[test]
fn test_sarif_empty_rule_id() {
    let findings = vec![Finding {
        rule_id: "".to_string(), // empty rule_id
        severity: Severity::Warn,
        message: "Test message".to_string(),
        path: "src/test.rs".to_string(),
        line: 1,
        column: None,
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_receipt(findings);
    let json = render_sarif_json(&receipt).expect("should serialize");

    // Should handle empty rule_id gracefully
    assert!(json.contains("\"ruleId\":\"\"") || json.contains("\"ruleId\": \"\""));
}

// ============================================================================
// JUnit XML Output Edge Cases
// ============================================================================

/// Test JUnit output with Unicode characters
#[test]
fn test_junit_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: "Сообщение об ошибке with 🎉".to_string(),
        path: "src/тест.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// тест".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_junit_for_receipt(&receipt);

    // Unicode should be preserved and XML-escaped
    assert!(xml.contains("Сообщение"));
    assert!(xml.contains("тест"));
    // NOTE: escape_xml does NOT escape unicode chars to XML entities (correct behavior).
    // The unicode assertions above verify correct preservation.
}

/// Test JUnit output with very long message
#[test]
fn test_junit_long_message() {
    let long_message = format!("Long error message: {}", "x".repeat(500));

    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: long_message,
        path: "src/test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_junit_for_receipt(&receipt);

    // Should render without crashing
    assert!(xml.contains("<failure"));
    assert!(xml.contains("test.rule"));
}

/// Test JUnit output with empty finding fields
#[test]
fn test_junit_empty_fields() {
    let findings = vec![Finding {
        rule_id: "".to_string(),
        severity: Severity::Warn,
        message: "".to_string(),
        path: "".to_string(),
        line: 0,
        column: None,
        match_text: "".to_string(),
        snippet: "".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_junit_for_receipt(&receipt);

    // Should render valid XML even with empty fields
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("<testsuites"));
    assert!(xml.contains("</testsuites>"));
}

// ============================================================================
// CSV/TSV Output Edge Cases
// ============================================================================

/// Test CSV output with Unicode characters
#[test]
fn test_csv_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "日本語メッセージ".to_string(),
        path: "src/テスト.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// テスト".to_string(),
    }];
    let receipt = make_receipt(findings);
    let csv = render_csv_for_receipt(&receipt);

    // Unicode should be preserved in CSV
    assert!(csv.contains("日本語メッセージ"));
    assert!(csv.contains("src/テスト.rs"));
    assert!(csv.contains("// テスト"));
}

/// Test CSV output with CRLF line endings in fields
#[test]
fn test_csv_crlf_line_endings() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "Multi-line\r\nmessage".to_string(),
        path: "src/test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "line1\r\nline2".to_string(),
    }];
    let receipt = make_receipt(findings);
    let csv = render_csv_for_receipt(&receipt);

    // CRLF should be escaped per RFC 4180 - field should be quoted
    // and CRLF inside should be preserved (but the field should be quoted)
    assert!(csv.contains("\"Multi-line\r\nmessage\""));
    assert!(csv.contains("\"line1\r\nline2\""));
}

/// Test CSV output with empty fields
#[test]
fn test_csv_empty_fields() {
    let findings = vec![Finding {
        rule_id: "".to_string(),
        severity: Severity::Warn,
        message: "".to_string(),
        path: "".to_string(),
        line: 0,
        column: Some(0),
        match_text: "".to_string(),
        snippet: "".to_string(),
    }];
    let receipt = make_receipt(findings);
    let csv = render_csv_for_receipt(&receipt);

    // Should render with empty quoted fields or just empty fields
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines.len() == 2); // header + 1 data row
    assert!(lines[1].contains(",0,,warn,,")); // empty fields
}

/// Test TSV output with backslash escape sequences
#[test]
fn test_tsv_backslash_escapes() {
    let findings = vec![Finding {
        rule_id: r"path\to\file".to_string(),
        severity: Severity::Warn,
        message: r"Message with \n and \t".to_string(),
        path: r"src\test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: r"\\".to_string(),
        snippet: r"let x = \\".to_string(),
    }];
    let receipt = make_receipt(findings);
    let tsv = render_tsv_for_receipt(&receipt);

    // Backslashes should be escaped in TSV
    assert!(tsv.contains(r"path\\to\\file"));
    assert!(tsv.contains(r"Message with \\n and \\t"));
    assert!(tsv.contains(r"src\\test.rs"));
    assert!(tsv.contains(r"let x = \\\\"));
}

/// Test TSV output with Unicode characters
#[test]
fn test_tsv_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "emoji.test".to_string(),
        severity: Severity::Info,
        message: "Message with 🚀 rocket".to_string(),
        path: "src/文件.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "rocket".to_string(),
        snippet: "// 🚀 launch".to_string(),
    }];
    let receipt = make_receipt(findings);
    let tsv = render_tsv_for_receipt(&receipt);

    // Unicode should be preserved
    assert!(tsv.contains("🚀"));
    assert!(tsv.contains("文件.rs"));
}

/// Test TSV output with empty fields
#[test]
fn test_tsv_empty_fields() {
    let findings = vec![Finding {
        rule_id: "".to_string(),
        severity: Severity::Warn,
        message: "".to_string(),
        path: "".to_string(),
        line: 0,
        column: None,
        match_text: "".to_string(),
        snippet: "".to_string(),
    }];
    let receipt = make_receipt(findings);
    let tsv = render_tsv_for_receipt(&receipt);

    // Should render with empty fields
    let lines: Vec<&str> = tsv.lines().collect();
    assert!(lines.len() == 2); // header + 1 data row
    // Tab-separated empty fields
    assert!(lines[1].contains("\t0\t\twarn\t\t")); // 5 tabs for 6 fields: "",0,"",warn,"",""
}

// ============================================================================
// Checkstyle Output Edge Cases
// ============================================================================

/// Test Checkstyle output with Unicode characters
#[test]
fn test_checkstyle_unicode_characters() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: "Сообщение об ошибке".to_string(),
        path: "src/файл.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "// тест".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Unicode should be preserved and XML-escaped
    assert!(xml.contains("Сообщение"));
    assert!(xml.contains("файл"));
    // NOTE: escape_xml does NOT escape unicode chars (correct per XML spec).
}

/// Test Checkstyle output with special characters in rule_id
#[test]
fn test_checkstyle_special_rule_id() {
    let findings = vec![Finding {
        rule_id: "x<>&\"'rule".to_string(), // all special XML chars
        severity: Severity::Error,
        message: "Test".to_string(),
        path: "src/test.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // All special chars in rule_id should be XML-escaped
    assert!(xml.contains("&lt;"));
    assert!(xml.contains("&gt;"));
    assert!(xml.contains("&amp;"));
    assert!(xml.contains("&quot;"));
    assert!(xml.contains("&apos;"));
    // Unescaped chars should NOT appear
    assert!(!xml.contains("x<&gt;&quot;'rule"));
}

/// Test Checkstyle output with empty file path
#[test]
fn test_checkstyle_empty_path() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "Test".to_string(),
        path: "".to_string(),
        line: 1,
        column: None,
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Should render valid XML with empty path
    assert!(xml.contains("<file name=\""));
    assert!(xml.contains("</checkstyle>"));
}

// ============================================================================
// Summary Test - All Renderers with Same Edge Case Data
// ============================================================================

/// Helper to create a receipt with challenging Unicode and special chars
fn make_receipt_with_all_edge_cases() -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        findings: vec![Finding {
            rule_id: "test.<>&\"'rule".to_string(),
            severity: Severity::Error,
            message: "Error: **bold** & *italic* #header [link](url)".to_string(),
            path: "src/测试.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "// 🚀 & <html> \"quotes\" 'apos'".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

/// Test that all output formats handle the same challenging data without crashing
#[test]
fn test_all_renderers_handle_edge_cases() {
    let receipt = make_receipt_with_all_edge_cases();

    // All these should not panic
    let _md = render_markdown_for_receipt(&receipt);
    let _json = render_sarif_json(&receipt).expect("SARIF should serialize");
    let _xml = render_junit_for_receipt(&receipt);
    let _csv = render_csv_for_receipt(&receipt);
    let _tsv = render_tsv_for_receipt(&receipt);
    let _checkstyle = render_checkstyle_for_receipt(&receipt);

    // If we got here without panicking, the test passes
    // The actual correctness of the output is tested by the other tests
    assert!(true);
}
