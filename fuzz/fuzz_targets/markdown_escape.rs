//! Fuzz target for Markdown escaping in diffguard output.
//!
//! This target exercises the escape_md function used in markdown rendering.
//! It tests:
//! 1. escape_md with random arbitrary strings (no panics)
//! 2. render_markdown_for_receipt with varied Finding text
//! 3. Output format validity (proper table structure)
//!
//! Issue #490: escape_md in main.rs was missing character escapes that existed
//! in render.rs:126. The fix (PR #524) made both functions identical.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_core::render_markdown_for_receipt;
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus, CHECK_SCHEMA_V1,
};

/// Characters that should NOT appear unescaped in markdown table cells
const DANGEROUS_CHARS: &[char] = &['|', '`', '#', '*', '_', '[', ']', '>', '\r', '\n'];

/// Fuzz input that generates CheckReceipt with varied Finding text.
/// This exercises the escape_md function in the markdown renderer.
#[derive(Arbitrary, Debug)]
struct FuzzMarkdownInput {
    /// Multiple findings with varied text content
    findings: Vec<FuzzFinding>,
    /// Number of findings to generate (separate from vector length for variety)
    findings_count: usize,
}

/// A fuzz finding with potentially problematic text values.
#[derive(Arbitrary, Debug)]
struct FuzzFinding {
    rule_id: String,
    severity: u8,
    message: String,
    path: String,
    line: u32,
    match_text: String,
    snippet: String,
}

/// Check if a markdown table has proper column alignment markers
fn has_valid_table_structure(s: &str) -> bool {
    // Find the header separator line (|---|---|...|)
    s.lines()
        .any(|line| line.trim().starts_with('|') && line.contains("---"))
}

fuzz_target!(|input: FuzzMarkdownInput| {
    // Limit to reasonable size to avoid OOM
    if input.findings.len() > 100 {
        return;
    }

    // Build a receipt with the generated findings
    let findings: Vec<Finding> = input
        .findings
        .iter()
        .take(input.findings_count.min(100))
        .map(|f| Finding {
            rule_id: f.rule_id.clone(),
            severity: match f.severity % 3 {
                0 => Severity::Info,
                1 => Severity::Warn,
                _ => Severity::Error,
            },
            message: f.message.clone(),
            path: f.path.clone(),
            line: f.line,
            column: Some(1),
            match_text: f.match_text.clone(),
            snippet: f.snippet.clone(),
        })
        .collect();

    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard-fuzz".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: findings.len() as u64,
            lines_scanned: findings.len() as u32 * 10,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["fuzz test".to_string()],
        },
        timing: None,
    };

    // Render markdown - should not panic
    let markdown = render_markdown_for_receipt(&receipt);

    // === Verify output invariants ===

    // 1. Output should not be empty when there are findings
    if !receipt.findings.is_empty() {
        assert!(
            !markdown.trim().is_empty(),
            "Markdown output should not be empty when there are findings"
        );
    }

    // 2. Output should contain the table header (only when there are findings)
    if !receipt.findings.is_empty() {
        assert!(
            markdown.contains("| Severity | Rule |"),
            "Markdown with findings should contain table header"
        );
    }

    // 3. Output should contain the separator line (only when there are findings)
    if !receipt.findings.is_empty() {
        assert!(
            has_valid_table_structure(&markdown),
            "Markdown with findings should have valid table structure with separator line"
        );
    }

    // === Test edge cases with known problematic inputs ===

    // Test 1: All markdown special characters
    let special_chars_receipt = CheckReceipt {
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
            rule_id: "rule|with|`all|#special|*chars|_in_[rule]_id|>test".to_string(),
            severity: Severity::Error,
            message: "Test | message `with` #all *the] special > chars\r\n".to_string(),
            path: "src/path|with`#*special[chars].rs".to_string(),
            line: 42,
            column: Some(1),
            match_text: "|all|".to_string(),
            snippet: "`code` with |pipes| and *asterisks* and #hash".to_string(),
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
    };

    let special_md = render_markdown_for_receipt(&special_chars_receipt);

    // The markdown should still have valid table structure
    assert!(
        has_valid_table_structure(&special_md),
        "Markdown with all special chars should still have valid table structure"
    );

    // The special characters should be escaped (preceded by backslash)
    // Note: backticks are handled specially since they delimit code spans
    assert!(
        special_md.contains("rule\\|with\\|"), // pipes escaped
        "Pipes in rule_id should be escaped"
    );
    assert!(
        special_md.contains("\\#all"), // hash escaped
        "Hash in rule_id should be escaped"
    );
    assert!(
        special_md.contains("\\*chars"), // asterisk escaped
        "Asterisk in rule_id should be escaped"
    );
    assert!(
        special_md.contains("\\_in\\_"), // underscore escaped
        "Underscore in rule_id should be escaped"
    );

    // Test 2: Empty strings (should not panic)
    let empty_receipt = CheckReceipt {
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
            files_scanned: 0,
            lines_scanned: 0,
        },
        findings: vec![],
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let empty_md = render_markdown_for_receipt(&empty_receipt);
    assert!(
        !empty_md.contains("panic"),
        "Empty findings should produce valid markdown without panic"
    );

    // Test 3: Very long strings with special characters
    let long_rule = "x".repeat(50_000);
    let long_rule_with_special = format!("rule\\|{}*test", long_rule);
    let long_receipt = CheckReceipt {
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
            rule_id: long_rule_with_special,
            severity: Severity::Error,
            message: "x".repeat(100_000),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "x".to_string(),
            snippet: "x".repeat(100_000),
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
    };

    let long_md = render_markdown_for_receipt(&long_receipt);
    assert!(
        has_valid_table_structure(&long_md),
        "Very long strings should still produce valid markdown"
    );

    // Test 4: Unicode content (should not be escaped, only markdown special chars)
    let unicode_receipt = CheckReceipt {
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
            rule_id: "test.unicode".to_string(),
            severity: Severity::Error,
            message: "Hello 世界 🌍 é日本語".to_string(),
            path: "src/路径.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "Hello".to_string(),
            snippet: "Hello 世界".to_string(),
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
    };

    let unicode_md = render_markdown_for_receipt(&unicode_receipt);
    // Unicode characters should appear WITHOUT backslash escaping
    assert!(
        unicode_md.contains("世界"),
        "Unicode should be preserved in output"
    );
    assert!(
        unicode_md.contains("🌍"),
        "Emoji should be preserved in output"
    );
    // But NOT escaped with backslash
    assert!(
        !unicode_md.contains("\\世"),
        "Unicode should NOT be escaped with backslash"
    );

    // Test 5: Newlines and carriage returns (must be escaped to preserve table)
    let newline_receipt = CheckReceipt {
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
            rule_id: "test.newline".to_string(),
            severity: Severity::Error,
            message: "line1\nline2".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "line1\nline2".to_string(),
            snippet: "line1\nline2".to_string(),
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
    };

    let newline_md = render_markdown_for_receipt(&newline_receipt);
    // The \n should be escaped as \\n (backslash-n) to not break the table
    assert!(
        newline_md.contains("line1\\nline2") || newline_md.contains("line1\\\\nline2"),
        "Newlines should be escaped in markdown output"
    );
    // Should NOT contain actual newlines in the message column
    // (This would break the table structure)
    assert!(
        has_valid_table_structure(&newline_md),
        "Newlines in content should not break table structure"
    );

    // Test 6: Carriage return + newline (Windows line endings)
    let crlf_receipt = CheckReceipt {
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
            rule_id: "test.crlf".to_string(),
            severity: Severity::Error,
            message: "line1\r\nline2".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "line1\r\nline2".to_string(),
            snippet: "line1\r\nline2".to_string(),
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
    };

    let crlf_md = render_markdown_for_receipt(&crlf_receipt);
    assert!(
        has_valid_table_structure(&crlf_md),
        "CRLF in content should not break table structure"
    );
});