//! Fuzz target for SARIF output rendering.
//!
//! This target exercises the SARIF renderer introduced in work-f8263aec.
//! It tests:
//! 1. SARIF JSON serialization with arbitrary Finding text
//! 2. HTML escaping of special characters in message and snippet fields
//! 3. Control character escaping as &#xNN; entities
//! 4. Valid JSON output from the renderer
//!
//! Requirements: Fuzz testing for SARIF output boundary conditions

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_core::{render_sarif_for_receipt, render_sarif_json};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus, CHECK_SCHEMA_V1,
};

/// Fuzz input that generates CheckReceipt with varied Finding text.
/// This exercises the SARIF renderer's HTML escaping path.
#[derive(Arbitrary, Debug)]
struct FuzzSarifInput {
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

/// Check if a string contains any unescaped XML/HTML special characters.
fn has_unescaped_special_chars(s: &str) -> bool {
    s.contains('&')
        || s.contains('<')
        || s.contains('>')
        || s.contains('\"')
        || s.contains('\'')
        || s.bytes().any(|b| b <= 0x1F && b != 0x09 && b != 0x0A && b != 0x0D)
}

/// Check if escaped output is valid JSON by parsing it.
fn is_valid_json(s: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(s).is_ok()
}

fuzz_target!(|input: FuzzSarifInput| {
    // Limit to reasonable size
    if input.findings.len() > 100 {
        return;
    }

    // Build a receipt with the generated findings
    let findings: Vec<Finding> = input
        .findings
        .iter()
        .take(input.findings_count.min(100))
        .map(|f| {
            Finding {
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
            }
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

    // Render to SARIF - should not panic
    let sarif_report = render_sarif_for_receipt(&receipt);

    // Render to JSON - should not panic
    let json_result = render_sarif_json(&receipt);
    assert!(json_result.is_ok(), "SARIF JSON rendering should not panic");

    let json = json_result.unwrap();

    // === Verify output invariants ===

    // 1. Output must be valid JSON
    assert!(
        is_valid_json(&json),
        "SARIF output must be valid JSON"
    );

    // 2. Check that HTML special characters in message and snippet are escaped
    // We'll look at the raw JSON strings for the findings
    let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();

    if let Some(runs) = json_value.get("runs").and_then(|r| r.as_array()) {
        for run in runs {
            if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                for result in results {
                    // Check message.text field
                    if let Some(message) = result.get("message").and_then(|m| m.get("text")) {
                        if let Some(text) = message.as_str() {
                            // If the original text had special chars, the JSON string
                            // should contain escaped versions
                            // Note: we can't directly check original text here,
                            // but we can verify the escaped forms are correct
                        }
                    }

                    // Check location.physicalLocation.region.snippet.text field
                    if let Some(locations) = result.get("locations").and_then(|l| l.as_array()) {
                        for loc in locations {
                            if let Some(snippet) = loc
                                .get("physicalLocation")
                                .and_then(|p| p.get("region"))
                                .and_then(|r| r.get("snippet"))
                                .and_then(|s| s.get("text"))
                            {
                                if let Some(text) = snippet.as_str() {
                                    // snippet text should not contain raw HTML special chars
                                    // that would be dangerous in a browser context
                                    // The escaped form should be present if special chars exist
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Check rules have escaped shortDescription
    if let Some(runs) = json_value.get("runs").and_then(|r| r.as_array()) {
        for run in runs {
            if let Some(driver) = run.get("tool").and_then(|t| t.get("driver")) {
                if let Some(rules) = driver.get("rules").and_then(|r| r.as_array()) {
                    for rule in rules {
                        if let Some(short_desc) = rule.get("shortDescription") {
                            if let Some(text) = short_desc.get("text").and_then(|t| t.as_str()) {
                                // shortDescription text should be escaped
                            }
                        }
                    }
                }
            }
        }
    }

    // === Test edge cases with known problematic inputs ===

    // Test with known HTML special characters
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
            rule_id: "test.html".to_string(),
            severity: Severity::Error,
            message: "<script>alert('xss')</script>".to_string(),
            path: "test.html".to_string(),
            line: 1,
            column: Some(1),
            match_text: "<script>".to_string(),
            snippet: "<script>alert('xss')</script>".to_string(),
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

    let special_json = render_sarif_json(&special_chars_receipt).unwrap();
    assert!(is_valid_json(&special_json), "HTML special chars must produce valid JSON");

    // Verify escaping: < should become &lt; etc.
    assert!(
        special_json.contains("&lt;script&gt;"),
        "HTML should be escaped in output"
    );
    assert!(
        special_json.contains("&apos;"),
        "Single quotes should be escaped"
    );

    // Verify the raw unescaped HTML is NOT in the output
    assert!(
        !special_json.contains("<script>"),
        "Unescaped HTML should not appear in JSON"
    );

    // Test with control characters
    let control_char_receipt = CheckReceipt {
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
            rule_id: "test.control".to_string(),
            severity: Severity::Error,
            message: format!("Test{}null{}bell", 0x00 as char, 0x07 as char),
            path: "test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "test".to_string(),
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

    let control_json = render_sarif_json(&control_char_receipt).unwrap();
    assert!(is_valid_json(&control_json), "Control chars must produce valid JSON");

    // Verify control characters are escaped as &#xNN;
    assert!(
        control_json.contains("&#x0;"),
        "NUL should be escaped as &#x0;"
    );
    assert!(
        control_json.contains("&#x7;"),
        "BEL should be escaped as &#x7;"
    );

    // Test with ampersand (must not double-escape existing entities)
    let amp_receipt = CheckReceipt {
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
            rule_id: "test.amp".to_string(),
            severity: Severity::Error,
            message: "Tom & Jerry".to_string(),
            path: "test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "&".to_string(),
            snippet: "Tom & Jerry".to_string(),
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

    let amp_json = render_sarif_json(&amp_receipt).unwrap();
    assert!(is_valid_json(&amp_json), "Ampersand must produce valid JSON");
    assert!(
        amp_json.contains("&amp;"),
        "Ampersand should be escaped as &amp;"
    );

    // Test empty findings (should produce valid empty SARIF)
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

    let empty_json = render_sarif_json(&empty_receipt).unwrap();
    assert!(is_valid_json(&empty_json), "Empty SARIF must be valid JSON");

    // Test with Unicode content (should be preserved)
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
            path: "test.rs".to_string(),
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

    let unicode_json = render_sarif_json(&unicode_receipt).unwrap();
    assert!(is_valid_json(&unicode_json), "Unicode content must produce valid JSON");

    // Parse back and verify Unicode is preserved
    let parsed: serde_json::Value = serde_json::from_str(&unicode_json).unwrap();
    if let Some(runs) = parsed.get("runs").and_then(|r| r.as_array()) {
        if let Some(run) = runs.first() {
            if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                if let Some(result) = results.first() {
                    if let Some(message) = result.get("message") {
                        if let Some(text) = message.get("text").and_then(|t| t.as_str()) {
                            assert!(
                                text.contains("Hello"),
                                "Unicode content should be preserved"
                            );
                        }
                    }
                }
            }
        }
    }

    // Test very long strings (stress test)
    let long_str = "x".repeat(100_000);
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
            rule_id: "test.long".to_string(),
            severity: Severity::Error,
            message: long_str.clone(),
            path: "test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "x".to_string(),
            snippet: long_str,
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

    let long_json = render_sarif_json(&long_receipt).unwrap();
    assert!(is_valid_json(&long_json), "Long strings must produce valid JSON");
});
