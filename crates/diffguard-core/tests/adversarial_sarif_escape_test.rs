//! Adversarial tests for SARIF escaping approach.
//!
//! These tests challenge the `#[serde(serialize_with = "escape_sarif_str")]`
//! approach by finding edge cases and incomplete escaping coverage.

use diffguard_core::render_sarif_json;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

/// Create a receipt with findings containing special characters in various fields.
fn create_receipt_with_poisoned_fields() -> CheckReceipt {
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
        // Finding with special characters that could break JSON or cause XSS
        findings: vec![Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            // Message with HTML/XSS special chars
            message: "Test <script>alert('xss')</script> & \"quotes\"".to_string(),
            path: "src/test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            // Snippet with special chars
            snippet: "let x = \"test\";".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error-level finding".to_string()],
        },
        timing: None,
    }
}

/// Create a receipt where the PATH contains HTML special characters.
/// This is realistic: files can be in directories with <, >, & in their names.
fn create_receipt_with_special_chars_in_path() -> CheckReceipt {
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
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            message: "Found issue in path".to_string(),
            // Path with HTML special chars - this is NOT escaped by the current implementation!
            path: "src/<repo>/root&special/file.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "let x = 1;".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error-level finding".to_string()],
        },
        timing: None,
    }
}

/// Challenge 1: The serde serialize_with approach only works on field-level.
/// If a new field is added without the attribute, it won't be escaped.
#[test]
fn challenge_uri_field_not_escaped() {
    let receipt = create_receipt_with_special_chars_in_path();
    let json = render_sarif_json(&receipt).expect("should serialize");
    
    // The URI contains <, >, & but they are NOT escaped in the JSON output
    // because SarifArtifactLocation.uri does not have serialize_with
    assert!(
        json.contains("src/<repo>"),
        "URI with < is NOT escaped - this could break JSON if it contains double quotes"
    );
    assert!(
        json.contains("root&special"),
        "URI with & is NOT escaped"
    );
    
    // The JSON is still valid because <, > don't break JSON strings,
    // but if someone tries to parse this as XML later, it could be problematic.
    let _: serde_json::Value = serde_json::from_str(&json).expect("should still be valid JSON");
    
    println!("ISSUE: URI field is not HTML-escaped:");
    println!("{}", json);
}

/// Challenge 2: Already-escaped content gets double-escaped
/// This is mentioned in the plan-reviewer findings but worth demonstrating.
#[test]
fn challenge_double_escaping_of_already_escaped_content() {
    let receipt = CheckReceipt {
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
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            // User's rule matched literal XML entities
            message: "Found &lt;tag&gt; in code".to_string(),
            path: "src/test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "let x = &lt;tag&gt;;".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error-level finding".to_string()],
        },
        timing: None,
    };

    let json = render_sarif_json(&receipt).expect("should serialize");
    
    // The &lt; becomes &amp;lt; (double-escaped)
    assert!(
        json.contains("&amp;lt;"),
        "Already-escaped content gets double-escaped: &lt; -> &amp;lt;"
    );
    
    // This is technically "correct" for the serializer approach, but:
    // 1. It doubles the output size for escaped content
    // 2. If a SARIF viewer unescapes once, it still shows &lt; literally
    // 3. If the user is debugging why their XML entities appear in output,
    //    the double-escaping is surprising and not obvious why
    
    println!("ISSUE: Double-escaping of already-escaped content:");
    println!("Original: 'Found &lt;tag&gt;' becomes: 'Found &amp;lt;tag&amp;gt;'");
    println!("{}", json);
}

/// Challenge 3: Control characters in fields other than message/snippet
#[test]
fn challenge_control_chars_in_rule_id() {
    // This is a pathological case but demonstrates the point:
    // What if a rule ID somehow contains a control character?
    // (In practice this won't happen, but it's a theoretical concern)
    
    let receipt = CheckReceipt {
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
            // Rule ID with control character
            rule_id: format!("test\x00rule"),
            severity: Severity::Error,
            message: "Test".to_string(),
            path: "src/test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "let x = 1;".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error-level finding".to_string()],
        },
        timing: None,
    };

    // This might produce invalid JSON if the NUL character isn't properly handled
    let result = render_sarif_json(&receipt);
    
    // The JSON serialization should either:
    // 1. Properly escape the control char
    // 2. Or panic/fail gracefully
    
    match result {
        Ok(json) => {
            // If it succeeded, verify the JSON is valid
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
            assert!(
                parsed.is_ok(),
                "JSON with NUL in rule_id should either be properly escaped or fail"
            );
        }
        Err(e) => {
            // If it fails, that's actually safer behavior - prevents corrupt output
            println!("Good: NUL in rule_id caused error: {}", e);
        }
    }
}

/// Challenge 4: The serialize_with approach is opt-in per field.
/// A developer adding a new String field might forget to add serialize_with.
#[test]
fn challenge_field_coverage_gap_analysis() {
    // This test documents which fields are NOT escaped:
    // - rule_id (SarifRule.id)
    // - uri (SarifArtifactLocation.uri)
    // - uri_base_id (SarifArtifactLocation.uri_base_id)
    // - command_line (SarifInvocation.command_line)
    
    // These fields COULD contain user-controlled content that should be escaped
    // for HTML safety in SARIF viewers.
    
    let receipt = create_receipt_with_poisoned_fields();
    let json = render_sarif_json(&receipt).expect("should serialize");
    
    // message and snippet ARE escaped (verify this is working)
    assert!(
        json.contains("&lt;script&gt;"),
        "message with <script> should be HTML-escaped"
    );
    
    // But rule_id is NOT escaped (it's the raw string "test.rule")
    assert!(
        json.contains("\"test.rule\""),
        "rule_id is not escaped (which is fine for test.rule but illustrates the point)"
    );
    
    // If we had a rule_id like "test<script>", it would NOT be escaped
    println!("Fields NOT escaped by serialize_with approach:");
    println!("- rule_id");
    println!("- uri");
    println!("- uri_base_id");
    println!("- command_line");
    println!("\nThis is a trade-off: serialize_with is field-level and opt-in.");
}

/// Challenge 5: Demonstrate the semantic issue - escape_sarif_str uses escape_xml
/// which is designed for XML, but SARIF is JSON with HTML rendering context.
/// The escaping might be semantically wrong for some cases.
#[test]
fn challenge_xml_escaping_in_json_html_context() {
    // escape_xml escapes ' as &apos; (XML single quote entity)
    // But in JSON, strings are already quoted with ""
    // And when rendered in HTML, &apos; might not work in all browsers
    
    let receipt = CheckReceipt {
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
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            // Single quote in message
            message: "User's code style issue".to_string(),
            path: "src/test.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "User's choice".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error-level finding".to_string()],
        },
        timing: None,
    };

    let json = render_sarif_json(&receipt).expect("should serialize");
    
    // &apos; is used, which is XML-specific
    assert!(
        json.contains("&apos;"),
        "Single quote escaped as &apos; (XML entity, not HTML)"
    );
    
    // In HTML5, the proper escape for single quote in attribute context is &#39;
    // But we're using &apos; which is not part of HTML5 spec (it's XML)
    
    println!("Note: Using XML entity &apos; for single quotes");
    println!("HTML5 prefers &#39; or &#x27; for single quotes in HTML context");
    println!("{}", json);
}