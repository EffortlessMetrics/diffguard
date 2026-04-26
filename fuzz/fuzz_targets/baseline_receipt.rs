//! Fuzz target for baseline receipt parsing and comparison logic.
//!
//! This target exercises the baseline mode feature introduced in work-5a1ff6f4.
//! It tests:
//! 1. CheckReceipt JSON parsing (valid and malformed)
//! 2. Schema version validation
//! 3. Finding fingerprint computation
//! 4. Finding classification (baseline vs new)
//! 5. Exit code computation
//!
//! Requirements: Fuzz testing for baseline mode input boundaries

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_analytics::{baseline_from_receipt, fingerprint_for_finding};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus, CHECK_SCHEMA_V1,
};

/// Fuzz input that generates baseline receipt JSON.
/// This exercises more paths than purely random bytes.
#[derive(Arbitrary, Debug)]
struct FuzzBaselineReceipt {
    /// Raw bytes for unstructured fuzzing
    raw_bytes: Vec<u8>,
    /// Structured receipt for targeted fuzzing
    structured: StructuredReceipt,
    /// Whether to use structured input
    use_structured: bool,
}

/// A structured receipt that generates valid-ish JSON
/// but with potentially problematic values.
#[derive(Arbitrary, Debug)]
struct StructuredReceipt {
    /// Schema version to use
    schema_version: String,
    /// Findings to include
    findings: Vec<FuzzFinding>,
    /// Whether to omit required fields
    omit_tool: bool,
    /// Whether to omit diff meta
    omit_diff: bool,
    /// Whether to omit verdict
    omit_verdict: bool,
    /// Invalid JSON injection
    inject_json_error: bool,
    /// Extra fields that might trip up parsing
    extra_fields: Vec<(String, String)>,
}

/// A fuzz finding with potentially problematic values.
#[derive(Arbitrary, Debug)]
struct FuzzFinding {
    rule_id: String,
    severity: u8, // Maps to info/warn/error
    message: String,
    path: String,
    line: u32,
    match_text: String,
    snippet: String,
}

impl StructuredReceipt {
    /// Convert to JSON string for parsing.
    fn to_json_string(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");

        // Schema
        out.push_str(&format!(
            "  \"schema\": {},\n",
            serde_json::to_string(&self.schema_version).unwrap_or_default()
        ));

        // Tool meta (required)
        if !self.omit_tool {
            out.push_str("  \"tool\": {\n");
            out.push_str("    \"name\": \"diffguard\",\n");
            out.push_str("    \"version\": \"0.1.0\"\n");
            out.push_str("  },\n");
        }

        // Diff meta (required)
        if !self.omit_diff {
            out.push_str("  \"diff\": {\n");
            out.push_str("    \"base\": \"abc123\",\n");
            out.push_str("    \"head\": \"def456\",\n");
            out.push_str("    \"context_lines\": 3,\n");
            out.push_str("    \"scope\": \"added\",\n");
            out.push_str("    \"files_scanned\": 1,\n");
            out.push_str("    \"lines_scanned\": 10\n");
            out.push_str("  },\n");
        }

        // Findings
        out.push_str("  \"findings\": [\n");
        for (i, finding) in self.findings.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            out.push_str("    {\n");
            out.push_str(&format!(
                "      \"rule_id\": {},\n",
                serde_json::to_string(&finding.rule_id).unwrap_or_default()
            ));
            let sev = match finding.severity % 3 {
                0 => "info",
                1 => "warn",
                _ => "error",
            };
            out.push_str(&format!(
                "      \"severity\": {},\n",
                serde_json::to_string(sev).unwrap_or_default()
            ));
            out.push_str(&format!(
                "      \"message\": {},\n",
                serde_json::to_string(&finding.message).unwrap_or_default()
            ));
            out.push_str(&format!(
                "      \"path\": {},\n",
                serde_json::to_string(&finding.path).unwrap_or_default()
            ));
            out.push_str(&format!("      \"line\": {},\n", finding.line));
            out.push_str(&format!(
                "      \"match_text\": {},\n",
                serde_json::to_string(&finding.match_text).unwrap_or_default()
            ));
            out.push_str(&format!(
                "      \"snippet\": {}",
                serde_json::to_string(&finding.snippet).unwrap_or_default()
            ));
            out.push_str("\n    }");
        }
        out.push_str("\n  ],\n");

        // Verdict (required)
        if !self.omit_verdict {
            out.push_str("  \"verdict\": {\n");
            out.push_str("    \"status\": \"pass\",\n");
            out.push_str(
                "    \"counts\": {\"info\": 0, \"warn\": 0, \"error\": 0, \"suppressed\": 0},\n",
            );
            out.push_str("    \"reasons\": []\n");
            out.push_str("  }\n");
        }

        // Extra fields
        for (key, value) in &self.extra_fields {
            out.push_str(&format!(
                "  {}: {}\n",
                serde_json::to_string(key).unwrap_or_default(),
                serde_json::to_string(value).unwrap_or_default()
            ));
        }

        // JSON error injection
        if self.inject_json_error {
            out.push_str("  ,invalid json,,,\n");
        }

        out.push_str("}\n");
        out
    }
}

/// Compute exit code for baseline mode based on new findings.
/// Mirrors the logic in main.rs::compute_baseline_exit_code
fn compute_baseline_exit_code(fail_on: &str, new_counts: &VerdictCounts) -> i32 {
    if new_counts.error == 0 && new_counts.warn == 0 && new_counts.info == 0 {
        return 0;
    }

    if new_counts.error > 0 {
        return 2;
    }

    if new_counts.warn > 0 && fail_on == "warn" {
        return 3;
    }

    0
}

fuzz_target!(|input: FuzzBaselineReceipt| {
    // Limit input size to avoid timeouts
    if input.raw_bytes.len() > 50000 && !input.use_structured {
        return;
    }

    if input.use_structured {
        // === Structured fuzzing: Generate valid-ish JSON with problematic values ===
        let json_str = input.structured.to_json_string();

        // Try to parse as CheckReceipt - should not panic
        let result: Result<CheckReceipt, _> = serde_json::from_str(&json_str);

        if let Ok(receipt) = result {
            // Test that schema validation works
            let _schema_valid = receipt.schema == CHECK_SCHEMA_V1;

            // Test fingerprint computation on all findings
            for finding in &receipt.findings {
                let fp = fingerprint_for_finding(finding);
                // Fingerprint should be a valid hex string of expected length
                assert_eq!(fp.len(), 64, "SHA-256 fingerprint should be 64 hex chars");
                assert!(
                    fp.chars().all(|c| c.is_ascii_hexdigit()),
                    "Fingerprint should be valid hex"
                );
            }

            // Test baseline_from_receipt
            let baseline = baseline_from_receipt(&receipt);
            assert_eq!(
                baseline.schema, "diffguard.false_positive_baseline.v1",
                "Baseline schema should be set correctly"
            );

            // Verify baseline entries match findings fingerprints
            for finding in &receipt.findings {
                let fp = fingerprint_for_finding(finding);
                assert!(
                    baseline.entries.iter().any(|e| e.fingerprint == fp),
                    "Each finding should have corresponding baseline entry"
                );
            }

            // Test exit code computation
            let fail_on_variants = ["error", "warn", "never"];
            for fail_on in &fail_on_variants {
                // Empty new counts should always return 0
                let empty_counts = VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 0,
                    suppressed: 0,
                };
                let code = compute_baseline_exit_code(fail_on, &empty_counts);
                assert_eq!(code, 0, "Empty counts should always exit 0");

                // Error counts should exit 2 if fail_on is error or warn
                let error_counts = VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 1,
                    suppressed: 0,
                };
                let code = compute_baseline_exit_code(fail_on, &error_counts);
                if *fail_on == "error" || *fail_on == "warn" {
                    assert_eq!(code, 2, "Errors should exit 2 when fail_on includes error");
                } else {
                    assert_eq!(code, 0, "Errors should exit 0 when fail_on is never");
                }

                // Warning counts depend on fail_on
                let warn_counts = VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                };
                let code = compute_baseline_exit_code(fail_on, &warn_counts);
                if *fail_on == "warn" {
                    assert_eq!(code, 3, "Warnings should exit 3 when fail_on is warn");
                } else {
                    assert_eq!(code, 0, "Warnings should exit 0 when fail_on is not warn");
                }
            }
        }
    } else {
        // === Unstructured fuzzing: Raw bytes as JSON ===
        if let Ok(s) = std::str::from_utf8(&input.raw_bytes) {
            // Skip excessively long inputs
            if s.len() > 50000 {
                return;
            }

            // Try to parse as CheckReceipt - should not panic on malformed input
            let _: Result<CheckReceipt, _> = serde_json::from_str(s);

            // Try to parse as serde_json::Value (more lenient)
            let _: Result<serde_json::Value, _> = serde_json::from_str(s);

            // Try parsing just the schema field
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(s) {
                if let Some(schema) = value.get("schema").and_then(|v| v.as_str()) {
                    // Schema version should be a string if present
                    let _ = schema.to_string();
                }

                // If findings are present, try to access them
                if let Some(findings) = value.get("findings").and_then(|v| v.as_array()) {
                    for finding in findings.iter().take(100) {
                        if let Some(obj) = finding.as_object() {
                            // Each finding should have rule_id, severity, path, line, match_text
                            let _: Option<&str> = obj.get("rule_id").and_then(|v| v.as_str());
                            let _: Option<&str> = obj.get("severity").and_then(|v| v.as_str());
                            let _: Option<&str> = obj.get("path").and_then(|v| v.as_str());
                            let _: Option<u64> = obj.get("line").and_then(|v| v.as_u64());
                            let _: Option<&str> = obj.get("match_text").and_then(|v| v.as_str());
                        }
                    }
                }
            }
        }
    }

    // === Test edge cases with valid minimal receipts ===

    // Empty findings
    let empty_receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "abc".to_string(),
            head: "def".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
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

    let baseline = baseline_from_receipt(&empty_receipt);
    assert!(
        baseline.entries.is_empty(),
        "Empty receipt should produce empty baseline"
    );

    // Single finding
    let single_finding = Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Error,
        message: "Test message".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: None,
        match_text: "unwrap()".to_string(),
        snippet: "Some(1).unwrap()".to_string(),
    };

    let fp = fingerprint_for_finding(&single_finding);
    assert_eq!(fp.len(), 64);

    // Multiple findings with same fingerprint should deduplicate in baseline
    let receipt_with_dups = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "abc".to_string(),
            head: "def".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        findings: vec![single_finding.clone(), single_finding.clone()],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 2,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let baseline = baseline_from_receipt(&receipt_with_dups);
    assert_eq!(
        baseline.entries.len(),
        1,
        "Duplicate findings should be deduplicated"
    );

    // Test various severity levels
    for severity_val in 0..10u8 {
        let finding = Finding {
            rule_id: "test.rule".to_string(),
            severity: match severity_val % 3 {
                0 => Severity::Info,
                1 => Severity::Warn,
                _ => Severity::Error,
            },
            message: "Test".to_string(),
            path: "test.rs".to_string(),
            line: 1,
            column: None,
            match_text: "test".to_string(),
            snippet: "test".to_string(),
        };
        let fp = fingerprint_for_finding(&finding);
        assert_eq!(fp.len(), 64);
    }
});
