//! Property-based tests for `render_sensor_report()` invariants.
//!
//! Feature: comprehensive-test-coverage
//! Feature: sensor-report-correctness
//!
//! These tests verify that critical invariants hold across a wide range of
//! randomly generated inputs using proptest.

use std::collections::HashMap;

use diffguard_core::{RuleMetadata, SensorReportContext, render_sensor_json, render_sensor_report};
use diffguard_types::{
    Artifact, CapabilityStatus, CheckReceipt, DiffMeta, Finding, SENSOR_REPORT_SCHEMA_V1, Scope,
    Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
};
use proptest::prelude::*;

// ============================================================================
// Proptest Strategies
// ============================================================================

/// Strategy for generating Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating VerdictStatus values.
fn arb_verdict_status() -> impl Strategy<Value = VerdictStatus> {
    prop_oneof![
        Just(VerdictStatus::Pass),
        Just(VerdictStatus::Warn),
        Just(VerdictStatus::Fail),
        Just(VerdictStatus::Skip),
    ]
}

/// Strategy for generating Scope values.
fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Added),
        Just(Scope::Changed),
        Just(Scope::Modified),
        Just(Scope::Deleted),
    ]
}

/// Strategy for generating non-empty strings.
fn arb_string() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_]{1,50}").expect("valid regex")
}

/// Builds a minimal CheckReceipt with the given findings.
fn build_receipt(
    findings: Vec<Finding>,
    verdict_status: VerdictStatus,
    suppressed: u32,
    files_scanned: u64,
    lines_scanned: u32,
) -> CheckReceipt {
    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned,
            lines_scanned,
        },
        findings,
        verdict: Verdict {
            status: verdict_status,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

/// Builds a SensorReportContext with the given parameters.
fn build_context(
    capabilities: HashMap<String, CapabilityStatus>,
    artifacts: Vec<Artifact>,
    rule_metadata: HashMap<String, RuleMetadata>,
    truncated_count: u32,
    rules_total: usize,
) -> SensorReportContext {
    SensorReportContext {
        started_at: "2024-01-15T10:30:00Z".to_string(),
        ended_at: "2024-01-15T10:30:01Z".to_string(),
        duration_ms: 1234,
        capabilities,
        artifacts,
        rule_metadata,
        truncated_count,
        rules_total,
    }
}

// ============================================================================
// Property 1: Schema is always "sensor.report.v1"
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_schema_always_sensor_report_v1(
        rule_id in arb_string(),
        message in arb_string(),
        path in arb_string(),
        line in 1u32..100_000,
        suppressed in 0u32..100,
        files_scanned in 0u64..1_000_000,
        lines_scanned in 0u32..10_000_000,
        verdict_status in arb_verdict_status(),
    ) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id,
                severity: Severity::Error,
                message,
                path,
                line,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            verdict_status,
            suppressed,
            files_scanned,
            lines_scanned,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 5);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.schema, SENSOR_REPORT_SCHEMA_V1);
    }
}

// ============================================================================
// Property 2: Tool metadata preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_tool_meta_preserved(
        tool_name in "[a-z][a-z0-9_-]*",
        tool_version in "[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9]+)?",
    ) {
        let receipt = CheckReceipt {
            tool: ToolMeta {
                name: tool_name.clone(),
                version: tool_version.clone(),
            },
            ..build_receipt(vec![], VerdictStatus::Pass, 0, 0, 0)
        };
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.tool.name, tool_name);
        prop_assert_eq!(report.tool.version, tool_version);
    }
}

// ============================================================================
// Property 3: Findings count matches input
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_findings_count_matches(count in 0usize..100, suppressed in 0u32..100) {
        let findings: Vec<Finding> = (0..count)
            .map(|i| Finding {
                rule_id: format!("rule.{}", i),
                severity: Severity::Error,
                message: format!("Finding {}", i),
                path: format!("src/file{}.rs", i),
                line: (i as u32) + 1,
                column: Some(10),
                match_text: format!("match{}", i),
                snippet: format!("snippet {}", i),
            })
            .collect();

        let receipt = build_receipt(findings, VerdictStatus::Fail, suppressed, 1, 100);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 10);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings.len(), count);
    }
}

// ============================================================================
// Property 4: Findings content mapping (rule_id → code)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_finding_rule_id_maps_to_code(rule_id in "[a-z][a-z0-9_\\.]*") {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: rule_id.clone(),
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 5);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].code.as_str(), rule_id.as_str());
    }
}

// ============================================================================
// Property 5: Findings severity preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_finding_severity_preserved(severity in arb_severity()) {
        let receipt = CheckReceipt {
            findings: vec![Finding {
                rule_id: "test.rule".to_string(),
                severity,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            ..build_receipt(vec![], VerdictStatus::Fail, 0, 1, 100)
        };
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].severity, severity);
    }
}

// ============================================================================
// Property 6: Findings message preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_finding_message_preserved(message in arb_string()) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: message.clone(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].message.as_str(), message.as_str());
    }
}

// ============================================================================
// Property 7: Check ID is always "diffguard.pattern"
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_check_id_always_diffguard_pattern(rule_id in arb_string()) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id,
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].check_id.as_str(), "diffguard.pattern");
    }
}

// ============================================================================
// Property 8: Fingerprint is valid 64-char hex
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_fingerprint_is_64_char_hex(
        rule_id in arb_string(),
        match_text in arb_string(),
        snippet in arb_string(),
    ) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id,
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text,
                snippet,
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        let fp = &report.findings[0].fingerprint;
        prop_assert_eq!(fp.len(), 64);
        prop_assert!(fp.chars().all(|c: char| c.is_ascii_hexdigit()));
    }
}

// ============================================================================
// Property 9: Path normalization (backslashes → forward slashes)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_path_backslash_normalized(rule_id in arb_string()) {
        // Generate paths with Windows-style backslashes
        let path_with_backslashes = "src\\\\nested\\\\file.rs";

        let receipt = build_receipt(
            vec![Finding {
                rule_id,
                severity: Severity::Error,
                message: "test".to_string(),
                path: path_with_backslashes.to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert!(!report.findings[0].location.path.contains('\\'));
        prop_assert_eq!(report.findings[0].location.path.as_str(), "src/nested/file.rs");
    }
}

// ============================================================================
// Property 10: Line number preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_line_number_preserved(line in 1u32..1_000_000) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].location.line, line);
    }
}

// ============================================================================
// Property 11: Column preserved when present
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_column_preserved_when_present(column in 1u32..10000) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: Some(column),
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].location.column, Some(column));
    }
}

// ============================================================================
// Property 12: Column absent when None
// ============================================================================

// Note: This test has no parameters, so we use a simple #[test] instead of proptest!
#[test]
fn property_column_absent_when_none() {
    let receipt = build_receipt(
        vec![Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            message: "test".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: None,
            match_text: "test".to_string(),
            snippet: "test".to_string(),
        }],
        VerdictStatus::Fail,
        0,
        1,
        100,
    );
    let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
    let report = render_sensor_report(&receipt, &ctx);

    assert!(report.findings[0].location.column.is_none());
}

// ============================================================================
// Property 13: Finding data contains match_text and snippet
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_finding_data_contains_match_text_and_snippet(
        match_text in arb_string(),
        snippet in arb_string(),
    ) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: match_text.clone(),
                snippet: snippet.clone(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        let data = report.findings[0].data.as_ref().unwrap();
        prop_assert_eq!(data["match_text"].as_str().unwrap(), match_text);
        prop_assert_eq!(data["snippet"].as_str().unwrap(), snippet);
    }
}

// ============================================================================
// Property 14: Verdict preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_verdict_preserved(
        verdict_status in arb_verdict_status(),
        info in 0u32..100,
        warn in 0u32..100,
        error in 0u32..100,
        suppressed in 0u32..100,
    ) {
        let receipt = CheckReceipt {
            verdict: Verdict {
                status: verdict_status,
                counts: VerdictCounts { info, warn, error, suppressed },
                reasons: vec![],
            },
            ..build_receipt(vec![], verdict_status, suppressed, 1, 100)
        };
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.verdict.status, verdict_status);
        prop_assert_eq!(report.verdict.counts.info, info);
        prop_assert_eq!(report.verdict.counts.warn, warn);
        prop_assert_eq!(report.verdict.counts.error, error);
        prop_assert_eq!(report.verdict.counts.suppressed, suppressed);
    }
}

// ============================================================================
// Property 15: Run meta from context
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_run_meta_from_context(
        started_at in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        ended_at in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        duration_ms in 0u64..1_000_000_000,
    ) {
        let ctx = SensorReportContext {
            started_at: started_at.clone(),
            ended_at: ended_at.clone(),
            duration_ms,
            ..build_context(HashMap::new(), vec![], HashMap::new(), 0, 0)
        };
        let receipt = build_receipt(vec![], VerdictStatus::Pass, 0, 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.run.started_at, started_at);
        prop_assert_eq!(report.run.ended_at, ended_at);
        prop_assert_eq!(report.run.duration_ms, duration_ms);
    }
}

// ============================================================================
// Property 16: Capabilities from context
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_capabilities_from_context(cap_count in 0usize..10) {
        let mut capabilities = HashMap::new();
        for i in 0..cap_count {
            capabilities.insert(
                format!("capability_{}", i),
                CapabilityStatus {
                    status: "available".to_string(),
                    reason: None,
                    detail: None,
                },
            );
        }

        let ctx = build_context(capabilities.clone(), vec![], HashMap::new(), 0, 1);
        let receipt = build_receipt(vec![], VerdictStatus::Pass, 0, 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.run.capabilities.len(), cap_count);
        for (key, value) in capabilities {
            prop_assert_eq!(report.run.capabilities.get(&key), Some(&value));
        }
    }
}

// ============================================================================
// Property 17: Artifacts from context
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_artifacts_from_context(artifact_count in 0usize..10) {
        let artifacts: Vec<Artifact> = (0..artifact_count)
            .map(|i| Artifact {
                path: format!("artifacts/report{}.json", i),
                format: "json".to_string(),
            })
            .collect();

        let ctx = build_context(HashMap::new(), artifacts.clone(), HashMap::new(), 0, 1);
        let receipt = build_receipt(vec![], VerdictStatus::Pass, 0, 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.artifacts.len(), artifact_count);
        prop_assert_eq!(report.artifacts, artifacts);
    }
}

// ============================================================================
// Property 18: suppressed_count in data matches verdict
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_suppressed_count_in_data(suppressed in 0u32..100) {
        let receipt = build_receipt(vec![], VerdictStatus::Fail, suppressed, 0, 0);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        let data = report.data.as_ref().unwrap();
        let diffguard = data.get("diffguard").unwrap();
        let reported_suppressed = diffguard.get("suppressed_count").unwrap().as_u64().unwrap() as u32;

        prop_assert_eq!(reported_suppressed, suppressed);
    }
}

// ============================================================================
// Property 19: truncated_count from context
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_truncated_count_from_context(truncated_count in 0u32..1000) {
        let receipt = build_receipt(vec![], VerdictStatus::Fail, 0, 0, 0);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), truncated_count, 0);
        let report = render_sensor_report(&receipt, &ctx);

        let data = report.data.as_ref().unwrap();
        let diffguard = data.get("diffguard").unwrap();
        let reported_truncated = diffguard.get("truncated_count").unwrap().as_u64().unwrap() as u32;

        prop_assert_eq!(reported_truncated, truncated_count);
    }
}

// ============================================================================
// Property 20: rules_total from context
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_rules_total_from_context(rules_total in 0usize..1000) {
        let receipt = build_receipt(vec![], VerdictStatus::Fail, 0, 0, 0);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, rules_total);
        let report = render_sensor_report(&receipt, &ctx);

        let data = report.data.as_ref().unwrap();
        let diffguard = data.get("diffguard").unwrap();
        let reported_rules_total = diffguard.get("rules_total").unwrap().as_u64().unwrap() as usize;

        prop_assert_eq!(reported_rules_total, rules_total);
    }
}

// ============================================================================
// Property 21: Diff metadata preserved
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_diff_metadata_preserved(
        base in arb_string(),
        head in arb_string(),
        context_lines in 0u32..100,
        scope in arb_scope(),
        files_scanned in 0u64..1_000_000,
        lines_scanned in 0u32..10_000_000,
    ) {
        let receipt = CheckReceipt {
            diff: DiffMeta {
                base: base.clone(),
                head: head.clone(),
                context_lines,
                scope,
                files_scanned,
                lines_scanned,
            },
            ..build_receipt(vec![], VerdictStatus::Pass, 0, files_scanned, lines_scanned)
        };
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        let data = report.data.as_ref().unwrap();
        let diff_data = data.get("diff").unwrap();

        prop_assert_eq!(diff_data["base"].as_str().unwrap(), base);
        prop_assert_eq!(diff_data["head"].as_str().unwrap(), head);
        prop_assert_eq!(diff_data["context_lines"].as_u64().unwrap() as u32, context_lines);
        prop_assert_eq!(diff_data["files_scanned"].as_u64().unwrap(), files_scanned);
        prop_assert_eq!(diff_data["lines_scanned"].as_u64().unwrap() as u32, lines_scanned);
    }
}

// ============================================================================
// Property 22: tags_matched aggregated correctly
// ============================================================================

// Note: Uses fixed rule metadata, not generated - validates aggregation logic
#[test]
fn property_tags_matched_aggregated() {
    let findings = vec![
        Finding {
            rule_id: "rule1".to_string(),
            severity: Severity::Error,
            message: "test".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: None,
            match_text: "test".to_string(),
            snippet: "test".to_string(),
        },
        Finding {
            rule_id: "rule2".to_string(),
            severity: Severity::Warn,
            message: "test".to_string(),
            path: "src/lib.rs".to_string(),
            line: 2,
            column: None,
            match_text: "test".to_string(),
            snippet: "test".to_string(),
        },
    ];

    let receipt = build_receipt(findings, VerdictStatus::Fail, 0, 1, 100);

    let mut rule_metadata = HashMap::new();
    rule_metadata.insert(
        "rule1".to_string(),
        RuleMetadata {
            help: None,
            url: None,
            tags: vec!["tag1".to_string()],
        },
    );
    rule_metadata.insert(
        "rule2".to_string(),
        RuleMetadata {
            help: None,
            url: None,
            tags: vec!["tag1".to_string(), "tag2".to_string()],
        },
    );

    let ctx = build_context(HashMap::new(), vec![], rule_metadata, 0, 2);
    let report = render_sensor_report(&receipt, &ctx);

    let data = report.data.as_ref().unwrap();
    let diffguard = data.get("diffguard").unwrap();
    let tags_matched = diffguard.get("tags_matched").unwrap().as_object().unwrap();

    // tag1 appears in both rules = 2 total
    assert_eq!(tags_matched.get("tag1").unwrap().as_u64().unwrap(), 2);
    // tag2 appears only in rule2 = 1 total
    assert_eq!(tags_matched.get("tag2").unwrap().as_u64().unwrap(), 1);
}

// ============================================================================
// Property 23: render_sensor_json produces valid JSON
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_render_sensor_json_valid_json(count in 0usize..20) {
        let findings: Vec<Finding> = (0..count)
            .map(|i| Finding {
                rule_id: format!("rule.{}", i),
                severity: if i % 2 == 0 { Severity::Error } else { Severity::Warn },
                message: format!("Message {}", i),
                path: format!("src/file{}.rs", i),
                line: (i as u32) + 1,
                column: Some((i as u32) * 10),
                match_text: format!("match{}", i),
                snippet: format!("snippet {}", i),
            })
            .collect();

        let receipt = build_receipt(findings, VerdictStatus::Fail, 0, count as u64, 1000);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, count);

        let json_result = render_sensor_json(&receipt, &ctx);
        prop_assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        // Verify it can be parsed back
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        prop_assert!(parsed.is_object());
    }
}

// ============================================================================
// Property 24: Empty findings still produces valid report
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_empty_findings_produces_valid_report(verdict_status in arb_verdict_status()) {
        let receipt = build_receipt(vec![], verdict_status, 0, 0, 0);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, 0);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.schema, SENSOR_REPORT_SCHEMA_V1);
        prop_assert_eq!(report.findings.len(), 0);
        prop_assert_eq!(report.verdict.status, verdict_status);
    }
}

// ============================================================================
// Property 25: Help and URL from rule metadata
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_help_url_from_rule_metadata(
        has_help in prop::sample::subsequence(vec![true, false], 1),
        has_url in prop::sample::subsequence(vec![true, false], 1),
    ) {
        let receipt = build_receipt(
            vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "test".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }],
            VerdictStatus::Fail,
            0,
            1,
            100,
        );

        let mut rule_metadata = HashMap::new();
        rule_metadata.insert("test.rule".to_string(), RuleMetadata {
            help: if has_help[0] { Some("Use ? instead".to_string()) } else { None },
            url: if has_url[0] { Some("https://example.com".to_string()) } else { None },
            tags: vec![],
        });

        let ctx = build_context(HashMap::new(), vec![], rule_metadata, 0, 1);
        let report = render_sensor_report(&receipt, &ctx);

        prop_assert_eq!(report.findings[0].help.is_some(), has_help[0]);
        prop_assert_eq!(report.findings[0].url.is_some(), has_url[0]);
    }
}

// ============================================================================
// Property 26: No tags_matched when no rule metadata has tags
// ============================================================================

// Note: This test has no parameters, so we use a simple #[test] instead of proptest!
#[test]
fn property_no_tags_matched_when_no_tags_in_metadata() {
    let receipt = build_receipt(
        vec![Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Error,
            message: "test".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: None,
            match_text: "test".to_string(),
            snippet: "test".to_string(),
        }],
        VerdictStatus::Fail,
        0,
        1,
        100,
    );

    let rule_metadata = HashMap::new();
    let ctx = build_context(HashMap::new(), vec![], rule_metadata, 0, 1);
    let report = render_sensor_report(&receipt, &ctx);

    let data = report.data.as_ref().unwrap();
    let diffguard = data.get("diffguard").unwrap();

    assert!(!diffguard.as_object().unwrap().contains_key("tags_matched"));
}

// ============================================================================
// Property 27: rules_matched is distinct rule_id count
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_rules_matched_is_distinct_rule_count(finding_count in 0usize..20) {
        // Create findings with some repeated rule_ids
        let findings: Vec<Finding> = (0..finding_count)
            .map(|i| Finding {
                // Each rule_id appears roughly twice (i and i^1)
                rule_id: format!("rule.{}", i / 2),
                severity: Severity::Error,
                message: format!("Finding {}", i),
                path: format!("src/file{}.rs", i),
                line: (i as u32) + 1,
                column: None,
                match_text: format!("match{}", i),
                snippet: format!("snippet {}", i),
            })
            .collect();

        let receipt = build_receipt(findings.clone(), VerdictStatus::Fail, 0, 1, 100);
        let ctx = build_context(HashMap::new(), vec![], HashMap::new(), 0, finding_count);
        let report = render_sensor_report(&receipt, &ctx);

        // Count distinct rule_ids
        let mut distinct_rules = std::collections::HashSet::new();
        for f in &findings {
            distinct_rules.insert(&f.rule_id);
        }

        let data = report.data.as_ref().unwrap();
        let diffguard = data.get("diffguard").unwrap();
        let rules_matched = diffguard.get("rules_matched").unwrap().as_u64().unwrap() as usize;

        prop_assert_eq!(rules_matched, distinct_rules.len());
    }
}
