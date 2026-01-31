//! Property-based tests for diffguard-types.
//!
//! Feature: diffguard-completion, Property 9: Schema Validation Round-Trip

use diffguard_types::{
    CheckReceipt, ConfigFile, Defaults, DiffMeta, FailOn, Finding, RuleConfig, Scope, Severity,
    ToolMeta, Verdict, VerdictCounts, VerdictStatus, CHECK_SCHEMA_V1,
};
use jsonschema::JSONSchema;
use proptest::prelude::*;

/// Load the config schema from the schemas directory.
fn load_config_schema() -> JSONSchema {
    let schema_str = include_str!("../../../schemas/diffguard.config.schema.json");
    let schema: serde_json::Value = serde_json::from_str(schema_str).expect("valid JSON schema");
    JSONSchema::compile(&schema).expect("valid JSON schema")
}

/// Load the check receipt schema from the schemas directory.
fn load_check_schema() -> JSONSchema {
    let schema_str = include_str!("../../../schemas/diffguard.check.schema.json");
    let schema: serde_json::Value = serde_json::from_str(schema_str).expect("valid JSON schema");
    JSONSchema::compile(&schema).expect("valid JSON schema")
}

// ============================================================================
// Proptest Strategies for generating random instances
// ============================================================================

/// Strategy for generating valid Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating valid Scope values.
fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![Just(Scope::Added), Just(Scope::Changed),]
}

/// Strategy for generating valid FailOn values.
fn arb_fail_on() -> impl Strategy<Value = FailOn> {
    prop_oneof![Just(FailOn::Error), Just(FailOn::Warn), Just(FailOn::Never),]
}

/// Strategy for generating valid VerdictStatus values.
fn arb_verdict_status() -> impl Strategy<Value = VerdictStatus> {
    prop_oneof![
        Just(VerdictStatus::Pass),
        Just(VerdictStatus::Warn),
        Just(VerdictStatus::Fail),
    ]
}

/// Strategy for generating non-empty strings (for required fields).
fn arb_non_empty_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.-]{1,50}".prop_map(|s| s)
}

/// Strategy for generating optional strings.
fn arb_optional_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), arb_non_empty_string().prop_map(Some),]
}

/// Strategy for generating a vector of strings (for paths, patterns, etc.).
fn arb_string_vec() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_non_empty_string(), 0..5)
}

/// Strategy for generating valid Defaults.
fn arb_defaults() -> impl Strategy<Value = Defaults> {
    (
        arb_optional_string(),
        arb_optional_string(),
        prop::option::of(arb_scope()),
        prop::option::of(arb_fail_on()),
        prop::option::of(0u32..1000),
        prop::option::of(0u32..10),
    )
        .prop_map(
            |(base, head, scope, fail_on, max_findings, diff_context)| Defaults {
                base,
                head,
                scope,
                fail_on,
                max_findings,
                diff_context,
            },
        )
}

/// Strategy for generating valid RuleConfig.
/// Note: patterns must be non-empty for a valid rule.
fn arb_rule_config() -> impl Strategy<Value = RuleConfig> {
    (
        arb_non_empty_string(),                              // id
        arb_severity(),                                      // severity
        arb_non_empty_string(),                              // message
        arb_string_vec(),                                    // languages
        prop::collection::vec(arb_non_empty_string(), 1..5), // patterns (at least 1)
        arb_string_vec(),                                    // paths
        arb_string_vec(),                                    // exclude_paths
        any::<bool>(),                                       // ignore_comments
        any::<bool>(),                                       // ignore_strings
    )
        .prop_map(
            |(
                id,
                severity,
                message,
                languages,
                patterns,
                paths,
                exclude_paths,
                ignore_comments,
                ignore_strings,
            )| {
                RuleConfig {
                    id,
                    severity,
                    message,
                    languages,
                    patterns,
                    paths,
                    exclude_paths,
                    ignore_comments,
                    ignore_strings,
                }
            },
        )
}

/// Strategy for generating valid ConfigFile.
fn arb_config_file() -> impl Strategy<Value = ConfigFile> {
    (
        arb_defaults(),
        prop::collection::vec(arb_rule_config(), 0..5),
    )
        .prop_map(|(defaults, rule)| ConfigFile { defaults, rule })
}

/// Strategy for generating valid ToolMeta.
fn arb_tool_meta() -> impl Strategy<Value = ToolMeta> {
    (arb_non_empty_string(), arb_non_empty_string())
        .prop_map(|(name, version)| ToolMeta { name, version })
}

/// Strategy for generating valid DiffMeta.
fn arb_diff_meta() -> impl Strategy<Value = DiffMeta> {
    (
        arb_non_empty_string(), // base
        arb_non_empty_string(), // head
        0u32..100,              // context_lines
        arb_scope(),            // scope
        0u32..1000,             // files_scanned
        0u32..10000,            // lines_scanned
    )
        .prop_map(
            |(base, head, context_lines, scope, files_scanned, lines_scanned)| DiffMeta {
                base,
                head,
                context_lines,
                scope,
                files_scanned,
                lines_scanned,
            },
        )
}

/// Strategy for generating valid Finding.
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_non_empty_string(),      // rule_id
        arb_severity(),              // severity
        arb_non_empty_string(),      // message
        arb_non_empty_string(),      // path
        1u32..10000,                 // line
        prop::option::of(1u32..500), // column
        arb_non_empty_string(),      // match_text
        arb_non_empty_string(),      // snippet
    )
        .prop_map(
            |(rule_id, severity, message, path, line, column, match_text, snippet)| Finding {
                rule_id,
                severity,
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating valid VerdictCounts.
fn arb_verdict_counts() -> impl Strategy<Value = VerdictCounts> {
    (0u32..100, 0u32..100, 0u32..100).prop_map(|(info, warn, error)| VerdictCounts {
        info,
        warn,
        error,
    })
}

/// Strategy for generating valid Verdict.
fn arb_verdict() -> impl Strategy<Value = Verdict> {
    (arb_verdict_status(), arb_verdict_counts(), arb_string_vec()).prop_map(
        |(status, counts, reasons)| Verdict {
            status,
            counts,
            reasons,
        },
    )
}

/// Strategy for generating valid CheckReceipt.
fn arb_check_receipt() -> impl Strategy<Value = CheckReceipt> {
    (
        arb_tool_meta(),
        arb_diff_meta(),
        prop::collection::vec(arb_finding(), 0..10),
        arb_verdict(),
    )
        .prop_map(|(tool, diff, findings, verdict)| CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool,
            diff,
            findings,
            verdict,
        })
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Property 9: Schema Validation Round-Trip (ConfigFile)**
    ///
    /// For any valid ConfigFile instance, serializing to JSON and validating
    /// against the generated JSON schema SHALL succeed.
    ///
    /// **Validates: Requirements 5.3**
    #[test]
    fn config_file_validates_against_schema(config in arb_config_file()) {
        // Feature: diffguard-completion, Property 9: Schema Validation Round-Trip
        let schema = load_config_schema();

        // Serialize the ConfigFile to JSON
        let json_value = serde_json::to_value(&config)
            .expect("ConfigFile should serialize to JSON");

        // Validate against the schema
        let result = schema.validate(&json_value);
        prop_assert!(
            result.is_ok(),
            "ConfigFile should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    /// **Property 9: Schema Validation Round-Trip (CheckReceipt)**
    ///
    /// For any valid CheckReceipt instance, serializing to JSON and validating
    /// against the generated JSON schema SHALL succeed.
    ///
    /// **Validates: Requirements 5.4**
    #[test]
    fn check_receipt_validates_against_schema(receipt in arb_check_receipt()) {
        // Feature: diffguard-completion, Property 9: Schema Validation Round-Trip
        let schema = load_check_schema();

        // Serialize the CheckReceipt to JSON
        let json_value = serde_json::to_value(&receipt)
            .expect("CheckReceipt should serialize to JSON");

        // Validate against the schema
        let result = schema.validate(&json_value);
        prop_assert!(
            result.is_ok(),
            "CheckReceipt should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }
}

// ============================================================================
// Additional Unit Tests for Schema Validation
// ============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn built_in_config_validates_against_schema() {
        let schema = load_config_schema();
        let config = ConfigFile::built_in();

        let json_value =
            serde_json::to_value(&config).expect("ConfigFile should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "Built-in ConfigFile should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn empty_config_validates_against_schema() {
        let schema = load_config_schema();
        let config = ConfigFile {
            defaults: Defaults::default(),
            rule: vec![],
        };

        let json_value =
            serde_json::to_value(&config).expect("ConfigFile should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "Empty ConfigFile should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn minimal_check_receipt_validates_against_schema() {
        let schema = load_check_schema();
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
                files_scanned: 0,
                lines_scanned: 0,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
        };

        let json_value =
            serde_json::to_value(&receipt).expect("CheckReceipt should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "Minimal CheckReceipt should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn check_receipt_with_findings_validates_against_schema() {
        let schema = load_check_schema();
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 3,
                scope: Scope::Changed,
                files_scanned: 5,
                lines_scanned: 100,
            },
            findings: vec![
                Finding {
                    rule_id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap".to_string(),
                    path: "src/main.rs".to_string(),
                    line: 42,
                    column: Some(10),
                    match_text: ".unwrap()".to_string(),
                    snippet: "let x = foo.unwrap();".to_string(),
                },
                Finding {
                    rule_id: "rust.no_dbg".to_string(),
                    severity: Severity::Warn,
                    message: "Remove dbg!".to_string(),
                    path: "src/lib.rs".to_string(),
                    line: 100,
                    column: None,
                    match_text: "dbg!".to_string(),
                    snippet: "dbg!(value);".to_string(),
                },
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 1,
                },
                reasons: vec!["1 error-level finding".to_string()],
            },
        };

        let json_value =
            serde_json::to_value(&receipt).expect("CheckReceipt should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "CheckReceipt with findings should validate against schema. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }
}
