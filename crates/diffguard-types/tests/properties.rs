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
                    help: None,
                    url: None,
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
    (0u32..100, 0u32..100, 0u32..100, 0u32..50).prop_map(|(info, warn, error, suppressed)| {
        VerdictCounts {
            info,
            warn,
            error,
            suppressed,
        }
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
// Helper Functions for Field Name Validation
// ============================================================================

/// Check if a string is in snake_case format.
/// Snake case: lowercase letters, digits, and underscores only.
/// Must not start or end with underscore, no consecutive underscores.
fn is_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Must not start or end with underscore
    if s.starts_with('_') || s.ends_with('_') {
        return false;
    }

    // Must not contain consecutive underscores
    if s.contains("__") {
        return false;
    }

    // Must only contain lowercase letters, digits, and underscores
    // Must not contain uppercase letters (which would indicate camelCase)
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Recursively collect all field names from a JSON value.
fn collect_field_names(value: &serde_json::Value, field_names: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                field_names.push(key.clone());
                collect_field_names(val, field_names);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_field_names(item, field_names);
            }
        }
        _ => {}
    }
}

/// Verify all field names in a JSON value are snake_case.
fn verify_snake_case_fields(value: &serde_json::Value) -> Result<(), Vec<String>> {
    let mut field_names = Vec::new();
    collect_field_names(value, &mut field_names);

    let non_snake_case: Vec<String> = field_names
        .into_iter()
        .filter(|name| !is_snake_case(name))
        .collect();

    if non_snake_case.is_empty() {
        Ok(())
    } else {
        Err(non_snake_case)
    }
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // ========================================================================
    // Property 2: Schema Validation (field names)
    // Feature: comprehensive-test-coverage
    // **Validates: Requirements 1.4**
    // ========================================================================

    /// **Property 2: Schema Validation (ConfigFile field names)**
    ///
    /// For any valid ConfigFile instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format (e.g., "fail_on" not "failOn").
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn config_file_field_names_are_snake_case(config in arb_config_file()) {
        // Serialize the ConfigFile to JSON
        let json_value = serde_json::to_value(&config)
            .expect("ConfigFile should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "ConfigFile field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    /// **Property 2: Schema Validation (CheckReceipt field names)**
    ///
    /// For any valid CheckReceipt instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format (e.g., "rule_id" not "ruleId").
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn check_receipt_field_names_are_snake_case(receipt in arb_check_receipt()) {
        // Serialize the CheckReceipt to JSON
        let json_value = serde_json::to_value(&receipt)
            .expect("CheckReceipt should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "CheckReceipt field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    /// **Property 2: Schema Validation (RuleConfig field names)**
    ///
    /// For any valid RuleConfig instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format.
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn rule_config_field_names_are_snake_case(rule in arb_rule_config()) {
        // Serialize the RuleConfig to JSON
        let json_value = serde_json::to_value(&rule)
            .expect("RuleConfig should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "RuleConfig field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    /// **Property 2: Schema Validation (Finding field names)**
    ///
    /// For any valid Finding instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format.
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn finding_field_names_are_snake_case(finding in arb_finding()) {
        // Serialize the Finding to JSON
        let json_value = serde_json::to_value(&finding)
            .expect("Finding should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "Finding field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    /// **Property 2: Schema Validation (Defaults field names)**
    ///
    /// For any valid Defaults instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format.
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn defaults_field_names_are_snake_case(defaults in arb_defaults()) {
        // Serialize the Defaults to JSON
        let json_value = serde_json::to_value(&defaults)
            .expect("Defaults should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "Defaults field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    /// **Property 2: Schema Validation (Verdict field names)**
    ///
    /// For any valid Verdict instance, serializing to JSON SHALL produce
    /// field names that are all in snake_case format.
    ///
    /// Feature: comprehensive-test-coverage, Property 2: Schema Validation
    /// **Validates: Requirements 1.4**
    #[test]
    fn verdict_field_names_are_snake_case(verdict in arb_verdict()) {
        // Serialize the Verdict to JSON
        let json_value = serde_json::to_value(&verdict)
            .expect("Verdict should serialize to JSON");

        // Verify all field names are snake_case
        let result = verify_snake_case_fields(&json_value);
        prop_assert!(
            result.is_ok(),
            "Verdict field names should be snake_case. Non-snake_case fields: {:?}",
            result.err()
        );
    }

    // ========================================================================
    // Property 1: Serialization Round-Trip (enum variants)
    // Feature: comprehensive-test-coverage
    // **Validates: Requirements 1.5**
    // ========================================================================

    /// **Property 1: Serialization Round-Trip (Severity enum)**
    ///
    /// For any valid Severity variant, serializing to JSON and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// Feature: comprehensive-test-coverage, Property 1: Serialization Round-Trip
    /// **Validates: Requirements 1.5**
    #[test]
    fn severity_json_round_trip(severity in arb_severity()) {
        // Serialize the Severity to JSON
        let json_string = serde_json::to_string(&severity)
            .expect("Severity should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: Severity = serde_json::from_str(&json_string)
            .expect("Severity should deserialize from JSON");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            severity, deserialized,
            "Severity JSON round-trip should produce equivalent value"
        );
    }

    /// **Property 1: Serialization Round-Trip (Scope enum)**
    ///
    /// For any valid Scope variant, serializing to JSON and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// Feature: comprehensive-test-coverage, Property 1: Serialization Round-Trip
    /// **Validates: Requirements 1.5**
    #[test]
    fn scope_json_round_trip(scope in arb_scope()) {
        // Serialize the Scope to JSON
        let json_string = serde_json::to_string(&scope)
            .expect("Scope should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: Scope = serde_json::from_str(&json_string)
            .expect("Scope should deserialize from JSON");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            scope, deserialized,
            "Scope JSON round-trip should produce equivalent value"
        );
    }

    /// **Property 1: Serialization Round-Trip (FailOn enum)**
    ///
    /// For any valid FailOn variant, serializing to JSON and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// Feature: comprehensive-test-coverage, Property 1: Serialization Round-Trip
    /// **Validates: Requirements 1.5**
    #[test]
    fn fail_on_json_round_trip(fail_on in arb_fail_on()) {
        // Serialize the FailOn to JSON
        let json_string = serde_json::to_string(&fail_on)
            .expect("FailOn should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: FailOn = serde_json::from_str(&json_string)
            .expect("FailOn should deserialize from JSON");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            fail_on, deserialized,
            "FailOn JSON round-trip should produce equivalent value"
        );
    }

    /// **Property 1: Serialization Round-Trip (VerdictStatus enum)**
    ///
    /// For any valid VerdictStatus variant, serializing to JSON and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// Feature: comprehensive-test-coverage, Property 1: Serialization Round-Trip
    /// **Validates: Requirements 1.5**
    #[test]
    fn verdict_status_json_round_trip(status in arb_verdict_status()) {
        // Serialize the VerdictStatus to JSON
        let json_string = serde_json::to_string(&status)
            .expect("VerdictStatus should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: VerdictStatus = serde_json::from_str(&json_string)
            .expect("VerdictStatus should deserialize from JSON");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            status, deserialized,
            "VerdictStatus JSON round-trip should produce equivalent value"
        );
    }

    // ========================================================================
    // Property 1: Serialization Round-Trip (ConfigFile TOML)
    // Feature: comprehensive-test-coverage
    // **Validates: Requirements 1.2**
    // ========================================================================

    /// **Property 1: Serialization Round-Trip (ConfigFile TOML)**
    ///
    /// For any valid ConfigFile instance, serializing to TOML and deserializing
    /// back SHALL produce an equivalent value.
    ///
    /// Feature: comprehensive-test-coverage, Property 1: Serialization Round-Trip
    /// **Validates: Requirements 1.2**
    #[test]
    fn config_file_toml_round_trip(config in arb_config_file()) {
        // Serialize the ConfigFile to TOML
        let toml_string = toml::to_string(&config)
            .expect("ConfigFile should serialize to TOML");

        // Deserialize back from TOML
        let deserialized: ConfigFile = toml::from_str(&toml_string)
            .expect("ConfigFile should deserialize from TOML");

        // Verify round-trip produces equivalent value
        prop_assert_eq!(
            config, deserialized,
            "ConfigFile TOML round-trip should produce equivalent value"
        );
    }

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

    // ========================================================================
    // Unit tests for is_snake_case helper function
    // ========================================================================

    #[test]
    fn is_snake_case_accepts_valid_snake_case() {
        assert!(is_snake_case("hello"));
        assert!(is_snake_case("hello_world"));
        assert!(is_snake_case("rule_id"));
        assert!(is_snake_case("fail_on"));
        assert!(is_snake_case("max_findings"));
        assert!(is_snake_case("context_lines"));
        assert!(is_snake_case("files_scanned"));
        assert!(is_snake_case("lines_scanned"));
        assert!(is_snake_case("exclude_paths"));
        assert!(is_snake_case("ignore_comments"));
        assert!(is_snake_case("ignore_strings"));
        assert!(is_snake_case("match_text"));
        assert!(is_snake_case("diff_context"));
        assert!(is_snake_case("a"));
        assert!(is_snake_case("a1"));
        assert!(is_snake_case("test123"));
        assert!(is_snake_case("a_b_c"));
    }

    #[test]
    fn is_snake_case_rejects_camel_case() {
        assert!(!is_snake_case("helloWorld"));
        assert!(!is_snake_case("ruleId"));
        assert!(!is_snake_case("failOn"));
        assert!(!is_snake_case("maxFindings"));
        assert!(!is_snake_case("contextLines"));
        assert!(!is_snake_case("filesScanned"));
        assert!(!is_snake_case("linesScanned"));
        assert!(!is_snake_case("excludePaths"));
        assert!(!is_snake_case("ignoreComments"));
        assert!(!is_snake_case("ignoreStrings"));
        assert!(!is_snake_case("matchText"));
        assert!(!is_snake_case("diffContext"));
    }

    #[test]
    fn is_snake_case_rejects_invalid_formats() {
        assert!(!is_snake_case("")); // empty
        assert!(!is_snake_case("_hello")); // starts with underscore
        assert!(!is_snake_case("hello_")); // ends with underscore
        assert!(!is_snake_case("hello__world")); // consecutive underscores
        assert!(!is_snake_case("Hello")); // uppercase
        assert!(!is_snake_case("HELLO")); // all uppercase
        assert!(!is_snake_case("hello-world")); // kebab-case
        assert!(!is_snake_case("hello world")); // space
    }

    // ========================================================================
    // Unit tests for schema validation
    // ========================================================================

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
                    suppressed: 0,
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

    // ========================================================================
    // JSON Round-Trip Tests
    // ========================================================================

    #[test]
    fn config_file_json_round_trip() {
        let config = ConfigFile::built_in();

        // Serialize to JSON
        let json_string =
            serde_json::to_string(&config).expect("ConfigFile should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: ConfigFile =
            serde_json::from_str(&json_string).expect("ConfigFile should deserialize from JSON");

        // Verify round-trip produces equivalent value
        assert_eq!(
            config, deserialized,
            "ConfigFile JSON round-trip should produce equivalent value"
        );
    }

    #[test]
    fn check_receipt_json_round_trip() {
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
            findings: vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Warn,
                message: "Test message".to_string(),
                path: "src/test.rs".to_string(),
                line: 10,
                column: Some(5),
                match_text: "match".to_string(),
                snippet: "test snippet".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec!["1 warning".to_string()],
            },
        };

        // Serialize to JSON
        let json_string =
            serde_json::to_string(&receipt).expect("CheckReceipt should serialize to JSON");

        // Deserialize back from JSON
        let deserialized: CheckReceipt =
            serde_json::from_str(&json_string).expect("CheckReceipt should deserialize from JSON");

        // Verify round-trip produces equivalent value
        assert_eq!(
            receipt, deserialized,
            "CheckReceipt JSON round-trip should produce equivalent value"
        );
    }

    // ========================================================================
    // Schema Validation Negative Tests
    // ========================================================================

    #[test]
    fn invalid_severity_rejected_by_schema() {
        let schema = load_check_schema();

        // Create invalid JSON with wrong severity value
        let invalid_json = serde_json::json!({
            "schema": "diffguard.check.v1",
            "tool": {"name": "test", "version": "1.0"},
            "diff": {
                "base": "main",
                "head": "HEAD",
                "context_lines": 0,
                "scope": "added",
                "files_scanned": 1,
                "lines_scanned": 1
            },
            "findings": [{
                "rule_id": "test",
                "severity": "critical",  // Invalid severity
                "message": "msg",
                "path": "test.rs",
                "line": 1,
                "match_text": "x",
                "snippet": "x"
            }],
            "verdict": {
                "status": "pass",
                "counts": {"info": 0, "warn": 0, "error": 0},
                "reasons": []
            }
        });

        let result = schema.validate(&invalid_json);
        assert!(
            result.is_err(),
            "Invalid severity should be rejected by schema"
        );
    }

    #[test]
    fn missing_required_field_rejected_by_schema() {
        let schema = load_check_schema();

        // Create invalid JSON missing required 'schema' field
        let invalid_json = serde_json::json!({
            // "schema" is missing
            "tool": {"name": "test", "version": "1.0"},
            "diff": {
                "base": "main",
                "head": "HEAD",
                "context_lines": 0,
                "scope": "added",
                "files_scanned": 1,
                "lines_scanned": 1
            },
            "findings": [],
            "verdict": {
                "status": "pass",
                "counts": {"info": 0, "warn": 0, "error": 0},
                "reasons": []
            }
        });

        let result = schema.validate(&invalid_json);
        assert!(
            result.is_err(),
            "Missing required field should be rejected by schema"
        );
    }

    #[test]
    fn invalid_scope_rejected_by_config_schema() {
        let schema = load_config_schema();

        // Create invalid JSON with wrong scope value
        let invalid_json = serde_json::json!({
            "defaults": {
                "scope": "modified"  // Invalid scope (should be "added" or "changed")
            },
            "rule": []
        });

        let result = schema.validate(&invalid_json);
        assert!(
            result.is_err(),
            "Invalid scope should be rejected by config schema"
        );
    }

    #[test]
    fn invalid_fail_on_rejected_by_config_schema() {
        let schema = load_config_schema();

        // Create invalid JSON with wrong fail_on value
        let invalid_json = serde_json::json!({
            "defaults": {
                "fail_on": "always"  // Invalid (should be "error", "warn", or "never")
            },
            "rule": []
        });

        let result = schema.validate(&invalid_json);
        assert!(
            result.is_err(),
            "Invalid fail_on should be rejected by config schema"
        );
    }

    #[test]
    fn rule_missing_patterns_rejected_by_config_schema() {
        let schema = load_config_schema();

        // Create invalid JSON with rule missing required 'patterns' field
        let invalid_json = serde_json::json!({
            "defaults": {},
            "rule": [{
                "id": "test.rule",
                "severity": "warn",
                "message": "Test",
                // "patterns" is missing
            }]
        });

        let result = schema.validate(&invalid_json);
        assert!(
            result.is_err(),
            "Rule missing patterns should be rejected by config schema"
        );
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn config_with_all_optional_fields_null() {
        let schema = load_config_schema();
        let config = ConfigFile {
            defaults: Defaults {
                base: None,
                head: None,
                scope: None,
                fail_on: None,
                max_findings: None,
                diff_context: None,
            },
            rule: vec![],
        };

        let json_value =
            serde_json::to_value(&config).expect("ConfigFile should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "ConfigFile with all optional fields null should validate. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn finding_without_column_validates() {
        let schema = load_check_schema();
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "test".to_string(),
                version: "1.0".to_string(),
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
                rule_id: "test".to_string(),
                severity: Severity::Info,
                message: "info message".to_string(),
                path: "test.txt".to_string(),
                line: 1,
                column: None, // Optional field is None
                match_text: "x".to_string(),
                snippet: "x".to_string(),
            }],
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
            "Finding without column should validate. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn max_u32_values_validate() {
        let schema = load_check_schema();
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: u32::MAX,
                scope: Scope::Added,
                files_scanned: u32::MAX,
                lines_scanned: u32::MAX,
            },
            findings: vec![Finding {
                rule_id: "test".to_string(),
                severity: Severity::Info,
                message: "msg".to_string(),
                path: "test.txt".to_string(),
                line: u32::MAX,
                column: Some(u32::MAX),
                match_text: "x".to_string(),
                snippet: "x".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts {
                    info: u32::MAX,
                    warn: u32::MAX,
                    error: u32::MAX,
                    suppressed: 0,
                },
                reasons: vec![],
            },
        };

        let json_value =
            serde_json::to_value(&receipt).expect("CheckReceipt should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "Max u32 values should validate. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn unicode_content_validates() {
        let schema = load_check_schema();
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
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
                rule_id: "test.unicode".to_string(),
                severity: Severity::Warn,
                message: "Unicode message: \u{4e2d}\u{6587}".to_string(),
                path: "src/\u{65e5}\u{672c}\u{8a9e}.rs".to_string(),
                line: 1,
                column: Some(1),
                match_text: "\u{1f600}".to_string(),
                snippet: "let emoji = \"\u{1f680}\";".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec!["\u{8b66}\u{544a}".to_string()],
            },
        };

        let json_value =
            serde_json::to_value(&receipt).expect("CheckReceipt should serialize to JSON");

        let result = schema.validate(&json_value);
        assert!(
            result.is_ok(),
            "Unicode content should validate. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn empty_strings_validate() {
        let schema = load_check_schema();
        let receipt = CheckReceipt {
            schema: "".to_string(), // Empty but still valid string
            tool: ToolMeta {
                name: "".to_string(),
                version: "".to_string(),
            },
            diff: DiffMeta {
                base: "".to_string(),
                head: "".to_string(),
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
            "Empty strings should validate. Errors: {:?}",
            result.err().map(|e| e.collect::<Vec<_>>())
        );
    }

    #[test]
    fn severity_as_str_matches_expected() {
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Warn.as_str(), "warn");
        assert_eq!(Severity::Error.as_str(), "error");
    }

    #[test]
    fn scope_as_str_matches_expected() {
        assert_eq!(Scope::Added.as_str(), "added");
        assert_eq!(Scope::Changed.as_str(), "changed");
    }

    #[test]
    fn fail_on_as_str_matches_expected() {
        assert_eq!(FailOn::Error.as_str(), "error");
        assert_eq!(FailOn::Warn.as_str(), "warn");
        assert_eq!(FailOn::Never.as_str(), "never");
    }

    #[test]
    fn verdict_counts_suppressed_skips_zero() {
        let counts = VerdictCounts {
            info: 0,
            warn: 0,
            error: 0,
            suppressed: 0,
        };
        let json_value = serde_json::to_value(&counts).expect("counts serialize");
        let object = json_value.as_object().expect("counts should be object");
        assert!(
            !object.contains_key("suppressed"),
            "suppressed should be omitted when zero"
        );
    }

    #[test]
    fn verdict_counts_suppressed_serializes_when_nonzero() {
        let counts = VerdictCounts {
            info: 0,
            warn: 0,
            error: 0,
            suppressed: 2,
        };
        let json_value = serde_json::to_value(&counts).expect("counts serialize");
        let object = json_value.as_object().expect("counts should be object");
        assert_eq!(
            object.get("suppressed"),
            Some(&serde_json::json!(2)),
            "suppressed should serialize when non-zero"
        );
    }
}
