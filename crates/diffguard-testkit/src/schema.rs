//! JSON schema validators for diffguard DTOs.
//!
//! This module provides functions to validate DTOs against their
//! schemars-generated JSON schemas.

use diffguard_types::{CheckReceipt, ConfigFile};
use jsonschema::JSONSchema;

/// Error type for schema validation failures.
#[derive(Debug)]
pub struct SchemaValidationError {
    /// The validation errors.
    pub errors: Vec<String>,
}

impl std::fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Schema validation failed: {}", self.errors.join("; "))
    }
}

impl std::error::Error for SchemaValidationError {}

/// Load and compile the ConfigFile JSON schema.
///
/// The schema is loaded from the schemas/ directory at the workspace root.
pub fn load_config_schema() -> JSONSchema {
    let schema_str = include_str!("../../../schemas/diffguard.config.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(schema_str).expect("Config schema should be valid JSON");
    JSONSchema::compile(&schema).expect("Config schema should compile")
}

/// Load and compile the CheckReceipt JSON schema.
///
/// The schema is loaded from the schemas/ directory at the workspace root.
pub fn load_check_schema() -> JSONSchema {
    let schema_str = include_str!("../../../schemas/diffguard.check.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(schema_str).expect("Check schema should be valid JSON");
    JSONSchema::compile(&schema).expect("Check schema should compile")
}

/// Validate a ConfigFile against its JSON schema.
///
/// # Returns
///
/// - `Ok(())` if the config is valid
/// - `Err(SchemaValidationError)` with details if validation fails
pub fn validate_config_file(config: &ConfigFile) -> Result<(), SchemaValidationError> {
    let schema = load_config_schema();
    let json_value = serde_json::to_value(config).expect("ConfigFile should serialize to JSON");

    validate_with_schema(&schema, &json_value)
}

/// Validate a CheckReceipt against its JSON schema.
///
/// # Returns
///
/// - `Ok(())` if the receipt is valid
/// - `Err(SchemaValidationError)` with details if validation fails
pub fn validate_check_receipt(receipt: &CheckReceipt) -> Result<(), SchemaValidationError> {
    let schema = load_check_schema();
    let json_value = serde_json::to_value(receipt).expect("CheckReceipt should serialize to JSON");

    validate_with_schema(&schema, &json_value)
}

/// Validate any JSON value against the ConfigFile schema.
pub fn validate_config_json(json: &serde_json::Value) -> Result<(), SchemaValidationError> {
    let schema = load_config_schema();
    validate_with_schema(&schema, json)
}

/// Validate any JSON value against the CheckReceipt schema.
pub fn validate_check_json(json: &serde_json::Value) -> Result<(), SchemaValidationError> {
    let schema = load_check_schema();
    validate_with_schema(&schema, json)
}

/// Internal helper to validate JSON against a schema.
fn validate_with_schema(
    schema: &JSONSchema,
    json: &serde_json::Value,
) -> Result<(), SchemaValidationError> {
    let validation_result = schema.validate(json);
    match validation_result {
        Ok(_) => Ok(()),
        Err(errors) => {
            // Collect errors - we consume the iterator
            let error_strings: Vec<String> = errors.map(|e| e.to_string()).collect();
            Err(SchemaValidationError {
                errors: error_strings,
            })
        }
    }
}

/// Check if a string is in snake_case format.
///
/// Snake case rules:
/// - Only lowercase letters, digits, and underscores
/// - Must not start or end with underscore
/// - No consecutive underscores
pub fn is_snake_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    if s.starts_with('_') || s.ends_with('_') {
        return false;
    }

    if s.contains("__") {
        return false;
    }

    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Recursively collect all field names from a JSON value.
pub fn collect_field_names(value: &serde_json::Value) -> Vec<String> {
    let mut names = Vec::new();
    collect_field_names_recursive(value, &mut names);
    names
}

fn collect_field_names_recursive(value: &serde_json::Value, names: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                names.push(key.clone());
                collect_field_names_recursive(val, names);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_field_names_recursive(item, names);
            }
        }
        _ => {}
    }
}

/// Verify all field names in a JSON value are snake_case.
///
/// # Returns
///
/// - `Ok(())` if all field names are snake_case
/// - `Err(Vec<String>)` with the non-snake_case field names
///
/// # Errors
///
/// Returns `Err(Vec<String>)` if any field name in the JSON value is not
/// valid snake_case. The returned vector contains the offending field names.
pub fn verify_snake_case_fields(value: &serde_json::Value) -> Result<(), Vec<String>> {
    let field_names = collect_field_names(value);

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

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CHECK_SCHEMA_V1, Defaults, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
        VerdictCounts, VerdictStatus,
    };
    use std::error::Error;

    #[test]
    fn validates_built_in_config() {
        let config = ConfigFile::built_in();
        assert!(
            validate_config_file(&config).is_ok(),
            "Built-in config should validate against schema"
        );
    }

    #[test]
    fn validates_empty_config() {
        let config = ConfigFile {
            includes: vec![],
            defaults: Defaults::default(),
            rule: vec![],
        };
        assert!(
            validate_config_file(&config).is_ok(),
            "Empty config should validate against schema"
        );
    }

    #[test]
    fn validates_minimal_check_receipt() {
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
            timing: None,
        };

        assert!(
            validate_check_receipt(&receipt).is_ok(),
            "Minimal check receipt should validate against schema"
        );
    }

    #[test]
    fn validates_check_receipt_with_findings() {
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
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "Avoid unwrap".to_string(),
                path: "src/main.rs".to_string(),
                line: 42,
                column: Some(10),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = foo.unwrap();".to_string(),
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

        assert!(
            validate_check_receipt(&receipt).is_ok(),
            "Check receipt with findings should validate against schema"
        );
    }

    #[test]
    fn is_snake_case_accepts_valid() {
        assert!(is_snake_case("hello"));
        assert!(is_snake_case("hello_world"));
        assert!(is_snake_case("rule_id"));
        assert!(is_snake_case("fail_on"));
        assert!(is_snake_case("a1"));
        assert!(is_snake_case("test123"));
    }

    #[test]
    fn is_snake_case_rejects_invalid() {
        assert!(!is_snake_case("")); // empty
        assert!(!is_snake_case("_hello")); // starts with underscore
        assert!(!is_snake_case("hello_")); // ends with underscore
        assert!(!is_snake_case("hello__world")); // consecutive underscores
        assert!(!is_snake_case("Hello")); // uppercase
        assert!(!is_snake_case("helloWorld")); // camelCase
        assert!(!is_snake_case("hello-world")); // kebab-case
    }

    #[test]
    fn verify_snake_case_config() {
        let config = ConfigFile::built_in();
        let json = serde_json::to_value(&config).unwrap();
        assert!(
            verify_snake_case_fields(&json).is_ok(),
            "All ConfigFile field names should be snake_case"
        );
    }

    #[test]
    fn collect_field_names_basic() {
        let json = serde_json::json!({
            "foo": 1,
            "bar": {
                "baz": 2
            }
        });

        let names = collect_field_names(&json);
        assert!(names.contains(&"foo".to_string()));
        assert!(names.contains(&"bar".to_string()));
        assert!(names.contains(&"baz".to_string()));
    }

    #[test]
    fn validate_config_and_check_json_helpers() {
        let config = ConfigFile::built_in();
        let config_json = serde_json::to_value(&config).expect("serialize config");
        assert!(validate_config_json(&config_json).is_ok());

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
            timing: None,
        };
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        assert!(validate_check_json(&receipt_json).is_ok());
    }

    #[test]
    fn validate_with_schema_reports_errors() {
        let bad = serde_json::json!({ "rule": [ { "id": "bad.rule" } ] });
        let err = validate_config_json(&bad).expect_err("expected schema error");
        assert!(err.to_string().contains("Schema validation failed"));
    }

    #[test]
    fn verify_snake_case_fields_reports_errors() {
        let json = serde_json::json!({ "camelCase": 1, "snake_case": 2 });
        let err = verify_snake_case_fields(&json).expect_err("expected snake_case failure");
        assert!(err.iter().any(|name| name == "camelCase"));
    }

    #[test]
    fn verify_snake_case_empty_object_passes() {
        // Empty object has no fields, so it trivially passes
        let json = serde_json::json!({});
        assert!(
            verify_snake_case_fields(&json).is_ok(),
            "Empty object should have no field names to violate snake_case"
        );
    }

    #[test]
    fn verify_snake_case_deeply_nested_reports_all_errors() {
        // Field names from all nesting levels should be collected
        let json = serde_json::json!({
            "top_level": {
                "middle_level": {
                    "camelCaseField": "deep"
                }
            }
        });
        let err = verify_snake_case_fields(&json).expect_err("expected snake_case failure");
        assert!(
            err.iter().any(|name| name == "camelCaseField"),
            "Should catch camelCaseField from deeply nested object"
        );
    }

    #[test]
    fn verify_snake_case_array_elements_collected() {
        // Field names should be collected from objects inside arrays
        let json = serde_json::json!({
            "items": [
                { "itemName": "first" },
                { "itemName": "second" }
            ]
        });
        let err = verify_snake_case_fields(&json).expect_err("expected snake_case failure");
        assert!(
            err.iter().any(|name| name == "itemName"),
            "Should catch itemName from array element objects"
        );
    }

    #[test]
    fn verify_snake_case_multiple_errors_all_reported() {
        // All non-snake_case field names should be in the error vector
        let json = serde_json::json!({
            "camelCase1": 1,
            "camelCase2": 2,
            "alsoCamel": 3
        });
        let err = verify_snake_case_fields(&json).expect_err("expected snake_case failure");
        assert_eq!(err.len(), 3, "Should report all 3 non-snake_case fields");
        assert!(err.contains(&"camelCase1".to_string()));
        assert!(err.contains(&"camelCase2".to_string()));
        assert!(err.contains(&"alsoCamel".to_string()));
    }

    #[test]
    fn verify_snake_case_numbers_only_field_passes() {
        // Numbers-only field names are valid snake_case
        let json = serde_json::json!({ "123": "value" });
        assert!(
            verify_snake_case_fields(&json).is_ok(),
            "Numbers-only field name should be valid snake_case"
        );
    }

    #[test]
    fn verify_snake_case_field_with_embedded_numbers_passes() {
        // Fields with embedded numbers are valid snake_case
        let json = serde_json::json!({
            "field_1": 1,
            "rule_2_name": "test"
        });
        assert!(
            verify_snake_case_fields(&json).is_ok(),
            "Fields with embedded numbers should be valid snake_case"
        );
    }

    #[test]
    fn verify_snake_case_starts_with_digit_passes() {
        // Fields starting with a digit are valid snake_case
        // (is_snake_case only checks for lowercase/digit/underscore)
        let json = serde_json::json!({ "1_field": "value" });
        assert!(
            verify_snake_case_fields(&json).is_ok(),
            "Field starting with digit should be valid snake_case"
        );
    }

    // =============================================================================
    // Error source() chain propagation tests (AC4)
    // =============================================================================

    #[test]
    fn source_returns_none() {
        // AC4: SchemaValidationError::source() should return None
        // because validation errors are collected as Vec<String>, not chained
        let error = SchemaValidationError {
            errors: vec!["field 'id' is required".into()],
        };
        assert!(
            error.source().is_none(),
            "source() should return None for SchemaValidationError"
        );
    }
}
