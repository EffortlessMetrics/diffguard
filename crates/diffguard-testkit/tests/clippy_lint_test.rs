//! Behavioral tests verifying the `validate_with_schema` function behavior.
//!
//! These tests verify the behavioral contract of validate_with_schema.
//! The clippy::ignored_unit_patterns fix is verified by the Clippy CI job.
//!
//! The original red test (test_validate_with_schema_uses_idiomatic_unit_pattern)
//! ran `cargo clippy` as a subprocess, which doesn't work reliably in CI environments
//! due to PATH/environment differences. The actual clippy lint check is performed
//! by the Clippy CI job which runs `cargo clippy --workspace --all-targets -- -D warnings`.

#[test]
fn test_validate_with_schema_success_returns_unit() {
    // This test verifies the behavioral contract: validate_with_schema
    // returns Ok(()) on successful validation.
    //
    // This test exists to document the expected behavior and would pass
    // both before and after the fix (since behavior is identical).
    // It's included for completeness of the specification.

    use diffguard_testkit::schema::validate_config_json;
    use serde_json::json;

    let valid_json = json!({
        "rules": [
            {
                "id": "test.rule",
                "severity": "warn",
                "pattern": "test pattern"
            }
        ]
    });

    let result = validate_config_json(&valid_json);

    // The success case returns Ok(()) - behavior is unchanged by the fix
    assert!(
        result.is_ok(),
        "Expected validate_config_json to return Ok(()) for valid JSON, got {:?}",
        result
    );
}

#[test]
fn test_validate_with_schema_error_returns_validation_error() {
    // This test verifies that validation errors are properly reported.
    // Behavior is unchanged by the fix.
    // Using same invalid data pattern as existing test in schema.rs

    use diffguard_testkit::schema::validate_config_json;
    use serde_json::json;

    // Invalid JSON - using "rule" (singular) which doesn't match schema expectation
    let invalid_json = json!({ "rule": [ { "id": "bad.rule" } ] });

    let result = validate_config_json(&invalid_json);

    // The error case returns Err(SchemaValidationError)
    assert!(
        result.is_err(),
        "Expected validate_config_json to return Err for invalid JSON, got {:?}",
        result
    );

    let error = result.unwrap_err();
    assert!(
        error.to_string().contains("Schema validation failed"),
        "Expected error message to contain 'Schema validation failed', got: {}",
        error
    );
}
