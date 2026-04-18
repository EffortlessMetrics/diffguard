//! Red test verifying the `clippy::ignored_unit_patterns` lint is fixed.
//!
//! This test verifies that the `Ok(())` pattern is used instead of `Ok(_)`
//! when matching on `Result<(), E>` in the `validate_with_schema` function.
//!
//! The test runs clippy with the `ignored_unit_patterns` lint enabled and
//! verifies no warnings are produced for line 89 of schema.rs.
//!
//! This test FAILS before the fix (when `Ok(_)` is used) and PASSES after
//! the fix (when `Ok(())` is used).

use std::process::Command;

#[test]
fn test_validate_with_schema_uses_idiomatic_unit_pattern() {
    // Run clippy with the specific lint enabled
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-testkit",
            "--",
            "-W",
            "clippy::ignored_unit_patterns",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}{}", stdout, stderr);

    // The warning we expect to NOT see after the fix:
    // "matching over `()` is more explicit"
    // "use `()` instead of `_`: `()`"
    let has_ignored_unit_patterns_warning = combined_output.contains("ignored_unit_patterns")
        && combined_output.contains("schema.rs:89");

    // Assert NO warning exists - this test FAILS before fix, PASSES after fix
    assert!(
        !has_ignored_unit_patterns_warning,
        "Expected no clippy::ignored_unit_patterns warning at schema.rs:89, but found it.\n\
         The Ok(_) pattern should be replaced with Ok(()).\n\
         Clippy output:\n{}",
        combined_output
    );
}

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
