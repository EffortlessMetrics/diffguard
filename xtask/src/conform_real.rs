// Conformance tests for Cockpit ecosystem integration.
//
// These tests validate that diffguard produces valid `sensor.report.v1` output
// that conforms to the Cockpit contract.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

/// Run all conformance tests.
pub fn run_conformance(quick: bool) -> Result<()> {
    println!("Running diffguard conformance tests...\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Schema validation (serde round-trip)
    print!("  [1/15] Schema validation (serde)... ");
    match test_schema_validation() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 2: Determinism (skip if quick mode)
    if quick {
        println!("  [2/15] Determinism... SKIP (quick mode)");
    } else {
        print!("  [2/15] Determinism... ");
        match test_determinism() {
            Ok(()) => {
                println!("PASS");
                passed += 1;
            }
            Err(e) => {
                println!("FAIL: {e}");
                failed += 1;
            }
        }
    }

    // Test 3: Survivability (cockpit mode with bad input)
    print!("  [3/15] Survivability... ");
    match test_survivability() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 4: Required fields
    print!("  [4/15] Required fields... ");
    match test_required_fields() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 5: Vocabulary compliance
    print!("  [5/15] Vocabulary compliance... ");
    match test_vocabulary() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 6: JSON schema file validation
    print!("  [6/15] JSON schema file validation... ");
    match test_json_schema_file() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 7: Schema drift detection
    print!("  [7/15] Schema drift detection... ");
    match test_schema_drift() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 8: Vocabulary constants
    print!("  [8/15] Vocabulary constants... ");
    match test_vocabulary_constants() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 9: Tool error code in sensor report
    print!("  [9/15] Tool error code field... ");
    match test_tool_error_code() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 10: Token lint (all tokens match ^[a-z][a-z0-9_.]*$)
    print!("  [10/15] Token lint... ");
    match test_token_lint() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 11: Path hygiene (forward slashes, repo-relative, no traversal)
    print!("  [11/15] Path hygiene... ");
    match test_path_hygiene() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 12: Fingerprint format (64 lowercase hex chars)
    print!("  [12/15] Fingerprint format... ");
    match test_fingerprint_format() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 13: Artifact path hygiene (forward slashes, no absolute, no traversal)
    print!("  [13/15] Artifact path hygiene... ");
    match test_artifact_path_hygiene() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 14: Cockpit output layout
    print!("  [14/15] Cockpit output layout... ");
    match test_cockpit_output_layout() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    // Test 15: data.diffguard shape validation
    print!("  [15/15] data.diffguard shape... ");
    match test_data_diffguard_shape() {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL: {e}");
            failed += 1;
        }
    }

    println!();
    let total = if quick { 14 } else { 15 };
    println!("Results: {passed}/{total} tests passed");

    if failed > 0 {
        bail!("{failed} conformance test(s) failed");
    }

    Ok(())
}

/// Test that sensor report output validates against the schema.
fn test_schema_validation() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    // Run diffguard with sensor output
    let _output = run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    if !sensor_path.exists() {
        bail!("sensor.json not created");
    }

    // Read and parse the sensor report
    let sensor_json = std::fs::read_to_string(&sensor_path).context("read sensor.json")?;
    let sensor_value: serde_json::Value =
        serde_json::from_str(&sensor_json).context("parse sensor.json")?;

    // Validate the parsed report can be deserialized to SensorReport
    let _: diffguard_types::SensorReport =
        serde_json::from_value(sensor_value.clone()).context("deserialize as SensorReport")?;

    // Verify schema field
    let schema_field = sensor_value
        .get("schema")
        .and_then(|s| s.as_str())
        .context("get schema field")?;

    if schema_field != "sensor.report.v1" {
        bail!(
            "invalid schema field: expected 'sensor.report.v1', got '{}'",
            schema_field
        );
    }

    Ok(())
}

/// Test that multiple runs produce identical output.
fn test_determinism() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let mut outputs: Vec<String> = Vec::new();

    for i in 0..5 {
        let sensor_path = temp_dir.path().join(format!("sensor_{i}.json"));
        let out_path = temp_dir.path().join(format!("report_{i}.json"));

        run_diffguard(
            temp_dir.path(),
            &[
                "check",
                "--base",
                "HEAD~1",
                "--head",
                "HEAD",
                "--out",
                out_path.to_str().unwrap(),
                "--sensor",
                sensor_path.to_str().unwrap(),
            ],
        )?;

        if !sensor_path.exists() {
            bail!("sensor_{i}.json not created");
        }

        // Read and normalize the output (remove timing fields which will vary)
        let content = std::fs::read_to_string(&sensor_path)?;
        let mut value: serde_json::Value = serde_json::from_str(&content)?;

        // Remove timing-dependent fields for comparison
        if let Some(run) = value.get_mut("run") {
            if let Some(o) = run.as_object_mut() {
                o.remove("started_at");
                o.remove("ended_at");
                o.remove("duration_ms");
            }
        }

        // Remove artifacts array (paths differ per run due to unique filenames)
        value.as_object_mut().map(|o| o.remove("artifacts"));

        outputs.push(serde_json::to_string_pretty(&value)?);
    }

    // All outputs should be identical
    let first = &outputs[0];
    for (i, output) in outputs.iter().enumerate().skip(1) {
        if output != first {
            bail!("Run {i} produced different output than run 0");
        }
    }

    Ok(())
}

/// Test that cockpit mode produces a valid receipt even with bad input.
fn test_survivability() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;

    // Create minimal git repo without proper history
    setup_minimal_repo(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    // Run diffguard in cockpit mode with a nonexistent base ref
    let output = Command::new(cargo_bin_path())
        .args([
            "check",
            "--mode",
            "cockpit",
            "--base",
            "nonexistent-ref",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ])
        .current_dir(temp_dir.path())
        .output()
        .context("run diffguard")?;

    // In cockpit mode, should exit 0 if any receipt was written
    if !output.status.success() && output.status.code() != Some(0) {
        // Check if we at least got a receipt
        if !out_path.exists() && !sensor_path.exists() {
            bail!(
                "cockpit mode did not exit 0 and no receipt was written: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // At least one receipt should exist
    if !out_path.exists() && !sensor_path.exists() {
        bail!("no receipt was written in cockpit mode with bad input");
    }

    // If sensor report exists, it should have skip status
    if sensor_path.exists() {
        let content = std::fs::read_to_string(&sensor_path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;

        let status = value
            .get("verdict")
            .and_then(|v| v.get("status"))
            .and_then(|s| s.as_str());

        if status != Some("skip") {
            bail!("expected verdict.status to be 'skip', got {:?}", status);
        }
    }

    Ok(())
}

/// Test that all required fields are present in the output.
fn test_required_fields() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    // Check required top-level fields
    let required_fields = ["schema", "tool", "run", "verdict", "findings"];
    for field in required_fields {
        if value.get(field).is_none() {
            bail!("missing required field: {field}");
        }
    }

    // Check tool fields
    let tool = value.get("tool").unwrap();
    if tool.get("name").is_none() || tool.get("version").is_none() {
        bail!("missing required tool fields (name, version)");
    }

    // Check run fields
    let run = value.get("run").unwrap();
    let run_fields = ["started_at", "ended_at", "duration_ms"];
    for field in run_fields {
        if run.get(field).is_none() {
            bail!("missing required run field: {field}");
        }
    }

    // Check verdict fields
    let verdict = value.get("verdict").unwrap();
    if verdict.get("status").is_none() || verdict.get("counts").is_none() {
        bail!("missing required verdict fields (status, counts)");
    }

    // If there are findings, check their fields
    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for (i, finding) in findings.iter().enumerate() {
            let finding_fields = [
                "check_id",
                "code",
                "severity",
                "message",
                "location",
                "fingerprint",
            ];
            for field in finding_fields {
                if finding.get(field).is_none() {
                    bail!("missing required finding field at index {i}: {field}");
                }
            }

            // Check location fields
            let location = finding.get("location").unwrap();
            if location.get("path").is_none() || location.get("line").is_none() {
                bail!("missing required location fields at finding {i}");
            }
        }
    }

    Ok(())
}

/// Test that severities and statuses use the frozen vocabulary.
fn test_vocabulary() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    // Check verdict status vocabulary
    let valid_statuses = ["pass", "warn", "fail", "skip"];
    let status = value
        .get("verdict")
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_str())
        .context("get verdict.status")?;

    if !valid_statuses.contains(&status) {
        bail!(
            "invalid verdict.status '{}', must be one of: {:?}",
            status,
            valid_statuses
        );
    }

    // Check finding severities
    let valid_severities = ["info", "warn", "error"];
    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for (i, finding) in findings.iter().enumerate() {
            let severity = finding
                .get("severity")
                .and_then(|s| s.as_str())
                .context(format!("get findings[{i}].severity"))?;

            if !valid_severities.contains(&severity) {
                bail!(
                    "invalid severity '{}' at findings[{}], must be one of: {:?}",
                    severity,
                    i,
                    valid_severities
                );
            }
        }
    }

    // Check capability statuses if present
    if let Some(capabilities) = value
        .get("run")
        .and_then(|r| r.get("capabilities"))
        .and_then(|c| c.as_object())
    {
        let valid_cap_statuses = ["available", "unavailable", "skipped"];
        for (name, cap) in capabilities {
            let status = cap
                .get("status")
                .and_then(|s| s.as_str())
                .context(format!("get capabilities.{name}.status"))?;

            if !valid_cap_statuses.contains(&status) {
                bail!(
                    "invalid capability status '{}' for '{}', must be one of: {:?}",
                    status,
                    name,
                    valid_cap_statuses
                );
            }
        }
    }

    Ok(())
}

/// Test that the sensor report output validates against the shipped JSON schema file.
fn test_json_schema_file() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    // Run diffguard with sensor output
    let _output = run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    if !sensor_path.exists() {
        bail!("sensor.json not created");
    }

    // Load the vendored contract schema (fleet anchor)
    let schema_path = workspace_root()
        .join("contracts")
        .join("schemas")
        .join("sensor.report.v1.schema.json");

    if !schema_path.exists() {
        bail!(
            "contract schema file not found at {}. Ensure contracts/schemas/ is committed.",
            schema_path.display()
        );
    }

    let schema_text = std::fs::read_to_string(&schema_path).context("read schema file")?;
    let schema_value: serde_json::Value =
        serde_json::from_str(&schema_text).context("parse schema file")?;

    let compiled_schema =
        jsonschema::JSONSchema::compile(&schema_value).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Validate the sensor report output against the schema
    let sensor_json = std::fs::read_to_string(&sensor_path).context("read sensor.json")?;
    let sensor_value: serde_json::Value =
        serde_json::from_str(&sensor_json).context("parse sensor.json")?;

    let result = compiled_schema.validate(&sensor_value);
    if let Err(errors) = result {
        let error_messages: Vec<String> = errors
            .map(|e| format!("  - {e} at {}", e.instance_path))
            .collect();
        bail!(
            "sensor report failed schema validation:\n{}",
            error_messages.join("\n")
        );
    }

    Ok(())
}

/// Test that the generated schema has not drifted from the vendored contract.
fn test_schema_drift() -> Result<()> {
    let generated_path = workspace_root()
        .join("schemas")
        .join("sensor.report.v1.schema.json");
    let contract_path = workspace_root()
        .join("contracts")
        .join("schemas")
        .join("sensor.report.v1.schema.json");

    if !generated_path.exists() {
        bail!(
            "generated schema not found at {}. Run `cargo run -p xtask -- schema` first.",
            generated_path.display()
        );
    }
    if !contract_path.exists() {
        bail!(
            "contract schema not found at {}. Ensure contracts/schemas/ is committed.",
            contract_path.display()
        );
    }

    let generated_text =
        std::fs::read_to_string(&generated_path).context("read generated schema")?;
    let contract_text = std::fs::read_to_string(&contract_path).context("read contract schema")?;

    let generated_value: serde_json::Value =
        serde_json::from_str(&generated_text).context("parse generated schema")?;
    let contract_value: serde_json::Value =
        serde_json::from_str(&contract_text).context("parse contract schema")?;

    let generated_canonical = canonicalize_json(&generated_value);
    let contract_canonical = canonicalize_json(&contract_value);

    if generated_canonical != contract_canonical {
        // Find first divergence line for diagnostics
        let first_diff = generated_canonical
            .lines()
            .zip(contract_canonical.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| {
                format!(
                    "first divergence at line {}:\n  generated: {}\n  contract:  {}",
                    i + 1,
                    a,
                    b
                )
            })
            .unwrap_or_else(|| "files differ in length".to_string());

        bail!(
            "schema drift detected!\n\
             Generated: schemas/sensor.report.v1.schema.json\n\
             Contract:  contracts/schemas/sensor.report.v1.schema.json\n\n\
             {first_diff}\n\n\
             If the schema change is intentional, update the contract:\n\
             cp schemas/sensor.report.v1.schema.json contracts/schemas/sensor.report.v1.schema.json"
        );
    }

    Ok(())
}

/// Re-serializes a JSON Value to a canonical pretty-printed string.
/// `serde_json::to_string_pretty` uses sorted keys when the Value is
/// backed by a BTreeMap (the default), providing stable ordering.
fn canonicalize_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).expect("re-serialize json")
}

/// Test that frozen vocabulary constants have the expected values.
fn test_vocabulary_constants() -> Result<()> {
    use diffguard_types::{
        CAP_GIT, CAP_STATUS_AVAILABLE, CAP_STATUS_SKIPPED, CAP_STATUS_UNAVAILABLE,
        CHECK_ID_INTERNAL, CHECK_ID_PATTERN, CHECK_SCHEMA_V1, CODE_TOOL_RUNTIME_ERROR,
        REASON_GIT_UNAVAILABLE, REASON_HAS_ERROR, REASON_HAS_WARNING, REASON_MISSING_BASE,
        REASON_NO_DIFF_INPUT, REASON_TOOL_ERROR, REASON_TRUNCATED, SENSOR_REPORT_SCHEMA_V1,
    };

    // Schema identifiers
    assert_eq!(CHECK_SCHEMA_V1, "diffguard.check.v1");
    assert_eq!(SENSOR_REPORT_SCHEMA_V1, "sensor.report.v1");

    // Check IDs
    assert_eq!(CHECK_ID_PATTERN, "diffguard.pattern");
    assert_eq!(CHECK_ID_INTERNAL, "diffguard.internal");

    // Reason tokens
    assert_eq!(REASON_NO_DIFF_INPUT, "no_diff_input");
    assert_eq!(REASON_MISSING_BASE, "missing_base");
    assert_eq!(REASON_GIT_UNAVAILABLE, "git_unavailable");
    assert_eq!(REASON_TOOL_ERROR, "tool_error");
    assert_eq!(REASON_HAS_ERROR, "has_error");
    assert_eq!(REASON_HAS_WARNING, "has_warning");
    assert_eq!(REASON_TRUNCATED, "truncated");

    // Tool error code (R1 survivability)
    assert_eq!(CODE_TOOL_RUNTIME_ERROR, "tool.runtime_error");

    // Capability names and statuses
    assert_eq!(CAP_GIT, "git");
    assert_eq!(CAP_STATUS_AVAILABLE, "available");
    assert_eq!(CAP_STATUS_UNAVAILABLE, "unavailable");
    assert_eq!(CAP_STATUS_SKIPPED, "skipped");

    Ok(())
}

/// Test that cockpit-mode tool errors produce the correct code field.
fn test_tool_error_code() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_minimal_repo(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    // Run in cockpit mode with a nonexistent base ref to trigger tool error
    let output = Command::new(cargo_bin_path())
        .args([
            "check",
            "--mode",
            "cockpit",
            "--base",
            "nonexistent-ref",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ])
        .current_dir(temp_dir.path())
        .output()
        .context("run diffguard")?;

    // In cockpit mode, should exit 0
    if !output.status.success() {
        bail!(
            "cockpit mode did not exit 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // If sensor report exists, verify the code field for tool errors
    if sensor_path.exists() {
        let content = std::fs::read_to_string(&sensor_path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;

        let status = value
            .get("verdict")
            .and_then(|v| v.get("status"))
            .and_then(|s| s.as_str());

        // If it's a skip status, the code field won't be present (no findings)
        // If it's a fail status (tool_error), check the code field
        if status == Some("fail") {
            if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
                for finding in findings {
                    if let Some(code) = finding.get("code").and_then(|c| c.as_str()) {
                        if code != "tool.runtime_error" {
                            bail!(
                                "expected tool error code 'tool.runtime_error', got '{}'",
                                code
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Test that all tokens (check_id, code, reasons, capability keys) match the
/// cockpit token format: `^[a-z][a-z0-9_.]*$`.
fn test_token_lint() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    let token_re = regex::Regex::new(r"^[a-z][a-z0-9_.]*$").expect("token regex");

    // Validate check_id and code on each finding
    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for (i, finding) in findings.iter().enumerate() {
            if let Some(check_id) = finding.get("check_id").and_then(|v| v.as_str()) {
                if !token_re.is_match(check_id) {
                    bail!(
                        "findings[{i}].check_id '{}' does not match token format",
                        check_id
                    );
                }
            }
            if let Some(code) = finding.get("code").and_then(|v| v.as_str()) {
                if !token_re.is_match(code) {
                    bail!("findings[{i}].code '{}' does not match token format", code);
                }
            }
        }
    }

    // Validate verdict.reasons
    if let Some(reasons) = value
        .get("verdict")
        .and_then(|v| v.get("reasons"))
        .and_then(|r| r.as_array())
    {
        for (i, reason) in reasons.iter().enumerate() {
            if let Some(r) = reason.as_str() {
                if !token_re.is_match(r) {
                    bail!("verdict.reasons[{i}] '{}' does not match token format", r);
                }
            }
        }
    }

    // Validate capability keys
    if let Some(capabilities) = value
        .get("run")
        .and_then(|r| r.get("capabilities"))
        .and_then(|c| c.as_object())
    {
        for name in capabilities.keys() {
            if !token_re.is_match(name) {
                bail!("capabilities key '{}' does not match token format", name);
            }
        }
    }

    // Validate verdict.status is in frozen enum
    let valid_statuses = ["pass", "warn", "fail", "skip"];
    if let Some(status) = value
        .get("verdict")
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_str())
    {
        if !valid_statuses.contains(&status) {
            bail!("verdict.status '{}' not in frozen enum", status);
        }
    }

    // Validate severity values in frozen enum
    let valid_severities = ["info", "warn", "error"];
    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for (i, finding) in findings.iter().enumerate() {
            if let Some(sev) = finding.get("severity").and_then(|s| s.as_str()) {
                if !valid_severities.contains(&sev) {
                    bail!("findings[{i}].severity '{}' not in frozen enum", sev);
                }
            }
        }
    }

    Ok(())
}

/// Test that finding `location.path` values use forward slashes, are repo-relative,
/// and don't contain absolute paths or traversals.
fn test_path_hygiene() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        for (i, finding) in findings.iter().enumerate() {
            if let Some(path) = finding
                .get("location")
                .and_then(|l| l.get("path"))
                .and_then(|p| p.as_str())
            {
                // Skip empty paths (e.g., tool error findings)
                if path.is_empty() {
                    continue;
                }

                if path.contains('\\') {
                    bail!(
                        "findings[{i}].location.path '{}' contains backslashes",
                        path
                    );
                }
                if path.starts_with('/') {
                    bail!("findings[{i}].location.path '{}' is an absolute path", path);
                }
                // Check for Windows drive letters (e.g., C:)
                if path.len() >= 2
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && path.as_bytes()[1] == b':'
                {
                    bail!(
                        "findings[{i}].location.path '{}' contains a drive letter",
                        path
                    );
                }
                if path.contains("..") {
                    bail!(
                        "findings[{i}].location.path '{}' contains traversal '..'",
                        path
                    );
                }
            }
        }
    }

    Ok(())
}

/// Test that all fingerprints are exactly 64 lowercase hex characters.
fn test_fingerprint_format() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    let fingerprint_re = regex::Regex::new(r"^[0-9a-f]{64}$").expect("fingerprint regex");

    if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
        if findings.is_empty() {
            bail!("no findings to validate fingerprints against");
        }
        for (i, finding) in findings.iter().enumerate() {
            let fingerprint = finding
                .get("fingerprint")
                .and_then(|f| f.as_str())
                .context(format!("findings[{i}].fingerprint missing"))?;

            if !fingerprint_re.is_match(fingerprint) {
                bail!(
                    "findings[{i}].fingerprint '{}' does not match ^[0-9a-f]{{64}}$",
                    fingerprint
                );
            }
        }
    } else {
        bail!("no findings array in sensor report");
    }

    Ok(())
}

/// Test that all `artifacts[].path` values use forward slashes.
fn test_artifact_path_hygiene() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(artifacts) = value.get("artifacts").and_then(|a| a.as_array()) {
        for (i, artifact) in artifacts.iter().enumerate() {
            if let Some(path) = artifact.get("path").and_then(|p| p.as_str()) {
                if path.contains('\\') {
                    bail!("artifacts[{i}].path '{}' contains backslashes", path);
                }
                if path.starts_with('/') {
                    bail!("artifacts[{i}].path '{}' is an absolute path", path);
                }
                if path.len() >= 2
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && path.as_bytes()[1] == b':'
                {
                    bail!("artifacts[{i}].path '{}' contains a drive letter", path);
                }
                if path.contains("..") {
                    bail!("artifacts[{i}].path '{}' contains traversal '..'", path);
                }
            }
        }
    }

    Ok(())
}

/// Test that cockpit mode produces the expected output layout.
fn test_cockpit_output_layout() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let artifacts_dir = temp_dir.path().join("artifacts").join("diffguard");

    // Find the binary in target/debug (already built by earlier tests)
    let binary = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "diffguard.exe"
        } else {
            "diffguard"
        });

    // Run diffguard in cockpit mode with all output flags
    let output = Command::new(&binary)
        .args([
            "check", "--mode", "cockpit", "--base", "HEAD~1", "--head", "HEAD", "--sensor", "--md",
            "--sarif", "--junit", "--csv", "--tsv",
        ])
        .current_dir(temp_dir.path())
        .output()
        .context("run diffguard")?;

    if !output.status.success() {
        bail!(
            "cockpit mode did not exit 0: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // 1. Validate top-level artifacts/diffguard/ has only: report.json, comment.md, extras/
    let mut top_entries: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&artifacts_dir).context("read artifacts/diffguard/")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        top_entries.push(name);
    }
    top_entries.sort();

    let expected_top = vec!["comment.md", "extras", "report.json"];
    if top_entries != expected_top {
        bail!(
            "unexpected top-level layout: got {:?}, expected {:?}",
            top_entries,
            expected_top
        );
    }

    // 2. Validate extras/ has the expected files
    let extras_dir = artifacts_dir.join("extras");
    let mut extras_entries: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&extras_dir).context("read extras/")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        extras_entries.push(name);
    }
    extras_entries.sort();

    let expected_extras = vec![
        "check.json",
        "report.csv",
        "report.sarif.json",
        "report.tsv",
        "report.xml",
    ];
    if extras_entries != expected_extras {
        bail!(
            "unexpected extras layout: got {:?}, expected {:?}",
            extras_entries,
            expected_extras
        );
    }

    // 3. Validate artifacts[] in sensor report has entries for all produced files
    let sensor_json =
        std::fs::read_to_string(artifacts_dir.join("report.json")).context("read report.json")?;
    let sensor_value: serde_json::Value =
        serde_json::from_str(&sensor_json).context("parse report.json")?;

    let artifacts = sensor_value
        .get("artifacts")
        .and_then(|a| a.as_array())
        .context("get artifacts array")?;

    // Should have 7 entries: check.json, comment.md, sarif, junit, csv, tsv, report.json (sensor)
    if artifacts.len() != 7 {
        let paths: Vec<&str> = artifacts
            .iter()
            .filter_map(|a| a.get("path").and_then(|p| p.as_str()))
            .collect();
        bail!("expected 7 artifacts, got {}: {:?}", artifacts.len(), paths);
    }

    // 4. All artifact paths pass full hygiene
    for (i, artifact) in artifacts.iter().enumerate() {
        if let Some(path) = artifact.get("path").and_then(|p| p.as_str()) {
            if path.contains('\\') {
                bail!("artifacts[{i}].path '{}' contains backslashes", path);
            }
            if path.starts_with('/') {
                bail!("artifacts[{i}].path '{}' is an absolute path", path);
            }
            if path.len() >= 2
                && path.as_bytes()[0].is_ascii_alphabetic()
                && path.as_bytes()[1] == b':'
            {
                bail!("artifacts[{i}].path '{}' contains a drive letter", path);
            }
            if path.contains("..") {
                bail!("artifacts[{i}].path '{}' contains traversal '..'", path);
            }
        }
    }

    Ok(())
}

/// Test that the `data.diffguard` object has the expected shape and types.
fn test_data_diffguard_shape() -> Result<()> {
    let temp_dir = TempDir::new().context("create temp dir")?;
    setup_test_repo_with_finding(temp_dir.path())?;

    let sensor_path = temp_dir.path().join("sensor.json");
    let out_path = temp_dir.path().join("report.json");

    run_diffguard(
        temp_dir.path(),
        &[
            "check",
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            out_path.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    )?;

    let content = std::fs::read_to_string(&sensor_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    // data.diffguard must exist and be an object
    let diffguard = value
        .get("data")
        .and_then(|d| d.get("diffguard"))
        .and_then(|dg| dg.as_object())
        .context("data.diffguard must be an object")?;

    // Required numeric keys: all non-negative integers
    let required_keys = [
        "suppressed_count",
        "truncated_count",
        "rules_matched",
        "rules_total",
    ];
    for key in required_keys {
        let val = diffguard
            .get(key)
            .context(format!("data.diffguard.{key} is missing"))?;
        let n = val.as_u64().context(format!(
            "data.diffguard.{key} must be a non-negative integer"
        ))?;
        // Just access n to avoid unused variable warning
        let _ = n;
    }

    // If tags_matched is present, validate its shape
    if let Some(tags_matched) = diffguard.get("tags_matched") {
        let obj = tags_matched
            .as_object()
            .context("data.diffguard.tags_matched must be an object")?;
        for (key, val) in obj {
            val.as_u64().context(format!(
                "data.diffguard.tags_matched[\"{key}\"] must be a non-negative integer"
            ))?;
        }

        // Since our test fixture has tags = ["test"], tags_matched should be non-empty
        if obj.is_empty() {
            bail!("data.diffguard.tags_matched is present but empty (expected positive coverage)");
        }
    } else {
        // With our test fixture having tags, tags_matched should be present
        bail!("data.diffguard.tags_matched is missing (expected with tagged rule findings)");
    }

    Ok(())
}

// Helper functions

/// Get the path to the diffguard binary.
fn cargo_bin_path() -> String {
    // Use cargo to find the binary
    std::env::var("CARGO_BIN_EXE_diffguard").unwrap_or_else(|_| "diffguard".to_string())
}

/// Run diffguard with the given arguments.
fn run_diffguard(dir: &Path, args: &[&str]) -> Result<Output> {
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_diffguard") {
        let output = Command::new(bin)
            .args(args)
            .current_dir(dir)
            .output()
            .context("run diffguard")?;
        return Ok(output);
    }

    ensure_diffguard_built()?;

    // Find the binary in target/debug
    let binary = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "diffguard.exe"
        } else {
            "diffguard"
        });

    let output = Command::new(&binary)
        .args(args)
        .current_dir(dir)
        .output()
        .context("run diffguard")?;

    Ok(output)
}

fn ensure_diffguard_built() -> Result<()> {
    static BUILD_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

    let result = BUILD_RESULT.get_or_init(|| {
        let status = Command::new("cargo")
            .args(["build", "-p", "diffguard"])
            .status()
            .map_err(|e| format!("build diffguard: {e}"))?;
        if !status.success() {
            return Err("failed to build diffguard".to_string());
        }
        Ok(())
    });

    match result {
        Ok(()) => Ok(()),
        Err(msg) => bail!("{msg}"),
    }
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

/// Set up a minimal git repo.
fn setup_minimal_repo(dir: &Path) -> Result<()> {
    // Initialize git repo
    Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .output()
        .context("git init")?;

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir)
        .output()
        .context("git config email")?;

    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir)
        .output()
        .context("git config name")?;

    // Create initial file and commit
    std::fs::write(dir.join("README.md"), "# Test\n")?;

    Command::new("git")
        .args(["add", "."])
        .current_dir(dir)
        .output()
        .context("git add")?;

    Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(dir)
        .output()
        .context("git commit")?;

    Ok(())
}

/// Set up a git repo with a change that triggers a finding.
fn setup_test_repo_with_finding(dir: &Path) -> Result<()> {
    setup_minimal_repo(dir)?;

    // Create a diffguard.toml config
    std::fs::write(
        dir.join("diffguard.toml"),
        r#"
[[rule]]
id = "test.match"
severity = "warn"
message = "Test match found"
patterns = ["test_match"]
tags = ["test"]
"#,
    )?;

    // Add file with matching pattern
    std::fs::write(
        dir.join("test.rs"),
        "fn main() {\n    let x = test_match();\n}\n",
    )?;

    Command::new("git")
        .args(["add", "."])
        .current_dir(dir)
        .output()
        .context("git add")?;

    Command::new("git")
        .args(["commit", "-m", "add test file"])
        .current_dir(dir)
        .output()
        .context("git commit")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn cargo_bin_path_prefers_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("CARGO_BIN_EXE_diffguard", "custom-diffguard");
        assert_eq!(cargo_bin_path(), "custom-diffguard");
        std::env::remove_var("CARGO_BIN_EXE_diffguard");
    }

    #[test]
    fn setup_minimal_repo_creates_git_repo() {
        let dir = TempDir::new().expect("temp");
        setup_minimal_repo(dir.path()).expect("setup repo");

        assert!(dir.path().join(".git").exists());
        assert!(dir.path().join("README.md").exists());

        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir.path())
            .output()
            .expect("git rev-parse");
        assert!(output.status.success());
    }

    #[test]
    fn setup_test_repo_with_finding_writes_files() {
        let dir = TempDir::new().expect("temp");
        setup_test_repo_with_finding(dir.path()).expect("setup repo with finding");

        let config_path = dir.path().join("diffguard.toml");
        let source_path = dir.path().join("test.rs");
        assert!(config_path.exists());
        assert!(source_path.exists());

        let config = std::fs::read_to_string(config_path).expect("read config");
        assert!(config.contains("test.match"));
        assert!(config.contains("patterns"));
    }

    #[test]
    fn determinism_test_runs() {
        test_determinism().expect("determinism");
    }
}
