//! Conformance tests for Cockpit ecosystem integration.
//!
//! These tests validate that diffguard produces valid `sensor.report.v1` output
//! that conforms to the Cockpit contract.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

/// Run all conformance tests.
pub fn run_conformance(quick: bool) -> Result<()> {
    println!("Running diffguard conformance tests...\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Schema validation (serde round-trip)
    print!("  [1/6] Schema validation (serde)... ");
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
        println!("  [2/6] Determinism... SKIP (quick mode)");
    } else {
        print!("  [2/6] Determinism... ");
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
    print!("  [3/6] Survivability... ");
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
    print!("  [4/6] Required fields... ");
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
    print!("  [5/6] Vocabulary compliance... ");
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
    print!("  [6/6] JSON schema file validation... ");
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

    println!();
    let total = if quick { 5 } else { 6 };
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

    // Load the schema file from disk (proving the shipped file is the source of truth)
    let schema_path = std::env::current_dir()?
        .join("schemas")
        .join("sensor.report.v1.schema.json");

    if !schema_path.exists() {
        bail!(
            "schema file not found at {}. Run `cargo run -p xtask -- schema` first.",
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

// Helper functions

/// Get the path to the diffguard binary.
fn cargo_bin_path() -> String {
    // Use cargo to find the binary
    std::env::var("CARGO_BIN_EXE_diffguard").unwrap_or_else(|_| "diffguard".to_string())
}

/// Run diffguard with the given arguments.
fn run_diffguard(dir: &Path, args: &[&str]) -> Result<Output> {
    // Build the binary first to ensure it's up to date
    let status = Command::new("cargo")
        .args(["build", "-p", "diffguard"])
        .status()
        .context("build diffguard")?;

    if !status.success() {
        bail!("failed to build diffguard");
    }

    // Find the binary in target/debug
    let binary = std::env::current_dir()?
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
