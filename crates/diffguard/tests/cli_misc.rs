use assert_cmd::Command;
use assert_cmd::cargo;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus,
};
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

fn write_config(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("diffguard.toml");
    std::fs::write(&path, contents).expect("write config");
    path
}

fn write_sample_receipt(dir: &std::path::Path) -> std::path::PathBuf {
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
            scope: diffguard_types::Scope::Added,
            files_scanned: 1,
            lines_scanned: 1,
        },
        findings: vec![Finding {
            rule_id: "test.rule".to_string(),
            severity: Severity::Warn,
            message: "Test message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: Some(1),
            match_text: "TODO".to_string(),
            snippet: "// TODO".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: VerdictCounts {
                warn: 1,
                ..VerdictCounts::default()
            },
            reasons: vec![],
        },
        timing: None,
    };

    let path = dir.join("receipt.json");
    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    std::fs::write(&path, json).expect("write receipt");
    path
}

#[test]
fn rules_outputs_toml_and_json() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("rules")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .output()
        .expect("run rules");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test.rule"));

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("rules")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run rules json");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(value["rule"][0]["id"], "test.rule");
}

#[test]
fn explain_outputs_rule_details() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "example.rule"
severity = "warn"
message = "Example"
patterns = ["example"]
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("explain")
        .arg("example.rule")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .output()
        .expect("run explain");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Rule: example.rule"));
    assert!(stdout.contains("Severity: warn"));
}

#[test]
fn explain_unknown_rule_suggests_similar() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("explain")
        .arg("alpha.rul")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .output()
        .expect("run explain");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Did you mean"));
    assert!(stderr.contains("alpha.rule"));
}

#[test]
fn validate_json_reports_errors() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "bad.rule"
severity = "warn"
message = "Bad"
patterns = ["("]
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("validate")
        .arg("--config")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run validate");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(value["valid"], false);
    assert!(!value["errors"].as_array().unwrap().is_empty());
}

#[test]
fn validate_strict_reports_warnings_but_succeeds() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "warn.rule"
severity = "warn"
message = ""
patterns = ["todo"]
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("validate")
        .arg("--config")
        .arg(&config_path)
        .arg("--strict")
        .output()
        .expect("run validate strict");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Warnings"));
}

#[test]
fn sarif_junit_csv_render_from_receipt() {
    let td = TempDir::new().expect("temp");
    let receipt_path = write_sample_receipt(td.path());

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("sarif")
        .arg("--report")
        .arg(&receipt_path)
        .output()
        .expect("run sarif");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid sarif json");
    assert_eq!(value["version"], "2.1.0");

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("junit")
        .arg("--report")
        .arg(&receipt_path)
        .output()
        .expect("run junit");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<testsuites"));

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("csv")
        .arg("--report")
        .arg(&receipt_path)
        .output()
        .expect("run csv");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file,line,rule_id"));

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("csv")
        .arg("--report")
        .arg(&receipt_path)
        .arg("--tsv")
        .output()
        .expect("run tsv");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file\tline\trule_id"));
}

#[test]
fn test_command_reports_results_in_json() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]

[[rule.test_cases]]
input = "TODO"
should_match = true

[[rule.test_cases]]
input = "OK"
should_match = false
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("test")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run test");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(value["test_cases"], 2);
    assert_eq!(value["failed"], 0);
}

#[test]
fn test_command_exits_nonzero_on_failure() {
    let td = TempDir::new().expect("temp");
    let config_path = write_config(
        td.path(),
        r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]

[[rule.test_cases]]
input = "OK"
should_match = true
"#,
    );

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("test")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-default-rules")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run test");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(value["failed"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn validate_without_config_errors() {
    let td = TempDir::new().expect("temp");

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("validate")
        .output()
        .expect("run validate");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No configuration file found"));
}
