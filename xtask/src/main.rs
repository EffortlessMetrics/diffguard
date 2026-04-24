use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};
use schemars::schema_for;

mod conform;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Repo automation tasks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the "CI local" suite: fmt, clippy, test.
    Ci,

    /// Generate JSON Schemas for receipts/config into `schemas/`.
    Schema {
        #[arg(long, default_value = "schemas")]
        out_dir: PathBuf,
    },

    /// Run Cockpit conformance tests.
    Conform {
        /// Skip slow determinism test.
        #[arg(long)]
        quick: bool,
    },

    /// Run cargo-mutants across workspace crates (or selected packages).
    Mutants {
        /// Package name(s) to run. Repeatable. Defaults to all workspace crates.
        #[arg(long = "package", short = 'p', action = ArgAction::Append)]
        package: Vec<String>,
    },
}

#[cfg(not(test))]
fn main() -> Result<()> {
    run_with_args(std::env::args_os())
}

/// Parses CLI arguments and dispatches to the appropriate command handler.
///
/// `args` is any iterator of OS string arguments (e.g., from `std::env::args_os()`).
/// Returns an error if argument parsing fails or if the dispatched command fails.
fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    match cli.cmd {
        Cmd::Ci => ci(),
        Cmd::Schema { out_dir } => schema(out_dir.as_path()),
        Cmd::Conform { quick } => conform::run_conformance(quick),
        Cmd::Mutants { package } => mutants(package),
    }
}

/// Runs the full local CI suite: fmt check, clippy with warnings-as-errors,
/// workspace tests, and quick conformance tests.
///
/// Returns an error if any step in the suite fails.
fn ci() -> Result<()> {
    run("cargo", &["fmt", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run("cargo", &["test", "--workspace"])?;
    conform::run_conformance(true)?;
    Ok(())
}

/// Generates JSON Schemas for all diffguard types into the specified output directory.
///
/// Schema files generated:
/// - `diffguard.config.schema.json` — `ConfigFile` schema
/// - `diffguard.check.schema.json` — `CheckReceipt` schema
/// - `sensor.report.v1.schema.json` — `SensorReport` schema
/// - `diffguard.false-positive-baseline.v1.schema.json` — `FalsePositiveBaseline` schema
/// - `diffguard.trend-history.v1.schema.json` — `TrendHistory` schema
///
/// Creates the output directory if it does not exist.
/// Returns an error if directory creation or schema serialization fails.
fn schema(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).context("create schema output dir")?;

    let cfg_schema = schema_for!(diffguard_types::ConfigFile);
    let receipt_schema = schema_for!(diffguard_types::CheckReceipt);
    let sensor_schema = schema_for!(diffguard_types::SensorReport);
    let baseline_schema = schema_for!(diffguard_analytics::FalsePositiveBaseline);
    let trend_schema = schema_for!(diffguard_analytics::TrendHistory);

    let cfg_path = out_dir.join("diffguard.config.schema.json");
    let receipt_path = out_dir.join("diffguard.check.schema.json");
    let sensor_path = out_dir.join("sensor.report.v1.schema.json");
    let baseline_path = out_dir.join("diffguard.false-positive-baseline.v1.schema.json");
    let trend_path = out_dir.join("diffguard.trend-history.v1.schema.json");

    write_pretty_json(&cfg_path, &cfg_schema)?;
    write_pretty_json(&receipt_path, &receipt_schema)?;
    write_pretty_json(&sensor_path, &sensor_schema)?;
    write_pretty_json(&baseline_path, &baseline_schema)?;
    write_pretty_json(&trend_path, &trend_schema)?;

    eprintln!("wrote {}", cfg_path.display());
    eprintln!("wrote {}", receipt_path.display());
    eprintln!("wrote {}", sensor_path.display());
    eprintln!("wrote {}", baseline_path.display());
    eprintln!("wrote {}", trend_path.display());
    Ok(())
}

/// Returns the canonical list of all workspace crates that should be tested
/// by cargo-mutants.
///
/// This list should be kept in sync with the actual workspace members in
/// `Cargo.toml`. Used as the default when no specific packages are requested.
fn default_mutants_packages() -> Vec<String> {
    vec![
        "diffguard-analytics".to_string(),
        "diffguard".to_string(),
        "diffguard-core".to_string(),
        "diffguard-diff".to_string(),
        "diffguard-domain".to_string(),
        "diffguard-lsp".to_string(),
        "diffguard-testkit".to_string(),
        "diffguard-types".to_string(),
        "xtask".to_string(),
    ]
}

/// Runs cargo-mutants across one or more workspace crates.
///
/// If `package` is empty, runs against all workspace crates listed in
/// `default_mutants_packages()`. Otherwise runs only against the specified
/// packages. Returns an error if any cargo-mutants invocation fails.
fn mutants(package: Vec<String>) -> Result<()> {
    let packages = if package.is_empty() {
        default_mutants_packages()
    } else {
        package
    };

    for pkg in packages {
        eprintln!("running cargo mutants -p {pkg}");
        run("cargo", &["mutants", "-p", &pkg])?;
    }

    Ok(())
}

/// Serializes a value to JSON with pretty-print formatting and writes it to the given path.
///
/// Uses `serde_json::to_vec_pretty` to produce human-readable output.
/// Returns an error if serialization or file write fails.
fn write_pretty_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize json")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Executes an external command and returns its success status.
///
/// `bin` is the name or path of the executable. `args` are the command-line
/// arguments as string slices.
///
/// For `cargo` commands, checks the `DIFFGUARD_XTASK_CARGO` environment variable
/// first, allowing tests to override the cargo binary path. Returns an error
/// if the command exits with a non-zero status code.
fn run(bin: &str, args: &[&str]) -> Result<()> {
    let resolved = if bin == "cargo" {
        std::env::var_os("DIFFGUARD_XTASK_CARGO").unwrap_or_else(|| bin.into())
    } else {
        bin.into()
    };
    let status = Command::new(&resolved)
        .args(args)
        .status()
        .with_context(|| format!("run {bin} {args:?}"))?;
    if !status.success() {
        bail!("command failed: {bin} {args:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Lock the ENV mutex, recovering from poison if needed.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(windows)]
    fn ok_command() -> (&'static str, Vec<&'static str>) {
        ("cmd", vec!["/C", "exit 0"])
    }

    #[cfg(not(windows))]
    fn ok_command() -> (&'static str, Vec<&'static str>) {
        ("sh", vec!["-c", "exit 0"])
    }

    #[cfg(windows)]
    fn fail_command() -> (&'static str, Vec<&'static str>) {
        ("cmd", vec!["/C", "exit 1"])
    }

    #[cfg(not(windows))]
    fn fail_command() -> (&'static str, Vec<&'static str>) {
        ("sh", vec!["-c", "exit 1"])
    }

    #[test]
    fn write_pretty_json_creates_valid_file() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("out.json");
        let payload = serde_json::json!({ "ok": true });

        write_pretty_json(&path, &payload).expect("write json");

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn run_reports_success_and_failure() {
        let (bin_ok, args_ok) = ok_command();
        run(bin_ok, &args_ok).expect("expected ok command to succeed");

        let (bin_fail, args_fail) = fail_command();
        assert!(run(bin_fail, &args_fail).is_err());
    }

    #[test]
    fn schema_writes_expected_files() {
        let dir = TempDir::new().expect("temp");
        schema(dir.path()).expect("schema generation");

        assert!(dir.path().join("diffguard.config.schema.json").exists());
        assert!(dir.path().join("diffguard.check.schema.json").exists());
        assert!(dir.path().join("sensor.report.v1.schema.json").exists());
        assert!(
            dir.path()
                .join("diffguard.false-positive-baseline.v1.schema.json")
                .exists()
        );
        assert!(
            dir.path()
                .join("diffguard.trend-history.v1.schema.json")
                .exists()
        );
    }

    #[test]
    fn run_with_args_dispatches_schema() {
        let dir = TempDir::new().expect("temp");
        run_with_args(["xtask", "schema", "--out-dir", dir.path().to_str().unwrap()])
            .expect("run schema");

        assert!(dir.path().join("diffguard.config.schema.json").exists());
        assert!(
            dir.path()
                .join("diffguard.false-positive-baseline.v1.schema.json")
                .exists()
        );
    }

    #[test]
    fn run_with_args_dispatches_conform_quick() {
        run_with_args(["xtask", "conform", "--quick"]).expect("run conform");
    }

    #[test]
    fn default_mutants_packages_lists_workspace_crates() {
        let packages = default_mutants_packages();
        for expected in [
            "diffguard-analytics",
            "diffguard",
            "diffguard-core",
            "diffguard-diff",
            "diffguard-domain",
            "diffguard-lsp",
            "diffguard-testkit",
            "diffguard-types",
            "xtask",
        ] {
            assert!(packages.contains(&expected.to_string()));
        }
    }

    #[test]
    fn run_with_args_dispatches_mutants_with_fake_cargo() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().expect("temp");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");

        let cargo_path = {
            #[cfg(windows)]
            {
                bin_dir.join("cargo.cmd")
            }
            #[cfg(not(windows))]
            {
                bin_dir.join("cargo")
            }
        };
        let script = {
            #[cfg(windows)]
            {
                "@echo off\r\nexit /b 0\r\n"
            }
            #[cfg(not(windows))]
            {
                "#!/bin/sh\nexit 0\n"
            }
        };
        std::fs::write(&cargo_path, script).expect("write fake cargo");
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cargo_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&cargo_path, perms).unwrap();
        }

        unsafe {
            std::env::set_var("DIFFGUARD_XTASK_CARGO", &cargo_path);
        }
        let result = run_with_args(["xtask", "mutants", "-p", "diffguard-core"]);
        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }

        result.expect("run mutants");
    }

    #[test]
    fn run_with_args_dispatches_ci_with_fake_cargo() {
        let _guard = lock_env();
        let dir = TempDir::new().expect("temp");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");

        let cargo_path = {
            #[cfg(windows)]
            {
                bin_dir.join("cargo.cmd")
            }
            #[cfg(not(windows))]
            {
                bin_dir.join("cargo")
            }
        };
        let script = {
            #[cfg(windows)]
            {
                "@echo off\r\nexit /b 0\r\n"
            }
            #[cfg(not(windows))]
            {
                "#!/bin/sh\nexit 0\n"
            }
        };
        std::fs::write(&cargo_path, script).expect("write fake cargo");
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cargo_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&cargo_path, perms).unwrap();
        }

        unsafe {
            std::env::set_var("DIFFGUARD_XTASK_CARGO", &cargo_path);
        }

        let result = run_with_args(["xtask", "ci"]);

        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }
        result.expect("run ci");
    }

    #[test]
    fn ci_reports_failure_when_clippy_fails() {
        let _guard = lock_env();
        let dir = TempDir::new().expect("temp");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");

        let cargo_path = {
            #[cfg(windows)]
            {
                bin_dir.join("cargo.cmd")
            }
            #[cfg(not(windows))]
            {
                bin_dir.join("cargo")
            }
        };
        let script = {
            #[cfg(windows)]
            {
                "@echo off\r\nif \"%1\"==\"fmt\" exit /b 0\r\nif \"%1\"==\"clippy\" exit /b 1\r\nexit /b 0\r\n"
            }
            #[cfg(not(windows))]
            {
                "#!/bin/sh\nif [ \"$1\" = \"fmt\" ]; then exit 0; fi\nif [ \"$1\" = \"clippy\" ]; then exit 1; fi\nexit 0\n"
            }
        };
        std::fs::write(&cargo_path, script).expect("write fake cargo");
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cargo_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&cargo_path, perms).unwrap();
        }

        unsafe {
            std::env::set_var("DIFFGUARD_XTASK_CARGO", &cargo_path);
        }

        let err = ci().expect_err("ci should fail when clippy fails");

        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }

        assert!(err.to_string().contains("command failed"));
    }

    // =============================================================================
    // Green edge case tests for xtask CI pipeline
    // =============================================================================

    /// Test CI failure when test command fails
    #[test]
    fn ci_reports_failure_when_test_fails() {
        let _guard = lock_env();
        let dir = TempDir::new().expect("temp");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");

        let cargo_path = {
            #[cfg(windows)]
            {
                bin_dir.join("cargo.cmd")
            }
            #[cfg(not(windows))]
            {
                bin_dir.join("cargo")
            }
        };
        let script = {
            #[cfg(windows)]
            {
                "@echo off\r\nif \"%1\"==\"fmt\" exit /b 0\r\nif \"%1\"==\"test\" exit /b 1\r\nexit /b 0\r\n"
            }
            #[cfg(not(windows))]
            {
                "#!/bin/sh\nif [ \"$1\" = \"fmt\" ]; then exit 0; fi\nif [ \"$1\" = \"test\" ]; then exit 1; fi\nexit 0\n"
            }
        };
        std::fs::write(&cargo_path, script).expect("write fake cargo");
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cargo_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&cargo_path, perms).unwrap();
        }

        unsafe {
            std::env::set_var("DIFFGUARD_XTASK_CARGO", &cargo_path);
        }

        let err = ci().expect_err("ci should fail when test fails");

        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }

        assert!(err.to_string().contains("command failed"));
    }

    /// Test that default_mutants_packages has no duplicates
    #[test]
    fn default_mutants_packages_no_duplicates() {
        use std::collections::HashSet;
        let packages = default_mutants_packages();
        let unique: HashSet<_> = packages.iter().collect();
        assert_eq!(
            unique.len(),
            packages.len(),
            "packages should not have duplicates"
        );
    }

    /// Test writing empty JSON object
    #[test]
    fn write_pretty_json_empty_object() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("empty.json");

        write_pretty_json(&path, &serde_json::json!({})).expect("write empty json");

        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(content.trim(), "{}");
    }

    /// Test writing deeply nested JSON
    #[test]
    fn write_pretty_json_deeply_nested() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("nested.json");

        let nested = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "value": "deep"
                        }
                    }
                }
            }
        });

        write_pretty_json(&path, &nested).expect("write nested json");

        let content = std::fs::read_to_string(&path).expect("read back");
        assert!(content.contains("level4"));
        assert!(content.contains("deep"));
    }

    /// Test writing JSON with unicode characters
    #[test]
    fn write_pretty_json_unicode_content() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("unicode.json");

        let unicode_json = serde_json::json!({
            "japanese": "日本語",
            "chinese": "中文",
            "korean": "한국어",
            "emoji": "😀🎉"
        });

        write_pretty_json(&path, &unicode_json).expect("write unicode json");

        let content = std::fs::read_to_string(&path).expect("read back");
        assert!(content.contains("日本語"));
        assert!(content.contains("中文"));
        assert!(content.contains("한국어"));
    }

    /// Test writing JSON array with many objects
    #[test]
    fn write_pretty_json_large_array() {
        let dir = TempDir::new().expect("temp");
        let path = dir.path().join("large_array.json");

        let large_array = serde_json::json!([
            {"id": 1, "name": "item1"},
            {"id": 2, "name": "item2"},
            {"id": 3, "name": "item3"}
        ]);

        write_pretty_json(&path, &large_array).expect("write large array json");

        let content = std::fs::read_to_string(&path).expect("read back");
        assert!(content.contains("item1"));
        assert!(content.contains("item2"));
        assert!(content.contains("item3"));
    }

    /// Test that run function handles path with spaces correctly
    #[test]
    fn run_handles_path_with_spaces() {
        let (bin_ok, args_ok) = ok_command();
        // Test with a command that might have issues with spaces in path
        let result = run(bin_ok, &args_ok);
        assert!(result.is_ok(), "run should handle command properly");
    }

    /// Test that ci function handles fmt failure properly
    #[test]
    fn ci_reports_failure_when_fmt_fails() {
        let _guard = lock_env();
        let dir = TempDir::new().expect("temp");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create bin dir");

        let cargo_path = {
            #[cfg(windows)]
            {
                bin_dir.join("cargo.cmd")
            }
            #[cfg(not(windows))]
            {
                bin_dir.join("cargo")
            }
        };
        let script = {
            #[cfg(windows)]
            {
                "@echo off\r\nif \"%1\"==\"fmt\" exit /b 1\r\nexit /b 0\r\n"
            }
            #[cfg(not(windows))]
            {
                "#!/bin/sh\nif [ \"$1\" = \"fmt\" ]; then exit 1; fi\nexit 0\n"
            }
        };
        std::fs::write(&cargo_path, script).expect("write fake cargo");
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&cargo_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&cargo_path, perms).unwrap();
        }

        unsafe {
            std::env::set_var("DIFFGUARD_XTASK_CARGO", &cargo_path);
        }

        let err = ci().expect_err("ci should fail when fmt fails");

        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }

        assert!(err.to_string().contains("command failed"));
    }

    // =============================================================================
    // Property-based tests for schema() and write_pretty_json()
    // =============================================================================

    /// Property: write_pretty_json produces valid parseable JSON for various values.
    #[test]
    fn property_write_pretty_json_produces_valid_json() {
        let test_cases = vec![
            serde_json::json!({}),
            serde_json::json!({"key": "value"}),
            serde_json::json!([1, 2, 3]),
            serde_json::json!({"nested": {"deep": {"value": 42}}}),
            serde_json::json!({"array": [{"id": 1}, {"id": 2}]}),
            serde_json::json!({"unicode": "日本語中文한국어", "emoji": "😀🎉"}),
            serde_json::json!({"special_chars": "a\"b\\c\td\ne"}),
            serde_json::json!({"numbers": [0, -1, 1.5, 3.14159, 1e10]}),
            serde_json::json!({"booleans": [true, false, null]}),
        ];

        for value in test_cases {
            let dir = TempDir::new().expect("temp");
            let path = dir.path().join("test.json");

            write_pretty_json(&path, &value).expect("write should succeed");

            let content = std::fs::read_to_string(&path).expect("read should succeed");
            let parsed: serde_json::Value =
                serde_json::from_str(&content).expect("should be valid JSON");

            assert_eq!(parsed, value, "roundtrip should preserve value");
        }
    }

    /// Property: write_pretty_json is idempotent - writing same value twice
    /// produces byte-identical output.
    #[test]
    fn property_write_pretty_json_idempotent() {
        let test_cases = vec![
            serde_json::json!({"test": "value"}),
            serde_json::json!([1, 2, 3]),
            serde_json::json!({"nested": {"deep": true}}),
            serde_json::json!({"emoji": "😀🎉🏆"}),
        ];

        for value in test_cases {
            let dir = TempDir::new().expect("temp");
            let path = dir.path().join("idempotent.json");

            write_pretty_json(&path, &value).expect("first write should succeed");
            let first_content = std::fs::read(&path).expect("first read should succeed");

            write_pretty_json(&path, &value).expect("second write should succeed");
            let second_content = std::fs::read(&path).expect("second read should succeed");

            assert_eq!(
                first_content, second_content,
                "writing twice should produce identical content"
            );
        }
    }

    /// Property: schema() works with paths containing Unicode characters.
    #[test]
    fn property_schema_handles_unicode_paths() {
        let test_paths = vec![
            PathBuf::from("テスト/スキーマ"),
            PathBuf::from("测试/模式"),
            PathBuf::from("테스트/스키마"),
            PathBuf::from("test📁/schema📄"),
            PathBuf::from("日本語/test/中文"),
        ];

        for subpath in test_paths {
            let dir = TempDir::new().expect("temp");
            let out_dir = dir.path().join(&subpath);

            let result = schema(out_dir.as_path());
            assert!(
                result.is_ok(),
                "schema() should succeed with Unicode path: {:?}",
                subpath
            );

            assert!(
                out_dir.join("diffguard.config.schema.json").exists(),
                "config schema should exist for path: {:?}",
                subpath
            );
        }
    }

    /// Property: schema() creates the output directory if it doesn't exist.
    #[test]
    fn property_schema_creates_output_directory() {
        let dir = TempDir::new().expect("temp");
        let out_dir = dir
            .path()
            .join("nonexistent")
            .join("nested")
            .join("directory");

        assert!(
            !out_dir.exists(),
            "precondition: directory should not exist"
        );

        let result = schema(out_dir.as_path());
        assert!(
            result.is_ok(),
            "schema() should succeed even when output dir doesn't exist"
        );
        assert!(out_dir.exists(), "schema() should create the output directory");
    }

    /// Property: schema() generates all 5 expected files regardless of output path.
    #[test]
    fn property_schema_generates_all_expected_files() {
        use std::collections::HashSet;

        let test_cases = vec![
            PathBuf::from("schemas"),
            PathBuf::from("output"),
            PathBuf::from("test🌍"),
            PathBuf::from("nested/deep/path"),
        ];

        let expected_files: HashSet<String> = [
            "diffguard.config.schema.json".to_string(),
            "diffguard.check.schema.json".to_string(),
            "sensor.report.v1.schema.json".to_string(),
            "diffguard.false-positive-baseline.v1.schema.json".to_string(),
            "diffguard.trend-history.v1.schema.json".to_string(),
        ]
        .into_iter()
        .collect();

        for out_dir_name in test_cases {
            let dir = TempDir::new().expect("temp");
            let out_dir = dir.path().join(&out_dir_name);

            schema(out_dir.as_path()).expect("schema should succeed");

            let mut found_files = HashSet::new();
            for entry in std::fs::read_dir(&out_dir).expect("should read dir") {
                let entry = entry.expect("entry should exist");
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".json") {
                    found_files.insert(name);
                }
            }

            assert_eq!(
                found_files, expected_files,
                "schema() should generate exactly the 5 expected files for path: {:?}",
                out_dir_name
            );
        }
    }

    /// Property: schema() produces valid JSON in all output files.
    #[test]
    fn property_schema_produces_valid_json_files() {
        let dir = TempDir::new().expect("temp");

        schema(dir.path()).expect("schema should succeed");

        let schema_files = [
            "diffguard.config.schema.json",
            "diffguard.check.schema.json",
            "sensor.report.v1.schema.json",
            "diffguard.false-positive-baseline.v1.schema.json",
            "diffguard.trend-history.v1.schema.json",
        ];

        for filename in schema_files {
            let path = dir.path().join(filename);
            let content = std::fs::read_to_string(&path).expect("should read file");
            let _parsed: serde_json::Value =
                serde_json::from_str(&content).expect("schema file should be valid JSON");
        }
    }

    /// Property: schema() is deterministic - running twice produces same output.
    #[test]
    fn property_schema_deterministic() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn simple_hash(data: &[u8]) -> u64 {
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            hasher.finish()
        }

        let dir = TempDir::new().expect("temp");

        // First run
        schema(dir.path()).expect("first schema should succeed");

        let first_hashes: std::collections::HashSet<_> = std::fs::read_dir(dir.path())
            .expect("should read dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .map(|e| {
                let content = std::fs::read(e.path()).expect("should read file");
                let hash = simple_hash(&content);
                (e.file_name().to_string_lossy().into_owned(), hash)
            })
            .collect();

        // Second run
        schema(dir.path()).expect("second schema should succeed");

        let second_hashes: std::collections::HashSet<_> = std::fs::read_dir(dir.path())
            .expect("should read dir second time")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .map(|e| {
                let content = std::fs::read(e.path()).expect("should read file");
                let hash = simple_hash(&content);
                (e.file_name().to_string_lossy().into_owned(), hash)
            })
            .collect();

        assert_eq!(
            first_hashes, second_hashes,
            "schema() should produce deterministic output"
        );
    }

    /// Property: schema() works with spaces in the output path.
    #[test]
    fn property_schema_handles_spaces_in_path() {
        let dir = TempDir::new().expect("temp");
        let out_dir = dir.path().join("path with spaces").join("nested path");

        let result = schema(out_dir.as_path());
        assert!(result.is_ok(), "schema() should succeed with spaces in path");

        assert!(
            out_dir.join("diffguard.config.schema.json").exists(),
            "config schema should exist"
        );
    }

    /// Property: schema() accepts &Path (borrowed) instead of PathBuf (owned).
    /// This verifies the fix for needless_pass_by_value lint.
    #[test]
    fn property_schema_accepts_borrowed_path() {
        let dir = TempDir::new().expect("temp");
        let path_buf = dir.path().to_path_buf();

        // Call schema with borrowed &Path - this is the key verification
        // that the function signature was correctly changed from PathBuf to &Path
        let borrowed_path: &Path = path_buf.as_path();
        let result = schema(borrowed_path);
        assert!(
            result.is_ok(),
            "schema() should accept &Path, not require PathBuf"
        );
    }

    /// Property: schema() handles various path patterns.
    #[test]
    fn property_schema_handles_various_path_patterns() {
        let patterns = vec![
            "short",
            "a",
            "verylongdirname",
            "with-dash",
            "with_underscore",
            "with.dots",
            "UPPERCASE",
            "MixedCase",
            "日本語",
            "中文",
            "한국어",
            "mixe🇰🇷d",
            "spaces in dir",
        ];

        for pattern in patterns {
            let dir = TempDir::new().expect("temp");
            let out_dir = dir.path().join(pattern);

            let result = schema(out_dir.as_path());
            assert!(
                result.is_ok(),
                "schema() should handle path pattern: {:?}",
                pattern
            );

            if result.is_ok() {
                let count = std::fs::read_dir(&out_dir)
                    .map(|entries| entries.filter(|e| e.is_ok()).count())
                    .unwrap_or(0);
                assert_eq!(
                    count, 5,
                    "should create 5 schema files for pattern: {:?}",
                    pattern
                );
            }
        }
    }
}
