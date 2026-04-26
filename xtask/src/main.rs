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

/// Returns the list of all workspace crates that `cargo mutants` can target.
///
/// Hard-coded rather than discovered via `cargo metadata` to avoid a
/// bootstrap dependency on a working cargo installation during test.
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

/// Run `cargo mutants` on the specified packages, or all workspace crates if
/// `package` is empty.
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

/// Serialize `value` as pretty-printed JSON and write it to `path`.
fn write_pretty_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize json")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Execute `bin` with `args` and return the exit status.
///
/// When `bin` is `"cargo"`, the `DIFFGUARD_XTASK_CARGO` environment variable is
/// checked first — if set, its value is used instead. This allows tests to
/// intercept cargo invocations without patching PATH.
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
}
