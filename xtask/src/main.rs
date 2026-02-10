use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
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
        Cmd::Schema { out_dir } => schema(out_dir),
        Cmd::Conform { quick } => conform::run_conformance(quick),
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

fn schema(out_dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&out_dir).context("create schema output dir")?;

    let cfg_schema = schema_for!(diffguard_types::ConfigFile);
    let receipt_schema = schema_for!(diffguard_types::CheckReceipt);
    let sensor_schema = schema_for!(diffguard_types::SensorReport);

    let cfg_path = out_dir.join("diffguard.config.schema.json");
    let receipt_path = out_dir.join("diffguard.check.schema.json");
    let sensor_path = out_dir.join("sensor.report.v1.schema.json");

    write_pretty_json(&cfg_path, &cfg_schema)?;
    write_pretty_json(&receipt_path, &receipt_schema)?;
    write_pretty_json(&sensor_path, &sensor_schema)?;

    eprintln!("wrote {}", cfg_path.display());
    eprintln!("wrote {}", receipt_path.display());
    eprintln!("wrote {}", sensor_path.display());
    Ok(())
}

fn write_pretty_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize json")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

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
        schema(dir.path().to_path_buf()).expect("schema generation");

        assert!(dir.path().join("diffguard.config.schema.json").exists());
        assert!(dir.path().join("diffguard.check.schema.json").exists());
        assert!(dir.path().join("sensor.report.v1.schema.json").exists());
    }

    #[test]
    fn run_with_args_dispatches_schema() {
        let dir = TempDir::new().expect("temp");
        run_with_args(["xtask", "schema", "--out-dir", dir.path().to_str().unwrap()])
            .expect("run schema");

        assert!(dir.path().join("diffguard.config.schema.json").exists());
    }

    #[test]
    fn run_with_args_dispatches_conform_quick() {
        run_with_args(["xtask", "conform", "--quick"]).expect("run conform");
    }

    #[test]
    fn run_with_args_dispatches_ci_with_fake_cargo() {
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

        let result = run_with_args(["xtask", "ci"]);

        unsafe {
            std::env::remove_var("DIFFGUARD_XTASK_CARGO");
        }
        result.expect("run ci");
    }

    #[test]
    fn ci_reports_failure_when_clippy_fails() {
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
}
