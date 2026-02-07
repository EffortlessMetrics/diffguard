use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
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

fn main() -> Result<()> {
    let cli = Cli::parse();

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
    let status = Command::new(bin)
        .args(args)
        .status()
        .with_context(|| format!("run {bin} {args:?}"))?;
    if !status.success() {
        bail!("command failed: {bin} {args:?}");
    }
    Ok(())
}
