use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use diffguard_app::{run_check, CheckPlan};
use diffguard_types::{ConfigFile, FailOn, Scope};

#[derive(Parser)]
#[command(name = "diffguard")]
#[command(about = "Diff-scoped governance lint", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate rules against added/changed lines in a git diff.
    Check(CheckArgs),

    /// Print the effective rules (built-in + optional config merge).
    Rules(RulesArgs),
}

#[derive(Parser, Debug)]
struct RulesArgs {
    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Disable built-in rules; only use the config file.
    #[arg(long)]
    no_default_rules: bool,

    #[arg(long, value_enum, default_value_t = RulesFormat::Toml)]
    format: RulesFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RulesFormat {
    Toml,
    Json,
}

#[derive(Parser, Debug)]
struct CheckArgs {
    /// Base git ref (defaults to config defaults, else origin/main).
    #[arg(long)]
    base: Option<String>,

    /// Head git ref (defaults to config defaults, else HEAD).
    #[arg(long)]
    head: Option<String>,

    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Disable built-in rules; only use the config file.
    #[arg(long)]
    no_default_rules: bool,

    /// Scope of inspection.
    #[arg(long, value_enum)]
    scope: Option<ScopeArg>,

    /// How many context lines to request from git (passed to --unified).
    #[arg(long)]
    diff_context: Option<u32>,

    /// Fail policy.
    #[arg(long, value_enum)]
    fail_on: Option<FailOnArg>,

    /// Maximum number of findings to include in the receipt.
    #[arg(long)]
    max_findings: Option<usize>,

    /// Restrict to paths matching these glob patterns. Repeatable.
    #[arg(long, action = clap::ArgAction::Append)]
    paths: Vec<String>,

    /// Where to write the JSON receipt.
    #[arg(long, default_value = "artifacts/diffguard/report.json")]
    out: PathBuf,

    /// Write a Markdown summary.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/comment.md
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/comment.md"
    )]
    md: Option<PathBuf>,

    /// Emit GitHub Actions annotations to stdout.
    #[arg(long)]
    github_annotations: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScopeArg {
    Added,
    Changed,
}

impl From<ScopeArg> for Scope {
    fn from(v: ScopeArg) -> Self {
        match v {
            ScopeArg::Added => Scope::Added,
            ScopeArg::Changed => Scope::Changed,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FailOnArg {
    Error,
    Warn,
    Never,
}

impl From<FailOnArg> for FailOn {
    fn from(v: FailOnArg) -> Self {
        match v {
            FailOnArg::Error => FailOn::Error,
            FailOnArg::Warn => FailOn::Warn,
            FailOnArg::Never => FailOn::Never,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check(args) => cmd_check(args),
        Commands::Rules(args) => cmd_rules(args),
    }
}

fn cmd_rules(args: RulesArgs) -> Result<()> {
    let cfg = load_config(args.config, args.no_default_rules)?;

    match args.format {
        RulesFormat::Toml => {
            let s = toml::to_string_pretty(&cfg).context("render toml")?;
            print!("{s}");
        }
        RulesFormat::Json => {
            let s = serde_json::to_string_pretty(&cfg).context("render json")?;
            print!("{s}");
        }
    }

    Ok(())
}

fn cmd_check(args: CheckArgs) -> Result<()> {
    let cfg = load_config(args.config.clone(), args.no_default_rules)?;

    // Merge defaults (CLI overrides config).
    let base = args
        .base
        .or_else(|| cfg.defaults.base.clone())
        .unwrap_or_else(|| "origin/main".to_string());

    let head = args
        .head
        .or_else(|| cfg.defaults.head.clone())
        .unwrap_or_else(|| "HEAD".to_string());

    let scope = args
        .scope
        .map(Into::into)
        .or(cfg.defaults.scope)
        .unwrap_or(Scope::Added);

    let fail_on = args
        .fail_on
        .map(Into::into)
        .or(cfg.defaults.fail_on)
        .unwrap_or(FailOn::Error);

    let max_findings = args
        .max_findings
        .or(cfg.defaults.max_findings.map(|v| v as usize))
        .unwrap_or(200);

    let diff_context = args.diff_context.or(cfg.defaults.diff_context).unwrap_or(0);

    let diff_text = git_diff(&base, &head, diff_context)?;

    let plan = CheckPlan {
        base: base.clone(),
        head: head.clone(),
        scope,
        diff_context,
        fail_on,
        max_findings,
        path_filters: args.paths,
    };

    let run = run_check(&plan, &cfg, &diff_text)?;

    write_json(&args.out, &run.receipt)?;

    if let Some(md_path) = args.md {
        write_text(&md_path, &run.markdown)?;
    }

    if args.github_annotations {
        for line in &run.annotations {
            println!("{line}");
        }
    }

    std::process::exit(run.exit_code);
}

fn load_config(path: Option<PathBuf>, no_default_rules: bool) -> Result<ConfigFile> {
    let user_path = path.or_else(|| {
        let p = PathBuf::from("diffguard.toml");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    });

    let Some(path) = user_path else {
        return Ok(ConfigFile::built_in());
    };

    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read config {}", path.display()))?;

    let parsed: ConfigFile =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;

    if no_default_rules {
        return Ok(parsed);
    }

    Ok(merge_with_built_in(parsed))
}

fn merge_with_built_in(user: ConfigFile) -> ConfigFile {
    let mut built = ConfigFile::built_in();

    // Defaults: user overrides built when specified.
    built.defaults = user.defaults;

    // Rules: override by id, otherwise extend.
    let mut map = std::collections::BTreeMap::<String, diffguard_types::RuleConfig>::new();
    for r in built.rule {
        map.insert(r.id.clone(), r);
    }
    for r in user.rule {
        map.insert(r.id.clone(), r);
    }

    built.rule = map.into_values().collect();
    built
}

fn git_diff(base: &str, head: &str, context_lines: u32) -> Result<String> {
    let range = format!("{base}...{head}");
    let unified = format!("--unified={context_lines}");

    let output = Command::new("git")
        .args(["diff", &unified, &range])
        .output()
        .context("run git diff")?;

    if !output.status.success() {
        bail!(
            "git diff failed (exit={}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }

    let bytes = serde_json::to_vec_pretty(value).context("serialize receipt")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }

    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
