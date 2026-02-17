#![allow(clippy::collapsible_if)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use tracing::{debug, info};

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, TREND_HISTORY_SCHEMA_V1,
    TrendHistory, append_trend_run, baseline_from_receipt, false_positive_fingerprint_set,
    merge_false_positive_baselines, normalize_false_positive_baseline, normalize_trend_history,
    summarize_trend_history, trend_run_from_receipt,
};
use diffguard_core::{
    CheckPlan, RuleMetadata, SensorReportContext, render_csv_for_receipt, render_junit_for_receipt,
    render_sarif_json, render_sensor_json, render_tsv_for_receipt, run_check,
};
use diffguard_diff::parse_unified_diff;
use diffguard_domain::{DirectoryRuleOverride, compile_rules};
use diffguard_types::{
    Artifact, CAP_GIT, CAP_STATUS_AVAILABLE, CAP_STATUS_UNAVAILABLE, CHECK_ID_INTERNAL,
    CODE_TOOL_RUNTIME_ERROR, CapabilityStatus, CheckReceipt, ConfigFile, DiffMeta,
    DirectoryOverrideConfig, FailOn, MatchMode, REASON_MISSING_BASE, REASON_NO_DIFF_INPUT,
    REASON_TOOL_ERROR, RuleConfig, Scope, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
};

mod config_loader;
mod presets;

use config_loader::load_config_with_includes;
use presets::Preset;

#[derive(Parser)]
#[command(name = "diffguard")]
#[command(about = "Diff-scoped governance lint", long_about = None)]
struct Cli {
    /// Enable verbose (info-level) logging to stderr.
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    /// Enable debug-level logging to stderr.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate rules against diff-scoped lines in a git diff.
    Check(Box<CheckArgs>),

    /// Print the effective rules (built-in + optional config merge).
    Rules(RulesArgs),

    /// Show detailed information about a specific rule.
    Explain(ExplainArgs),

    /// Validate the configuration file (check regex patterns and globs).
    Validate(ValidateArgs),

    /// Convert a JSON receipt to SARIF format (render-only mode).
    Sarif(SarifArgs),

    /// Convert a JSON receipt to JUnit XML format (render-only mode).
    Junit(JunitArgs),

    /// Convert a JSON receipt to CSV or TSV format (render-only mode).
    Csv(CsvArgs),

    /// Initialize a new diffguard.toml configuration file.
    Init(InitArgs),

    /// Run test cases defined in rule configurations.
    Test(TestArgs),

    /// Summarize historical check trends from a trend history file.
    Trend(TrendArgs),
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
    /// Base git ref (repeatable for multi-base comparison).
    ///
    /// Examples:
    ///   --base origin/main
    ///   --base origin/main --base origin/release/1.0
    ///
    /// When omitted, defaults to config defaults, else origin/main.
    #[arg(long, action = clap::ArgAction::Append)]
    base: Vec<String>,

    /// Head git ref (defaults to config defaults, else HEAD).
    #[arg(long)]
    head: Option<String>,

    /// Check only staged changes (for pre-commit hooks).
    ///
    /// Uses `git diff --cached` instead of base...head range.
    /// Mutually exclusive with --base, --head, and --diff-file.
    #[arg(long, conflicts_with_all = ["base", "head", "diff_file"])]
    staged: bool,

    /// Read unified diff input from a file (or '-' for stdin) instead of git.
    ///
    /// Mutually exclusive with --staged, --base, and --head.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["staged", "base", "head"])]
    diff_file: Option<PathBuf>,

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

    /// Only run rules that have at least one of these tags. Repeatable.
    ///
    /// When specified, rules without any matching tags are skipped.
    /// Tags are matched case-insensitively.
    #[arg(long, action = clap::ArgAction::Append)]
    only_tags: Vec<String>,

    /// Disable rules that have any of these tags. Repeatable.
    ///
    /// Rules with any matching tag are skipped. Applied after --only-tags.
    /// Tags are matched case-insensitively.
    #[arg(long, action = clap::ArgAction::Append)]
    disable_tags: Vec<String>,

    /// Add rules with these tags even when --only-tags is set. Repeatable.
    #[arg(long, action = clap::ArgAction::Append)]
    enable_tags: Vec<String>,

    /// Where to write the JSON receipt.
    ///
    /// In standard mode, defaults to artifacts/diffguard/report.json.
    /// In cockpit mode with --sensor, defaults to artifacts/diffguard/extras/check.json
    /// (the canonical report.json path is used by the sensor envelope).
    #[arg(long)]
    out: Option<PathBuf>,

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

    /// Write a SARIF report.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/report.sarif.json
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/report.sarif.json"
    )]
    sarif: Option<PathBuf>,

    /// Write a JUnit XML report.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/report.xml
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/report.xml"
    )]
    junit: Option<PathBuf>,

    /// Write a CSV report.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/report.csv
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/report.csv"
    )]
    csv: Option<PathBuf>,

    /// Write a TSV report.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/report.tsv
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/report.tsv"
    )]
    tsv: Option<PathBuf>,

    /// Write per-rule hit statistics as JSON.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/rule-stats.json
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/rule-stats.json"
    )]
    rule_stats: Option<PathBuf>,

    /// Read a false-positive baseline file and suppress matching findings.
    #[arg(long, value_name = "PATH")]
    false_positive_baseline: Option<PathBuf>,

    /// Write/merge a false-positive baseline file from this run's findings.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/false-positives.json
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/false-positives.json"
    )]
    write_false_positive_baseline: Option<PathBuf>,

    /// Append this run to a trend history file for cross-run analytics.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/trend-history.json
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/trend-history.json"
    )]
    trend_history: Option<PathBuf>,

    /// Maximum number of runs to retain when writing trend history.
    #[arg(long)]
    trend_max_runs: Option<usize>,

    /// Filter scoped lines to specific blame author patterns. Repeatable.
    ///
    /// Matches case-insensitive substrings against `author` and `author-mail`.
    #[arg(long, action = clap::ArgAction::Append)]
    blame_author: Vec<String>,

    /// Filter scoped lines to commits no older than N days.
    #[arg(long)]
    blame_max_age_days: Option<u32>,

    /// Execution mode.
    ///
    /// In standard mode, exit codes reflect the verdict (0=pass, 2=fail, 3=warn-fail).
    /// In cockpit mode, exit 0 if a receipt was written, exit 1 only on catastrophic failure.
    /// Can also be set via DIFFGUARD_MODE environment variable.
    #[arg(long, value_enum, default_value_t = Mode::Standard)]
    mode: Mode,

    /// Write a sensor.report.v1 JSON file for Cockpit integration.
    ///
    /// If provided with no value, defaults to artifacts/diffguard/report.json
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "artifacts/diffguard/report.json"
    )]
    sensor: Option<PathBuf>,

    /// Force all files to use the specified language for preprocessing.
    ///
    /// This overrides the auto-detected language from file extensions.
    /// Valid values: rust, python, javascript, typescript, go, ruby, c, cpp,
    /// csharp, java, kotlin, shell, swift, scala, sql, xml, php, yaml, toml, json
    #[arg(long, value_enum)]
    language: Option<LanguageArg>,
}

#[derive(Parser, Debug)]
struct SarifArgs {
    /// Path to a JSON receipt file to convert.
    #[arg(long)]
    report: PathBuf,

    /// Output path for the SARIF file.
    ///
    /// If omitted, writes to stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct JunitArgs {
    /// Path to a JSON receipt file to convert.
    #[arg(long)]
    report: PathBuf,

    /// Output path for the JUnit XML file.
    ///
    /// If omitted, writes to stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct CsvArgs {
    /// Path to a JSON receipt file to convert.
    #[arg(long)]
    report: PathBuf,

    /// Output path for the CSV/TSV file.
    ///
    /// If omitted, writes to stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Output as TSV instead of CSV.
    #[arg(long)]
    tsv: bool,
}

#[derive(Parser, Debug)]
struct TrendArgs {
    /// Path to the trend history JSON file.
    #[arg(long, default_value = "artifacts/diffguard/trend-history.json")]
    history: PathBuf,

    /// Output format for trend summary.
    #[arg(long, value_enum, default_value_t = TrendFormat::Text)]
    format: TrendFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TrendFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
struct ExplainArgs {
    /// The rule ID to explain (e.g., "rust.no_unwrap").
    rule_id: String,

    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Disable built-in rules; only use the config file.
    #[arg(long)]
    no_default_rules: bool,
}

#[derive(Parser, Debug)]
struct InitArgs {
    /// Configuration preset to use.
    ///
    /// Available presets:
    /// - minimal: Basic starter config (default)
    /// - rust-quality: Rust best practices
    /// - secrets: Secret/credential detection
    /// - js-console: JavaScript/TypeScript debugging
    /// - python-debug: Python debugging
    #[arg(long, short, value_enum, default_value_t = Preset::Minimal)]
    preset: Preset,

    /// Output path for the configuration file.
    #[arg(long, short, default_value = "diffguard.toml")]
    output: PathBuf,

    /// Overwrite existing configuration file without prompting.
    #[arg(long, short)]
    force: bool,
}

#[derive(Parser, Debug)]
struct ValidateArgs {
    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Enable strict mode: also report best-practice warnings.
    #[arg(long)]
    strict: bool,

    /// Output format for validation results.
    #[arg(long, value_enum, default_value_t = ValidateFormat::Text)]
    format: ValidateFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ValidateFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
struct TestArgs {
    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Only test rules matching this ID (can be a prefix like "rust.").
    #[arg(long)]
    rule: Option<String>,

    /// Disable built-in rules; only use the config file.
    #[arg(long)]
    no_default_rules: bool,

    /// Output format for test results.
    #[arg(long, value_enum, default_value_t = TestFormat::Text)]
    format: TestFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TestFormat {
    Text,
    Json,
}

/// Execution mode for the check command.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Mode {
    /// Standard mode: exit codes 0=pass, 1=error, 2=fail, 3=warn-fail.
    #[default]
    Standard,
    /// Cockpit mode: exit 0 if receipt written, exit 1 only on catastrophic failure.
    Cockpit,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScopeArg {
    Added,
    Changed,
    Modified,
    Deleted,
}

impl From<ScopeArg> for Scope {
    fn from(v: ScopeArg) -> Self {
        match v {
            ScopeArg::Added => Scope::Added,
            ScopeArg::Changed => Scope::Changed,
            ScopeArg::Modified => Scope::Modified,
            ScopeArg::Deleted => Scope::Deleted,
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

/// Language for preprocessing override.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum LanguageArg {
    Rust,
    Python,
    Javascript,
    Typescript,
    Go,
    Ruby,
    C,
    Cpp,
    Csharp,
    Java,
    Kotlin,
    Shell,
    Swift,
    Scala,
    Sql,
    Xml,
    Php,
    Yaml,
    Toml,
    Json,
}

impl LanguageArg {
    /// Convert to lowercase string for the domain layer.
    fn as_str(self) -> &'static str {
        match self {
            LanguageArg::Rust => "rust",
            LanguageArg::Python => "python",
            LanguageArg::Javascript => "javascript",
            LanguageArg::Typescript => "typescript",
            LanguageArg::Go => "go",
            LanguageArg::Ruby => "ruby",
            LanguageArg::C => "c",
            LanguageArg::Cpp => "cpp",
            LanguageArg::Csharp => "csharp",
            LanguageArg::Java => "java",
            LanguageArg::Kotlin => "kotlin",
            LanguageArg::Shell => "shell",
            LanguageArg::Swift => "swift",
            LanguageArg::Scala => "scala",
            LanguageArg::Sql => "sql",
            LanguageArg::Xml => "xml",
            LanguageArg::Php => "php",
            LanguageArg::Yaml => "yaml",
            LanguageArg::Toml => "toml",
            LanguageArg::Json => "json",
        }
    }
}

#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    match run_with_args(std::env::args_os()) {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("{err:?}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run_with_args<I, T>(args: I) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    // Initialize logging based on flags
    init_logging(cli.verbose, cli.debug);

    // Initialize logging based on flags
    init_logging(cli.verbose, cli.debug);

    match cli.command {
        Commands::Check(args) => cmd_check(*args),
        Commands::Rules(args) => {
            cmd_rules(args)?;
            Ok(0)
        }
        Commands::Explain(args) => {
            cmd_explain(args)?;
            Ok(0)
        }
        Commands::Validate(args) => cmd_validate(args),
        Commands::Sarif(args) => {
            cmd_sarif(args)?;
            Ok(0)
        }
        Commands::Junit(args) => {
            cmd_junit(args)?;
            Ok(0)
        }
        Commands::Csv(args) => {
            cmd_csv(args)?;
            Ok(0)
        }
        Commands::Init(args) => {
            cmd_init(args)?;
            Ok(0)
        }
        Commands::Test(args) => cmd_test(args),
        Commands::Trend(args) => {
            cmd_trend(args)?;
            Ok(0)
        }
    }
}

/// Initialize tracing/logging based on CLI flags.
fn init_logging(verbose: bool, debug: bool) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let level = if debug {
        "debug"
    } else if verbose {
        "info"
    } else {
        "warn"
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .try_init();

    debug!("Logging initialized at level: {}", level);
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

fn compile_rules_checked(
    rules: &[diffguard_types::RuleConfig],
) -> Result<Vec<diffguard_domain::CompiledRule>, diffguard_domain::RuleCompileError> {
    #[cfg(test)]
    {
        if std::env::var("DIFFGUARD_TEST_FORCE_COMPILE_ERROR").is_ok() {
            return Err(diffguard_domain::RuleCompileError::MissingPatterns {
                rule_id: "forced.compile".to_string(),
            });
        }
    }

    compile_rules(rules)
}

fn cmd_validate(args: ValidateArgs) -> Result<i32> {
    info!("Validating configuration file");

    // Determine config path
    let config_path = args.config.clone().or_else(|| {
        let p = PathBuf::from("diffguard.toml");
        if p.exists() { Some(p) } else { None }
    });

    let Some(path) = config_path else {
        bail!("No configuration file found. Specify --config or create diffguard.toml");
    };

    debug!("Loading config from: {}", path.display());

    // Read and parse the config file (with env var expansion)
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read config {}", path.display()))?;

    let expanded = expand_env_vars(&text)?;

    let cfg: ConfigFile =
        toml::from_str(&expanded).with_context(|| format!("parse config {}", path.display()))?;

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Check for duplicate rule IDs
    let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for rule in &cfg.rule {
        if !seen_ids.insert(&rule.id) {
            errors.push(format!("Rule '{}': duplicate rule ID", rule.id));
        }
    }
    let known_rule_ids = cfg
        .rule
        .iter()
        .map(|r| r.id.as_str())
        .collect::<std::collections::HashSet<_>>();

    // Validate each rule
    for rule in &cfg.rule {
        debug!("Validating rule: {}", rule.id);

        // Check patterns are not empty
        if rule.patterns.is_empty() {
            errors.push(format!("Rule '{}': no patterns defined", rule.id));
            continue;
        }

        // Validate regex patterns
        for pattern in &rule.patterns {
            if let Err(e) = regex::Regex::new(pattern) {
                errors.push(format!(
                    "Rule '{}': invalid regex pattern '{}': {}",
                    rule.id, pattern, e
                ));
            }
        }
        for pattern in &rule.context_patterns {
            if let Err(e) = regex::Regex::new(pattern) {
                errors.push(format!(
                    "Rule '{}': invalid context pattern '{}': {}",
                    rule.id, pattern, e
                ));
            }
        }
        for pattern in &rule.escalate_patterns {
            if let Err(e) = regex::Regex::new(pattern) {
                errors.push(format!(
                    "Rule '{}': invalid escalation pattern '{}': {}",
                    rule.id, pattern, e
                ));
            }
        }

        if rule.multiline && rule.multiline_window.is_some_and(|window| window < 2) {
            errors.push(format!(
                "Rule '{}': multiline_window must be >= 2 when multiline=true",
                rule.id
            ));
        }

        for dependency in &rule.depends_on {
            if !known_rule_ids.contains(dependency.as_str()) {
                errors.push(format!(
                    "Rule '{}': unknown dependency '{}'",
                    rule.id, dependency
                ));
            }
        }

        // Validate path globs
        for glob in &rule.paths {
            if let Err(e) = globset::Glob::new(glob) {
                errors.push(format!(
                    "Rule '{}': invalid path glob '{}': {}",
                    rule.id, glob, e
                ));
            }
        }

        // Validate exclude_paths globs
        for glob in &rule.exclude_paths {
            if let Err(e) = globset::Glob::new(glob) {
                errors.push(format!(
                    "Rule '{}': invalid exclude_paths glob '{}': {}",
                    rule.id, glob, e
                ));
            }
        }

        // Strict mode: best-practice warnings
        if args.strict {
            if rule.message.is_empty() {
                warnings.push(format!("Rule '{}': empty message", rule.id));
            }
            if rule.help.is_none() {
                warnings.push(format!("Rule '{}': no help text provided", rule.id));
            }
            if rule.tags.is_empty() {
                warnings.push(format!("Rule '{}': no tags defined", rule.id));
            }
            if rule.paths.is_empty() && rule.languages.is_empty() {
                warnings.push(format!(
                    "Rule '{}': no path or language filters (applies to all files)",
                    rule.id
                ));
            }
        }
    }

    // Also try to compile all rules to catch any other issues
    if errors.is_empty() {
        if let Err(e) = compile_rules_checked(&cfg.rule) {
            errors.push(format!("Rule compilation error: {}", e));
        }
    }

    // Output results based on format
    match args.format {
        ValidateFormat::Json => {
            let result = serde_json::json!({
                "valid": errors.is_empty(),
                "path": path.display().to_string(),
                "rules_count": cfg.rule.len(),
                "errors": errors,
                "warnings": warnings,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ValidateFormat::Text => {
            println!("Validating {}...", path.display());
            println!();

            if !warnings.is_empty() {
                println!("Warnings ({}):", warnings.len());
                for (i, warn) in warnings.iter().enumerate() {
                    println!("  {}. {}", i + 1, warn);
                }
                println!();
            }

            if errors.is_empty() {
                println!("Configuration is valid!");
                println!("  {} rule(s) defined", cfg.rule.len());
            } else {
                println!("Configuration has {} error(s):", errors.len());
                println!();
                for (i, err) in errors.iter().enumerate() {
                    println!("  {}. {}", i + 1, err);
                }
            }
        }
    }

    if errors.is_empty() { Ok(0) } else { Ok(1) }
}

fn cmd_explain(args: ExplainArgs) -> Result<()> {
    let cfg = load_config(args.config, args.no_default_rules)?;

    // Find the rule by ID
    let rule = cfg.rule.iter().find(|r| r.id == args.rule_id);

    match rule {
        Some(r) => {
            print!("{}", format_rule_explanation(r));
            Ok(())
        }
        None => {
            // Rule not found - suggest similar rules
            let suggestions = find_similar_rules(&args.rule_id, &cfg.rule);
            let mut msg = format!("Rule '{}' not found.", args.rule_id);

            if !suggestions.is_empty() {
                msg.push_str("\n\nDid you mean one of these?\n");
                for s in &suggestions {
                    msg.push_str(&format!("  - {}\n", s));
                }
            }

            msg.push_str("\nUse 'diffguard rules' to list all available rules.");

            bail!("{}", msg);
        }
    }
}

/// Format rule explanation for display.
fn format_rule_explanation(rule: &RuleConfig) -> String {
    let mut out = String::new();

    out.push_str(&format!("Rule: {}\n", rule.id));
    out.push_str(&format!("Severity: {}\n", rule.severity.as_str()));
    out.push_str(&format!("Message: {}\n", rule.message));

    out.push_str("\nPatterns:\n");
    for p in &rule.patterns {
        out.push_str(&format!("  - {}\n", p));
    }

    out.push_str("\nSemantics:\n");
    let match_mode = match rule.match_mode {
        MatchMode::Any => "any",
        MatchMode::Absent => "absent",
    };
    out.push_str(&format!("  - Match mode: {match_mode}\n"));
    out.push_str(&format!(
        "  - Multiline: {}{}\n",
        if rule.multiline { "yes" } else { "no" },
        rule.multiline_window
            .map(|w| format!(" (window={w})"))
            .unwrap_or_default()
    ));
    if !rule.context_patterns.is_empty() {
        out.push_str(&format!(
            "  - Context patterns (window={}): {}\n",
            rule.context_window.unwrap_or(3),
            rule.context_patterns.join(", ")
        ));
    }
    if !rule.escalate_patterns.is_empty() {
        out.push_str(&format!(
            "  - Escalation to {} (window={}): {}\n",
            rule.escalate_to
                .unwrap_or(diffguard_types::Severity::Error)
                .as_str(),
            rule.escalate_window.unwrap_or(0),
            rule.escalate_patterns.join(", ")
        ));
    }
    if !rule.depends_on.is_empty() {
        out.push_str(&format!("  - Depends on: {}\n", rule.depends_on.join(", ")));
    }

    out.push_str("\nApplies to:\n");

    if !rule.languages.is_empty() {
        out.push_str(&format!("  - Languages: {}\n", rule.languages.join(", ")));
    }

    if !rule.paths.is_empty() {
        out.push_str(&format!("  - Paths: {}\n", rule.paths.join(", ")));
    }

    if !rule.exclude_paths.is_empty() {
        out.push_str(&format!(
            "  - Excludes: {}\n",
            rule.exclude_paths.join(", ")
        ));
    }

    out.push_str("\nPreprocessing:\n");
    out.push_str(&format!(
        "  - Ignore comments: {}\n",
        if rule.ignore_comments { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "  - Ignore strings: {}\n",
        if rule.ignore_strings { "yes" } else { "no" }
    ));

    if let Some(help) = &rule.help {
        out.push_str("\nRemediation:\n");
        for line in help.lines() {
            out.push_str(&format!("  {}\n", line));
        }
    }

    if let Some(url) = &rule.url {
        out.push_str(&format!("\nSee also: {}\n", url));
    }

    out
}

/// Find rules with similar IDs to the given rule_id.
fn find_similar_rules(rule_id: &str, rules: &[RuleConfig]) -> Vec<String> {
    let rule_id_lower = rule_id.to_lowercase();
    let mut candidates: Vec<(String, usize)> = Vec::new();

    for r in rules {
        let id_lower = r.id.to_lowercase();

        // Exact prefix match
        if id_lower.starts_with(&rule_id_lower) || rule_id_lower.starts_with(&id_lower) {
            candidates.push((r.id.clone(), 0));
            continue;
        }

        // Contains the search term
        if id_lower.contains(&rule_id_lower) || rule_id_lower.contains(&id_lower) {
            candidates.push((r.id.clone(), 1));
            continue;
        }

        // Simple Levenshtein-like distance for short strings
        let distance = simple_edit_distance(&rule_id_lower, &id_lower);
        if distance <= 3 {
            candidates.push((r.id.clone(), distance + 2));
        }
    }

    candidates.sort_by_key(|(_, score)| *score);
    candidates.truncate(5);
    candidates.into_iter().map(|(id, _)| id).collect()
}

/// Simple edit distance calculation.
fn simple_edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

/// Resolves the execution mode from CLI args and environment variable.
fn resolve_mode(args: &CheckArgs) -> Mode {
    std::env::var("DIFFGUARD_MODE")
        .ok()
        .and_then(|v| match v.to_lowercase().as_str() {
            "cockpit" => Some(Mode::Cockpit),
            "standard" => Some(Mode::Standard),
            _ => None,
        })
        .unwrap_or(args.mode)
}

/// Resolves the output path for the JSON receipt.
///
/// - If `--out` was explicitly provided, use that path.
/// - In cockpit mode when `--sensor` is active, default to `artifacts/diffguard/extras/check.json`
///   (the canonical `report.json` path is reserved for the sensor envelope).
/// - Otherwise, default to `artifacts/diffguard/report.json`.
fn resolve_out_path(args: &CheckArgs, mode: Mode) -> PathBuf {
    if let Some(ref out) = args.out {
        return out.clone();
    }
    match mode {
        Mode::Cockpit if args.sensor.is_some() => {
            PathBuf::from("artifacts/diffguard/extras/check.json")
        }
        _ => PathBuf::from("artifacts/diffguard/report.json"),
    }
}

/// Adjusts extras output paths for cockpit mode.
///
/// When `--sensor` is active (cockpit mode), the default paths for
/// `--sarif`, `--junit`, `--csv`, `--tsv`, `--rule-stats`,
/// `--write-false-positive-baseline`, and `--trend-history` are moved under
/// `artifacts/diffguard/extras/` to keep the top-level `artifacts/diffguard/`
/// clean for the bus (`report.json` + `comment.md` only).
///
/// Only adjusts paths that match the compile-time `default_missing_value`;
/// explicit user paths are left unchanged.
fn resolve_extras_paths(args: &mut CheckArgs, mode: Mode) {
    if !matches!(mode, Mode::Cockpit) || args.sensor.is_none() {
        return;
    }

    // (current default_missing_value, cockpit-mode default)
    let extras_defaults: &[(&str, &str)] = &[
        (
            "artifacts/diffguard/report.sarif.json",
            "artifacts/diffguard/extras/report.sarif.json",
        ),
        (
            "artifacts/diffguard/report.xml",
            "artifacts/diffguard/extras/report.xml",
        ),
        (
            "artifacts/diffguard/report.csv",
            "artifacts/diffguard/extras/report.csv",
        ),
        (
            "artifacts/diffguard/report.tsv",
            "artifacts/diffguard/extras/report.tsv",
        ),
        (
            "artifacts/diffguard/rule-stats.json",
            "artifacts/diffguard/extras/rule-stats.json",
        ),
        (
            "artifacts/diffguard/false-positives.json",
            "artifacts/diffguard/extras/false-positives.json",
        ),
        (
            "artifacts/diffguard/trend-history.json",
            "artifacts/diffguard/extras/trend-history.json",
        ),
    ];

    let fields: [&mut Option<PathBuf>; 7] = [
        &mut args.sarif,
        &mut args.junit,
        &mut args.csv,
        &mut args.tsv,
        &mut args.rule_stats,
        &mut args.write_false_positive_baseline,
        &mut args.trend_history,
    ];

    for (field, (standard_default, cockpit_default)) in
        fields.into_iter().zip(extras_defaults.iter())
    {
        if let Some(path) = field.as_ref() {
            if path == Path::new(standard_default) {
                *field = Some(PathBuf::from(cockpit_default));
            }
        }
    }
}

/// Builds rule metadata map from config for sensor report.
fn build_rule_metadata(cfg: &ConfigFile) -> HashMap<String, RuleMetadata> {
    cfg.rule
        .iter()
        .map(|r| {
            (
                r.id.clone(),
                RuleMetadata {
                    help: r.help.clone(),
                    url: r.url.clone(),
                    tags: r.tags.clone(),
                },
            )
        })
        .collect()
}

fn load_directory_overrides_for_diff(
    diff_text: &str,
    scope: Scope,
) -> Result<Vec<DirectoryRuleOverride>> {
    let (diff_lines, _) =
        parse_unified_diff(diff_text, scope).context("parse diff for directory overrides")?;

    let mut candidates = BTreeSet::<PathBuf>::new();
    for line in diff_lines {
        collect_override_candidates_for_path(&line.path, &mut candidates);
    }

    let mut candidate_paths: Vec<PathBuf> = candidates.into_iter().collect();
    candidate_paths.sort_by(|a, b| {
        let a_parent = a.parent().unwrap_or_else(|| Path::new(""));
        let b_parent = b.parent().unwrap_or_else(|| Path::new(""));
        directory_depth(a_parent)
            .cmp(&directory_depth(b_parent))
            .then_with(|| a.to_string_lossy().cmp(&b.to_string_lossy()))
    });

    let mut overrides = Vec::new();

    for override_path in candidate_paths {
        if !override_path.is_file() {
            continue;
        }

        let text = std::fs::read_to_string(&override_path).with_context(|| {
            format!("read directory override config {}", override_path.display())
        })?;
        let expanded = expand_env_vars(&text).with_context(|| {
            format!(
                "expand env vars in directory override config {}",
                override_path.display()
            )
        })?;

        let parsed: DirectoryOverrideConfig = toml::from_str(&expanded).with_context(|| {
            format!(
                "parse directory override config {}",
                override_path.display()
            )
        })?;

        let directory =
            normalize_override_directory(override_path.parent().unwrap_or_else(|| Path::new("")));

        for rule in parsed.rules {
            overrides.push(DirectoryRuleOverride {
                directory: directory.clone(),
                rule_id: rule.id,
                enabled: rule.enabled,
                severity: rule.severity,
                exclude_paths: rule.exclude_paths,
            });
        }
    }

    Ok(overrides)
}

fn collect_override_candidates_for_path(file_path: &str, out: &mut BTreeSet<PathBuf>) {
    let path = Path::new(file_path);
    let mut current = path.parent();

    if current.is_none() {
        out.insert(PathBuf::from(".diffguard.toml"));
        return;
    }

    while let Some(dir) = current {
        let mut candidate = PathBuf::new();
        if !dir.as_os_str().is_empty() {
            candidate.push(dir);
        }
        candidate.push(".diffguard.toml");
        out.insert(candidate);

        if dir.as_os_str().is_empty() {
            break;
        }
        current = dir.parent();
    }
}

fn normalize_override_directory(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn directory_depth(path: &Path) -> usize {
    path.components().count()
}

#[derive(Debug, Clone)]
struct BlameFilters {
    author_patterns: Vec<String>,
    max_age_days: Option<u32>,
}

impl BlameFilters {
    fn from_args(args: &CheckArgs) -> Option<Self> {
        let author_patterns: Vec<String> = args
            .blame_author
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        if author_patterns.is_empty() && args.blame_max_age_days.is_none() {
            return None;
        }

        Some(Self {
            author_patterns,
            max_age_days: args.blame_max_age_days,
        })
    }

    fn matches(&self, line: &BlameLineMeta, now_unix_seconds: i64) -> bool {
        if !self.author_patterns.is_empty() {
            let haystack = format!(
                "{} {}",
                line.author.to_ascii_lowercase(),
                line.author_mail.to_ascii_lowercase()
            );
            if !self
                .author_patterns
                .iter()
                .any(|pattern| haystack.contains(pattern))
            {
                return false;
            }
        }

        if let Some(max_age_days) = self.max_age_days {
            if line.author_time <= 0 {
                return false;
            }
            let age_seconds = now_unix_seconds.saturating_sub(line.author_time).max(0);
            let age_days = age_seconds / 86_400;
            if age_days > i64::from(max_age_days) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Default)]
struct BlameLineMeta {
    author: String,
    author_mail: String,
    author_time: i64,
}

fn load_false_positive_baseline(path: &Path) -> Result<FalsePositiveBaseline> {
    if !path.exists() {
        return Ok(FalsePositiveBaseline::default());
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read false-positive baseline {}", path.display()))?;
    let baseline: FalsePositiveBaseline = serde_json::from_str(&text)
        .with_context(|| format!("parse false-positive baseline {}", path.display()))?;
    let baseline = normalize_false_positive_baseline(baseline);
    if baseline.schema != FALSE_POSITIVE_BASELINE_SCHEMA_V1 {
        bail!(
            "unsupported false-positive baseline schema '{}'; expected '{}'",
            baseline.schema,
            FALSE_POSITIVE_BASELINE_SCHEMA_V1
        );
    }
    Ok(baseline)
}

fn load_trend_history(path: &Path) -> Result<TrendHistory> {
    if !path.exists() {
        return Ok(TrendHistory::default());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read trend history {}", path.display()))?;
    let history: TrendHistory = serde_json::from_str(&text)
        .with_context(|| format!("parse trend history {}", path.display()))?;
    let history = normalize_trend_history(history);
    if history.schema != TREND_HISTORY_SCHEMA_V1 {
        bail!(
            "unsupported trend history schema '{}'; expected '{}'",
            history.schema,
            TREND_HISTORY_SCHEMA_V1
        );
    }
    Ok(history)
}

fn parse_blame_porcelain(blame_text: &str) -> Result<BTreeMap<u32, BlameLineMeta>> {
    let mut out = BTreeMap::<u32, BlameLineMeta>::new();
    let lines: Vec<&str> = blame_text.lines().collect();
    let mut idx = 0usize;

    while idx < lines.len() {
        let header = lines[idx];
        let header_parts: Vec<&str> = header.split_whitespace().collect();
        if header_parts.len() < 4 {
            idx += 1;
            continue;
        }

        let final_line = match header_parts[2].parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                idx += 1;
                continue;
            }
        };
        let group_lines = header_parts[3].parse::<u32>().unwrap_or(1);

        idx += 1;
        let mut meta = BlameLineMeta::default();
        let mut found_source_line = false;

        while idx < lines.len() {
            let row = lines[idx];
            if row.starts_with('\t') {
                found_source_line = true;
                idx += 1;
                break;
            }
            if let Some(v) = row.strip_prefix("author ") {
                meta.author = v.to_string();
            } else if let Some(v) = row.strip_prefix("author-mail ") {
                meta.author_mail = v.trim_matches('<').trim_matches('>').to_string();
            } else if let Some(v) = row.strip_prefix("author-time ") {
                meta.author_time = v.parse::<i64>().unwrap_or(0);
            }
            idx += 1;
        }

        if found_source_line {
            for offset in 0..group_lines {
                out.insert(final_line.saturating_add(offset), meta.clone());
            }
        }
    }

    Ok(out)
}

fn git_blame_porcelain(head_ref: &str, path: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["blame", "--line-porcelain", head_ref, "--", path])
        .output()
        .with_context(|| format!("run git blame for {}", path))?;

    if !output.status.success() {
        bail!(
            "git blame failed for '{}' at '{}': {}",
            path,
            head_ref,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn collect_blame_allowed_lines(
    diff_text: &str,
    scope: Scope,
    head_ref: &str,
    filters: &BlameFilters,
) -> Result<BTreeSet<(String, u32)>> {
    let (diff_lines, _) =
        parse_unified_diff(diff_text, scope).context("parse diff for blame filtering")?;

    let mut lines_by_path = BTreeMap::<String, BTreeSet<u32>>::new();
    for line in diff_lines {
        lines_by_path
            .entry(line.path)
            .or_default()
            .insert(line.line);
    }

    let now = Utc::now().timestamp();
    let mut allowed = BTreeSet::<(String, u32)>::new();

    for (path, lines) in lines_by_path {
        let blame_text = git_blame_porcelain(head_ref, &path)?;
        let blame_map = parse_blame_porcelain(&blame_text)
            .with_context(|| format!("parse git blame for {}", path))?;
        for line in lines {
            let Some(meta) = blame_map.get(&line) else {
                continue;
            };
            if filters.matches(meta, now) {
                allowed.insert((path.clone(), line));
            }
        }
    }

    Ok(allowed)
}

fn maybe_force_sensor_json_error() -> Option<serde_json::Error> {
    if cfg!(test) && std::env::var("DIFFGUARD_TEST_FORCE_SENSOR_JSON_ERROR").is_ok() {
        Some(<serde_json::Error as serde::ser::Error>::custom(
            "forced sensor json error",
        ))
    } else {
        None
    }
}

fn render_sensor_json_checked(
    receipt: &CheckReceipt,
    ctx: &SensorReportContext,
) -> Result<String, serde_json::Error> {
    if let Some(err) = maybe_force_sensor_json_error() {
        return Err(err);
    }
    render_sensor_json(receipt, ctx)
}

fn serialize_sensor_report_checked(
    report: &diffguard_types::SensorReport,
) -> Result<String, serde_json::Error> {
    if let Some(err) = maybe_force_sensor_json_error() {
        return Err(err);
    }
    serde_json::to_string_pretty(report)
}

fn cmd_check(mut args: CheckArgs) -> Result<i32> {
    let mode = resolve_mode(&args);
    resolve_extras_paths(&mut args, mode);
    let out_path = resolve_out_path(&args, mode);

    // Start timing
    let started_at = Utc::now();
    let start_time = Instant::now();

    // In cockpit mode, wrap everything in error handling
    let result = cmd_check_inner(&args, mode, &started_at, &out_path);

    // End timing
    let ended_at = Utc::now();
    let duration_ms = start_time.elapsed().as_millis() as u64;

    match mode {
        Mode::Standard => {
            // Standard mode: propagate errors and use normal exit codes
            let exit_code = result?;
            Ok(exit_code)
        }
        Mode::Cockpit => {
            // Cockpit mode: always try to write a receipt, exit 0 if successful
            match result {
                Ok(_exit_code) => {
                    // Check ran successfully, exit 0 (receipt was written)
                    Ok(0)
                }
                Err(err) => {
                    // Classify the error to determine skip vs fail
                    match classify_cockpit_error(&err) {
                        Some(reason_token) => {
                            // Known prerequisite-missing error → skip receipt
                            let detail = cockpit_error_detail(&err);
                            let skip_receipt = build_skip_receipt(&args, reason_token, &detail);
                            let mut capabilities = HashMap::new();
                            capabilities.insert(
                                CAP_GIT.to_string(),
                                CapabilityStatus {
                                    status: CAP_STATUS_UNAVAILABLE.to_string(),
                                    reason: Some(reason_token.to_string()),
                                    detail: Some(detail.clone()),
                                },
                            );

                            let ctx = SensorReportContext {
                                started_at: started_at.to_rfc3339(),
                                ended_at: ended_at.to_rfc3339(),
                                duration_ms,
                                capabilities,
                                artifacts: vec![],
                                rule_metadata: HashMap::new(),
                                truncated_count: 0,
                                rules_total: 0,
                            };

                            // Try to write the sensor report
                            if let Some(sensor_path) = &args.sensor {
                                if let Ok(json) = render_sensor_json_checked(&skip_receipt, &ctx) {
                                    if write_text(sensor_path, &json).is_ok() {
                                        eprintln!("diffguard: check skipped: {detail}");
                                        return Ok(0);
                                    }
                                }
                            }

                            // Also write the regular receipt
                            if write_json(&out_path, &skip_receipt).is_ok() {
                                eprintln!("diffguard: check skipped: {detail}");
                                return Ok(0);
                            }
                        }
                        None => {
                            // Unexpected runtime error → fail receipt with tool_error
                            let detail = err.to_string();
                            let fail_receipt = build_tool_error_receipt(&args, &detail);

                            let ctx = build_tool_error_sensor_context(
                                &started_at,
                                &ended_at,
                                duration_ms,
                                &detail,
                            );

                            // Try to write the sensor report
                            if let Some(sensor_path) = &args.sensor {
                                let sensor_report =
                                    build_tool_error_sensor_report(&args, &detail, &ctx);
                                if let Ok(json) = serialize_sensor_report_checked(&sensor_report) {
                                    if write_text(sensor_path, &json).is_ok() {
                                        eprintln!("diffguard: tool error: {detail}");
                                        return Ok(0);
                                    }
                                }
                            }

                            // Also write the regular receipt
                            if write_json(&out_path, &fail_receipt).is_ok() {
                                eprintln!("diffguard: tool error: {detail}");
                                return Ok(0);
                            }
                        }
                    }

                    // Could not write any receipt - catastrophic failure
                    eprintln!("diffguard: catastrophic failure: {err}");
                    Ok(1)
                }
            }
        }
    }
}

/// Typed error for cockpit skip classification.
///
/// Wraps both a reason token and the source error via `.map_err()`,
/// so `downcast_ref` reliably finds the token.
#[derive(Debug)]
struct CockpitSkipError {
    token: &'static str,
    source: anyhow::Error,
}

impl std::fmt::Display for CockpitSkipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}

impl std::error::Error for CockpitSkipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Checks if the error is a `CockpitSkipError` and returns
/// the reason token if found. Walks the full anyhow error chain so that
/// additional `.context(...)` layers above the `CockpitSkipError` don't
/// hide it. Untagged errors are treated as tool errors.
fn classify_cockpit_error(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<CockpitSkipError>())
        .map(|e| e.token)
}

/// Extracts the original error detail from a `CockpitSkipError`.
/// Walks the full anyhow error chain so that additional `.context(...)`
/// layers above the `CockpitSkipError` don't hide it.
fn cockpit_error_detail(err: &anyhow::Error) -> String {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<CockpitSkipError>())
        .map(|e| e.source.to_string())
        .unwrap_or_else(|| err.to_string())
}

fn render_base_refs(bases: &[String]) -> String {
    match bases {
        [] => "origin/main".to_string(),
        [single] => single.clone(),
        _ => bases.join(","),
    }
}

/// Builds a fail receipt for tool/runtime errors in cockpit mode.
fn build_tool_error_receipt(args: &CheckArgs, detail: &str) -> CheckReceipt {
    let base = render_base_refs(&args.base);
    let head = args.head.clone().unwrap_or_else(|| "HEAD".to_string());

    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        diff: DiffMeta {
            base,
            head,
            context_lines: args.diff_context.unwrap_or(0),
            scope: args.scope.map(Into::into).unwrap_or(Scope::Added),
            files_scanned: 0,
            lines_scanned: 0,
        },
        findings: vec![diffguard_types::Finding {
            rule_id: CHECK_ID_INTERNAL.to_string(),
            severity: diffguard_types::Severity::Error,
            message: detail.to_string(),
            path: String::new(),
            line: 0,
            column: None,
            match_text: String::new(),
            snippet: String::new(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                error: 1,
                ..VerdictCounts::default()
            },
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        timing: None,
    }
}

/// Builds the SensorReportContext for a tool error.
fn build_tool_error_sensor_context(
    started_at: &chrono::DateTime<Utc>,
    ended_at: &chrono::DateTime<Utc>,
    duration_ms: u64,
    detail: &str,
) -> SensorReportContext {
    let mut capabilities = HashMap::new();
    capabilities.insert(
        CAP_GIT.to_string(),
        CapabilityStatus {
            status: CAP_STATUS_UNAVAILABLE.to_string(),
            reason: Some(REASON_TOOL_ERROR.to_string()),
            detail: Some(detail.to_string()),
        },
    );
    SensorReportContext {
        started_at: started_at.to_rfc3339(),
        ended_at: ended_at.to_rfc3339(),
        duration_ms,
        capabilities,
        artifacts: vec![],
        rule_metadata: HashMap::new(),
        truncated_count: 0,
        rules_total: 0,
    }
}

/// Builds a sensor.report.v1 directly for tool errors (without going through
/// the normal render pipeline, since the error may have prevented check setup).
fn build_tool_error_sensor_report(
    args: &CheckArgs,
    detail: &str,
    ctx: &SensorReportContext,
) -> diffguard_types::SensorReport {
    use diffguard_core::compute_fingerprint_raw;

    let base = render_base_refs(&args.base);
    let head = args.head.clone().unwrap_or_else(|| "HEAD".to_string());

    let fingerprint_input = format!("{CHECK_ID_INTERNAL}:{CODE_TOOL_RUNTIME_ERROR}:{detail}");
    let fingerprint = compute_fingerprint_raw(&fingerprint_input);

    diffguard_types::SensorReport {
        schema: diffguard_types::SENSOR_REPORT_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        run: diffguard_types::RunMeta {
            started_at: ctx.started_at.clone(),
            ended_at: ctx.ended_at.clone(),
            duration_ms: ctx.duration_ms,
            capabilities: ctx.capabilities.clone(),
        },

        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                error: 1,
                ..VerdictCounts::default()
            },
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        findings: vec![diffguard_types::SensorFinding {
            check_id: CHECK_ID_INTERNAL.to_string(),
            code: CODE_TOOL_RUNTIME_ERROR.to_string(),
            severity: diffguard_types::Severity::Error,
            message: detail.to_string(),
            location: diffguard_types::SensorLocation {
                path: String::new(),
                line: 0,
                column: None,
            },
            fingerprint,
            help: None,
            url: None,
            data: Some(serde_json::json!({
                "error": detail,
            })),
        }],
        artifacts: vec![],
        data: Some(serde_json::json!({
            "diff": {
                "base": base,
                "head": head,
            }
        })),
    }
}

/// Builds a skip receipt when the check cannot run due to missing prerequisites.
fn build_skip_receipt(args: &CheckArgs, reason_token: &str, _detail: &str) -> CheckReceipt {
    let base = render_base_refs(&args.base);
    let head = args.head.clone().unwrap_or_else(|| "HEAD".to_string());

    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        diff: DiffMeta {
            base,
            head,
            context_lines: args.diff_context.unwrap_or(0),
            scope: args.scope.map(Into::into).unwrap_or(Scope::Added),
            files_scanned: 0,
            lines_scanned: 0,
        },
        findings: vec![],
        verdict: Verdict {
            status: VerdictStatus::Skip,
            counts: VerdictCounts::default(),
            reasons: vec![reason_token.to_string()],
        },
        timing: None,
    }
}

/// Inner check function that does the actual work.
fn cmd_check_inner(
    args: &CheckArgs,
    _mode: Mode,
    started_at: &chrono::DateTime<Utc>,
    out_path: &Path,
) -> Result<i32> {
    info!("Starting diffguard check");

    let cfg = load_config(args.config.clone(), args.no_default_rules)?;

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

    // Log language override if specified
    if let Some(lang) = &args.language {
        info!("Language override: {}", lang.as_str());
    }

    debug!(
        "Check parameters: scope={:?}, fail_on={:?}, max_findings={}, diff_context={}",
        scope, fail_on, max_findings, diff_context
    );

    let forced_language = args.language.map(LanguageArg::as_str).map(str::to_string);

    if args.trend_max_runs.is_some_and(|v| v == 0) {
        bail!("--trend-max-runs must be >= 1");
    }

    let false_positive_fingerprints = if let Some(baseline_path) = &args.false_positive_baseline {
        let baseline = load_false_positive_baseline(baseline_path)?;
        let fingerprints = false_positive_fingerprint_set(&baseline);
        info!(
            "Loaded {} false-positive fingerprints from {}",
            fingerprints.len(),
            baseline_path.display()
        );
        fingerprints
    } else {
        BTreeSet::new()
    };

    let blame_filters = BlameFilters::from_args(args);

    // Handle --staged / --diff-file / base-head modes
    let (base, head, diff_text) = if args.staged {
        info!("Checking staged changes");
        let diff_text = git_staged_diff(diff_context).map_err(|e| {
            anyhow::Error::new(CockpitSkipError {
                token: REASON_NO_DIFF_INPUT,
                source: e,
            })
        })?;
        ("(staged)".to_string(), "HEAD".to_string(), diff_text)
    } else if let Some(diff_file) = &args.diff_file {
        let diff_text = if diff_file == Path::new("-") {
            info!("Reading unified diff from stdin");
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).map_err(|e| {
                anyhow::Error::new(CockpitSkipError {
                    token: REASON_NO_DIFF_INPUT,
                    source: e.into(),
                })
            })?;
            buf
        } else {
            info!("Reading unified diff from file: {}", diff_file.display());
            std::fs::read_to_string(diff_file).map_err(|e| {
                anyhow::Error::new(CockpitSkipError {
                    token: REASON_NO_DIFF_INPUT,
                    source: e.into(),
                })
            })?
        };

        let head = args
            .head
            .clone()
            .or_else(|| cfg.defaults.head.clone())
            .unwrap_or_else(|| "HEAD".to_string());

        let base = if diff_file == Path::new("-") {
            "(stdin)".to_string()
        } else {
            format!("(file:{})", diff_file.display())
        };

        (base, head, diff_text)
    } else {
        // Merge defaults (CLI overrides config).
        let bases = if args.base.is_empty() {
            vec![
                cfg.defaults
                    .base
                    .clone()
                    .unwrap_or_else(|| "origin/main".to_string()),
            ]
        } else {
            args.base.clone()
        };

        let head = args
            .head
            .clone()
            .or_else(|| cfg.defaults.head.clone())
            .unwrap_or_else(|| "HEAD".to_string());

        if bases.len() > 1 {
            info!(
                "Checking multi-base diff against {} base refs: {}",
                bases.len(),
                bases.join(", ")
            );
        }

        let mut diff_parts = Vec::with_capacity(bases.len());
        for base in &bases {
            info!("Checking diff: {}...{}", base, head);
            let diff = git_diff(base, &head, diff_context).map_err(|e| {
                anyhow::Error::new(CockpitSkipError {
                    token: REASON_MISSING_BASE,
                    source: e,
                })
            })?;
            diff_parts.push(diff);
        }

        let diff_text = diff_parts.join("\n");
        (render_base_refs(&bases), head, diff_text)
    };

    debug!("Diff text length: {} bytes", diff_text.len());

    let allowed_lines = if let Some(filters) = &blame_filters {
        if args.diff_file.is_some() {
            bail!("blame-aware filters are not supported with --diff-file");
        }
        if args.staged {
            bail!("blame-aware filters are not supported with --staged");
        }
        if matches!(scope, Scope::Deleted) {
            bail!("blame-aware filters are not supported with --scope deleted");
        }

        let allowed = collect_blame_allowed_lines(&diff_text, scope, &head, filters)?;
        info!("Blame filter retained {} scoped line(s)", allowed.len());
        Some(allowed)
    } else {
        None
    };

    let directory_overrides = load_directory_overrides_for_diff(&diff_text, scope)?;
    if !directory_overrides.is_empty() {
        info!(
            "Loaded {} per-directory override(s)",
            directory_overrides.len()
        );
    }

    let plan = CheckPlan {
        base: base.clone(),
        head: head.clone(),
        scope,
        diff_context,
        fail_on,
        max_findings,
        path_filters: args.paths.clone(),
        only_tags: args.only_tags.clone(),
        enable_tags: args.enable_tags.clone(),
        disable_tags: args.disable_tags.clone(),
        directory_overrides,
        force_language: forced_language,
        allowed_lines,
        false_positive_fingerprints,
    };

    let run = run_check(&plan, &cfg, &diff_text)?;

    info!(
        "Check complete: {} findings, {} false-positive filtered, verdict={:?}",
        run.receipt.findings.len(),
        run.false_positive_findings,
        run.receipt.verdict.status
    );

    let cwd = std::env::current_dir().ok();
    let to_artifact_path = |path: &Path| {
        let rel = match cwd.as_ref() {
            Some(cwd) if path.is_absolute() => path.strip_prefix(cwd).unwrap_or(path),
            _ => path,
        };
        rel.to_string_lossy().replace('\\', "/")
    };

    // Collect artifacts
    let mut artifacts = vec![Artifact {
        path: to_artifact_path(out_path),
        format: "json".to_string(),
    }];

    write_json(out_path, &run.receipt)?;

    if let Some(md_path) = &args.md {
        write_text(md_path, &run.markdown)?;
        artifacts.push(Artifact {
            path: to_artifact_path(md_path),
            format: "markdown".to_string(),
        });
    }

    if args.github_annotations {
        for line in &run.annotations {
            println!("{line}");
        }
    }

    if let Some(sarif_path) = &args.sarif {
        let sarif = render_sarif_json(&run.receipt).context("render SARIF")?;
        write_text(sarif_path, &sarif)?;
        artifacts.push(Artifact {
            path: to_artifact_path(sarif_path),
            format: "sarif".to_string(),
        });
    }

    if let Some(junit_path) = &args.junit {
        let junit = render_junit_for_receipt(&run.receipt);
        write_text(junit_path, &junit)?;
        artifacts.push(Artifact {
            path: to_artifact_path(junit_path),
            format: "junit".to_string(),
        });
    }

    if let Some(csv_path) = &args.csv {
        let csv = render_csv_for_receipt(&run.receipt);
        write_text(csv_path, &csv)?;
        artifacts.push(Artifact {
            path: to_artifact_path(csv_path),
            format: "csv".to_string(),
        });
    }

    if let Some(tsv_path) = &args.tsv {
        let tsv = render_tsv_for_receipt(&run.receipt);
        write_text(tsv_path, &tsv)?;
        artifacts.push(Artifact {
            path: to_artifact_path(tsv_path),
            format: "tsv".to_string(),
        });
    }

    if let Some(rule_stats_path) = &args.rule_stats {
        let stats_rows: Vec<_> = run
            .rule_hits
            .iter()
            .map(|s| {
                serde_json::json!({
                    "rule_id": s.rule_id,
                    "total": s.total,
                    "emitted": s.emitted,
                    "suppressed": s.suppressed,
                    "false_positive": s.false_positive,
                    "counts": {
                        "info": s.info,
                        "warn": s.warn,
                        "error": s.error,
                    }
                })
            })
            .collect();
        let stats_json =
            serde_json::to_string_pretty(&stats_rows).context("serialize rule hit statistics")?;
        write_text(rule_stats_path, &stats_json)?;
        artifacts.push(Artifact {
            path: to_artifact_path(rule_stats_path),
            format: "json".to_string(),
        });
    }

    let ended_at = Utc::now();
    let duration_ms = (ended_at - *started_at).num_milliseconds().max(0) as u64;

    if let Some(write_baseline_path) = &args.write_false_positive_baseline {
        let generated = baseline_from_receipt(&run.receipt);
        let merged = if write_baseline_path.exists() {
            let existing = load_false_positive_baseline(write_baseline_path)?;
            merge_false_positive_baselines(&existing, &generated)
        } else {
            generated
        };
        write_json(write_baseline_path, &merged)?;
        artifacts.push(Artifact {
            path: to_artifact_path(write_baseline_path),
            format: "json".to_string(),
        });
        info!(
            "Wrote false-positive baseline with {} entries to {}",
            merged.entries.len(),
            write_baseline_path.display()
        );
    }

    if let Some(trend_history_path) = &args.trend_history {
        let history = load_trend_history(trend_history_path)?;
        let run_sample = trend_run_from_receipt(
            &run.receipt,
            &started_at.to_rfc3339(),
            &ended_at.to_rfc3339(),
            duration_ms,
        );
        let updated = append_trend_run(history, run_sample, args.trend_max_runs);
        write_json(trend_history_path, &updated)?;
        artifacts.push(Artifact {
            path: to_artifact_path(trend_history_path),
            format: "json".to_string(),
        });
        info!(
            "Updated trend history to {} run(s) at {}",
            updated.runs.len(),
            trend_history_path.display()
        );
    }

    // Write sensor report if requested
    if let Some(sensor_path) = &args.sensor {
        let mut capabilities = HashMap::new();
        capabilities.insert(
            CAP_GIT.to_string(),
            CapabilityStatus {
                status: CAP_STATUS_AVAILABLE.to_string(),
                reason: None,
                detail: None,
            },
        );

        artifacts.push(Artifact {
            path: to_artifact_path(sensor_path),
            format: "json".to_string(),
        });

        let ctx = SensorReportContext {
            started_at: started_at.to_rfc3339(),
            ended_at: ended_at.to_rfc3339(),
            duration_ms,
            capabilities,
            artifacts,
            rule_metadata: build_rule_metadata(&cfg),
            truncated_count: run.truncated_findings,
            rules_total: run.rules_evaluated,
        };

        let sensor_json = render_sensor_json(&run.receipt, &ctx).context("render sensor report")?;
        write_text(sensor_path, &sensor_json)?;
    }

    Ok(run.exit_code)
}

fn cmd_sarif(args: SarifArgs) -> Result<()> {
    let receipt_text = std::fs::read_to_string(&args.report)
        .with_context(|| format!("read report {}", args.report.display()))?;

    let receipt: CheckReceipt = serde_json::from_str(&receipt_text)
        .with_context(|| format!("parse report {}", args.report.display()))?;

    let sarif = render_sarif_json(&receipt).context("render SARIF")?;

    match args.output {
        Some(path) => write_text(&path, &sarif)?,
        None => print!("{sarif}"),
    }

    Ok(())
}

fn cmd_junit(args: JunitArgs) -> Result<()> {
    let receipt_text = std::fs::read_to_string(&args.report)
        .with_context(|| format!("read report {}", args.report.display()))?;

    let receipt: CheckReceipt = serde_json::from_str(&receipt_text)
        .with_context(|| format!("parse report {}", args.report.display()))?;

    let junit = render_junit_for_receipt(&receipt);

    match args.output {
        Some(path) => write_text(&path, &junit)?,
        None => print!("{junit}"),
    }

    Ok(())
}

fn cmd_csv(args: CsvArgs) -> Result<()> {
    let receipt_text = std::fs::read_to_string(&args.report)
        .with_context(|| format!("read report {}", args.report.display()))?;

    let receipt: CheckReceipt = serde_json::from_str(&receipt_text)
        .with_context(|| format!("parse report {}", args.report.display()))?;

    let output = if args.tsv {
        render_tsv_for_receipt(&receipt)
    } else {
        render_csv_for_receipt(&receipt)
    };

    match args.output {
        Some(path) => write_text(&path, &output)?,
        None => print!("{output}"),
    }

    Ok(())
}

fn cmd_trend(args: TrendArgs) -> Result<()> {
    let history = load_trend_history(&args.history)?;
    let summary = summarize_trend_history(&history);

    match args.format {
        TrendFormat::Json => {
            let value = serde_json::json!({
                "history": history,
                "summary": summary,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        TrendFormat::Text => {
            println!("Trend history: {}", args.history.display());
            println!("Runs: {}", summary.run_count);
            println!(
                "Totals: findings={}, info={}, warn={}, error={}, suppressed={}",
                summary.total_findings,
                summary.totals.info,
                summary.totals.warn,
                summary.totals.error,
                summary.totals.suppressed
            );

            if let Some(latest) = summary.latest {
                println!(
                    "Latest: status={:?}, findings={}, base={}, head={}, ended_at={}",
                    latest.status, latest.findings, latest.base, latest.head, latest.ended_at
                );
            }
            if let Some(delta) = summary.delta_from_previous {
                println!(
                    "Delta: findings={:+}, info={:+}, warn={:+}, error={:+}, suppressed={:+}",
                    delta.findings, delta.info, delta.warn, delta.error, delta.suppressed
                );
            }
        }
    }

    Ok(())
}

fn confirm_overwrite<R: BufRead, W: Write>(
    input: &mut R,
    mut err: W,
    output_path: &Path,
) -> Result<bool> {
    eprint!(
        "Configuration file '{}' already exists. Overwrite? [y/N] ",
        output_path.display()
    );
    err.flush().context("flush stderr")?;

    let mut input_line = String::new();
    input.read_line(&mut input_line).context("read stdin")?;

    let input = input_line.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

fn cmd_init(args: InitArgs) -> Result<()> {
    let mut input = io::stdin().lock();
    cmd_init_with_io(args, &mut input, io::stderr())
}

fn cmd_init_with_io<R: BufRead, W: Write>(args: InitArgs, input: &mut R, err: W) -> Result<()> {
    let output_path = &args.output;

    // Check if file already exists
    if output_path.exists() && !args.force && !confirm_overwrite(input, err, output_path)? {
        println!("Aborted.");
        return Ok(());
    }

    // Generate the preset content
    let content = args.preset.generate();

    // Write the configuration file
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }

    std::fs::write(output_path, &content)
        .with_context(|| format!("write {}", output_path.display()))?;

    // Print success message
    println!(
        "Created {} with '{}' preset.",
        output_path.display(),
        args.preset.name()
    );
    println!();
    println!("Next steps:");
    println!(
        "  1. Review and customize the rules in {}",
        output_path.display()
    );
    println!("  2. Run 'diffguard check' to lint your changes");
    println!();
    println!("Available presets:");
    println!("  - minimal       Minimal starter configuration");
    println!("  - rust-quality  Rust best practices");
    println!("  - secrets       Secret/credential detection");
    println!("  - js-console    JavaScript/TypeScript debugging");
    println!("  - python-debug  Python debugging");
    println!();
    println!("To use a different preset, run:");
    println!("  diffguard init --preset <PRESET> --force");

    Ok(())
}

fn cmd_test(args: TestArgs) -> Result<i32> {
    info!("Running rule test cases");

    let cfg = load_config(args.config.clone(), args.no_default_rules)?;

    // Filter rules if --rule is specified
    let rules: Vec<_> = if let Some(ref rule_filter) = args.rule {
        cfg.rule
            .iter()
            .filter(|r| r.id.starts_with(rule_filter) || r.id == *rule_filter)
            .collect()
    } else {
        cfg.rule.iter().collect()
    };

    if rules.is_empty() {
        if let Some(filter) = &args.rule {
            bail!("No rules match filter '{}'", filter);
        } else {
            bail!("No rules defined in configuration");
        }
    }

    // Count total test cases
    let total_tests: usize = rules.iter().map(|r| r.test_cases.len()).sum();

    if total_tests == 0 {
        match args.format {
            TestFormat::Json => {
                let result = serde_json::json!({
                    "rules_checked": rules.len(),
                    "test_cases": 0,
                    "passed": 0,
                    "failed": 0,
                    "message": "No test cases defined"
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            TestFormat::Text => {
                println!("No test cases defined in {} rule(s).", rules.len());
                println!("\nTo add test cases, add them to your rule definitions:");
                println!("  [[rule]]");
                println!("  id = \"my.rule\"");
                println!("  patterns = [\"pattern\"]");
                println!("  ...");
                println!("  [[rule.test_cases]]");
                println!("  input = \"code that should match\"");
                println!("  should_match = true");
            }
        }
        return Ok(0);
    }

    let mut passed = 0;
    let mut failed = 0;
    let mut failures: Vec<serde_json::Value> = Vec::new();

    for rule in &rules {
        if rule.test_cases.is_empty() {
            continue;
        }

        // Compile the rule
        let compiled = match compile_rules(std::slice::from_ref(*rule)) {
            Ok(c) => c,
            Err(e) => {
                for tc in &rule.test_cases {
                    failed += 1;
                    failures.push(serde_json::json!({
                        "rule_id": rule.id,
                        "input": tc.input,
                        "error": format!("Rule compilation failed: {}", e),
                    }));
                }
                continue;
            }
        };

        let compiled_rule = &compiled[0];

        for tc in &rule.test_cases {
            // Check if any pattern matches the input
            let matches = compiled_rule.patterns.iter().any(|p| p.is_match(&tc.input));

            if matches == tc.should_match {
                passed += 1;
            } else {
                failed += 1;
                failures.push(serde_json::json!({
                    "rule_id": rule.id,
                    "input": tc.input,
                    "should_match": tc.should_match,
                    "actual_match": matches,
                    "description": tc.description,
                }));
            }
        }
    }

    // Output results
    match args.format {
        TestFormat::Json => {
            let result = serde_json::json!({
                "rules_checked": rules.len(),
                "test_cases": total_tests,
                "passed": passed,
                "failed": failed,
                "failures": failures,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        TestFormat::Text => {
            println!("Rule tests:");
            println!("  Rules checked: {}", rules.len());
            println!("  Test cases: {}", total_tests);
            println!("  Passed: {}", passed);
            println!("  Failed: {}", failed);

            if !failures.is_empty() {
                println!("\nFailures:");
                for (i, f) in failures.iter().enumerate() {
                    println!(
                        "\n  {}. Rule '{}': input \"{}\"",
                        i + 1,
                        f["rule_id"].as_str().unwrap_or(""),
                        f["input"].as_str().unwrap_or("")
                    );
                    if let Some(desc) = f["description"].as_str() {
                        if !desc.is_empty() {
                            println!("     Description: {}", desc);
                        }
                    }
                    if let Some(err) = f["error"].as_str() {
                        println!("     Error: {}", err);
                    } else {
                        println!(
                            "     Expected match: {}, got: {}",
                            f["should_match"], f["actual_match"]
                        );
                    }
                }
            }
        }
    }

    if failed > 0 { Ok(1) } else { Ok(0) }
}

fn load_config(path: Option<PathBuf>, no_default_rules: bool) -> Result<ConfigFile> {
    let user_path = path.or_else(|| {
        let p = PathBuf::from("diffguard.toml");
        if p.exists() { Some(p) } else { None }
    });

    let Some(path) = user_path else {
        debug!("No config file found, using built-in rules");
        return Ok(ConfigFile::built_in());
    };

    info!("Loading config from: {}", path.display());

    // Use config_loader to handle includes
    let parsed = load_config_with_includes(&path, expand_env_vars)?;

    debug!("Loaded {} rule(s) from config", parsed.rule.len());

    if no_default_rules {
        return Ok(parsed);
    }

    Ok(merge_with_built_in(parsed))
}

/// Expand environment variables in a string.
///
/// Supports two syntaxes:
/// - `${VAR}` - expands to the value of VAR, errors if not set
/// - `${VAR:-default}` - expands to the value of VAR, or "default" if not set
///
/// # Examples
///
/// ```ignore
/// assert_eq!(expand_env_vars("hello ${USER}")?, "hello alice");
/// assert_eq!(expand_env_vars("port ${PORT:-8080}")?, "port 8080"); // if PORT not set
/// ```
fn expand_env_vars(content: &str) -> Result<String> {
    use regex::Regex;

    // Match ${VAR} or ${VAR:-default}
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
        .expect("env var regex should compile");

    let mut result = String::with_capacity(content.len());
    let mut last_end = 0;

    for cap in re.captures_iter(content) {
        let full_match = cap.get(0).unwrap();
        let var_name = cap.get(1).unwrap().as_str();
        let default_value = cap.get(2).map(|m| m.as_str());

        // Append text before this match
        result.push_str(&content[last_end..full_match.start()]);

        // Look up the environment variable
        match std::env::var(var_name) {
            Ok(value) => {
                debug!("Expanded env var ${{{}}}", var_name);
                result.push_str(&value);
            }
            Err(_) => {
                if let Some(default) = default_value {
                    debug!(
                        "Env var ${{{0}}} not set, using default: {1}",
                        var_name, default
                    );
                    result.push_str(default);
                } else {
                    bail!(
                        "Environment variable '{}' is not set and no default provided",
                        var_name
                    );
                }
            }
        }

        last_end = full_match.end();
    }

    // Append remaining text after last match
    result.push_str(&content[last_end..]);

    Ok(result)
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

fn git_staged_diff(context_lines: u32) -> Result<String> {
    let unified = format!("--unified={context_lines}");

    let output = Command::new("git")
        .args(["diff", "--cached", &unified])
        .output()
        .context("run git diff --cached")?;

    if !output.status.success() {
        bail!(
            "git diff --cached failed (exit={}): {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use diffguard_types::{
        CheckReceipt, Defaults, DiffMeta, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
    };
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn base_check_args() -> CheckArgs {
        CheckArgs {
            base: vec![],
            head: None,
            staged: false,
            diff_file: None,
            config: None,
            no_default_rules: false,
            scope: None,
            diff_context: None,
            fail_on: None,
            max_findings: None,
            paths: vec![],
            only_tags: vec![],
            disable_tags: vec![],
            enable_tags: vec![],
            out: None,
            md: None,
            github_annotations: false,
            sarif: None,
            junit: None,
            csv: None,
            tsv: None,
            rule_stats: None,
            false_positive_baseline: None,
            write_false_positive_baseline: None,
            trend_history: None,
            trend_max_runs: None,
            blame_author: vec![],
            blame_max_age_days: None,
            mode: Mode::Standard,
            sensor: None,
            language: None,
        }
    }

    fn write_config(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("diffguard.toml");
        std::fs::write(&path, contents).expect("write config");
        path
    }

    fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run git");
        assert!(output.status.success(), "git {:?} failed", args);
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn with_current_dir_unlocked<F, R>(dir: &std::path::Path, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let prev = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(dir).expect("set current dir");
        let out = f();
        std::env::set_current_dir(prev).expect("restore current dir");
        out
    }

    fn with_current_dir<F, R>(dir: &std::path::Path, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = ENV_LOCK.lock().unwrap();
        with_current_dir_unlocked(dir, f)
    }

    fn setup_repo_with_match() -> (TempDir, String, String, PathBuf) {
        let dir = TempDir::new().expect("temp");
        run_git(dir.path(), &["init"]);
        run_git(dir.path(), &["config", "user.email", "test@example.com"]);
        run_git(dir.path(), &["config", "user.name", "Test"]);

        std::fs::create_dir_all(dir.path().join("src")).expect("create src");
        std::fs::write(dir.path().join("src/lib.rs"), "fn base() {}\n").expect("write base");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-m", "base"]);
        let base_sha = run_git(dir.path(), &["rev-parse", "HEAD"]);

        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.match"
severity = "warn"
message = "Test match"
patterns = ["test_match"]
paths = ["**/*.rs"]
"#,
        );

        std::fs::write(
            dir.path().join("src/lib.rs"),
            "fn base() { let _ = test_match(); }\n",
        )
        .expect("write head");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-m", "head"]);
        let head_sha = run_git(dir.path(), &["rev-parse", "HEAD"]);

        (dir, base_sha, head_sha, config_path)
    }

    fn write_sample_receipt(dir: &std::path::Path) -> PathBuf {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
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
            findings: vec![diffguard_types::Finding {
                rule_id: "test.rule".to_string(),
                severity: diffguard_types::Severity::Warn,
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
    fn collect_override_candidates_walks_ancestor_directories() {
        let mut out = BTreeSet::new();
        collect_override_candidates_for_path("src/deep/module/lib.rs", &mut out);

        assert!(out.contains(&PathBuf::from(".diffguard.toml")));
        assert!(out.contains(&PathBuf::from("src/.diffguard.toml")));
        assert!(out.contains(&PathBuf::from("src/deep/.diffguard.toml")));
        assert!(out.contains(&PathBuf::from("src/deep/module/.diffguard.toml")));
    }

    #[test]
    fn load_directory_overrides_for_diff_loads_root_then_deeper_overrides() {
        let dir = TempDir::new().expect("temp");
        std::fs::create_dir_all(dir.path().join("src/legacy")).expect("mkdir legacy");

        std::fs::write(
            dir.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "rust.no_unwrap"
enabled = false
"#,
        )
        .expect("write root override");

        std::fs::write(
            dir.path().join("src/legacy/.diffguard.toml"),
            r#"
[[rule]]
id = "rust.no_unwrap"
enabled = true
severity = "warn"
"#,
        )
        .expect("write nested override");

        let diff = r#"
diff --git a/src/legacy/lib.rs b/src/legacy/lib.rs
--- a/src/legacy/lib.rs
+++ b/src/legacy/lib.rs
@@ -0,0 +1 @@
+let x = y.unwrap();
"#;

        let overrides = with_current_dir(dir.path(), || {
            load_directory_overrides_for_diff(diff, Scope::Added).expect("load overrides")
        });

        assert_eq!(overrides.len(), 2);
        assert_eq!(overrides[0].directory, "");
        assert_eq!(overrides[0].rule_id, "rust.no_unwrap");
        assert_eq!(overrides[0].enabled, Some(false));

        assert_eq!(overrides[1].directory, "src/legacy");
        assert_eq!(overrides[1].enabled, Some(true));
        assert_eq!(overrides[1].severity, Some(Severity::Warn));
    }

    #[test]
    fn scope_arg_converts_to_scope() {
        let added: Scope = ScopeArg::Added.into();
        let changed: Scope = ScopeArg::Changed.into();
        let modified: Scope = ScopeArg::Modified.into();
        let deleted: Scope = ScopeArg::Deleted.into();
        assert!(matches!(added, Scope::Added));
        assert!(matches!(changed, Scope::Changed));
        assert!(matches!(modified, Scope::Modified));
        assert!(matches!(deleted, Scope::Deleted));
    }

    #[test]
    fn fail_on_arg_converts_to_fail_on() {
        let error: FailOn = FailOnArg::Error.into();
        let warn: FailOn = FailOnArg::Warn.into();
        let never: FailOn = FailOnArg::Never.into();
        assert!(matches!(error, FailOn::Error));
        assert!(matches!(warn, FailOn::Warn));
        assert!(matches!(never, FailOn::Never));
    }

    #[test]
    fn run_with_args_dispatches_rules_verbose_and_debug() {
        let dir = TempDir::new().expect("temp");
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
        );

        let exit_code = run_with_args([
            "diffguard",
            "--verbose",
            "rules",
            "--config",
            config_path.to_str().unwrap(),
            "--no-default-rules",
        ])
        .expect("run rules verbose");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "--debug",
            "rules",
            "--config",
            config_path.to_str().unwrap(),
            "--no-default-rules",
        ])
        .expect("run rules debug");
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn run_with_args_dispatches_additional_commands() {
        let dir = TempDir::new().expect("temp");
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
        );

        let receipt_path = write_sample_receipt(dir.path());
        let sarif_path = dir.path().join("out.sarif.json");
        let junit_path = dir.path().join("out.xml");
        let csv_path = dir.path().join("out.csv");
        let init_path = dir.path().join("generated.toml");

        let exit_code = run_with_args([
            "diffguard",
            "explain",
            "test.rule",
            "--config",
            config_path.to_str().unwrap(),
            "--no-default-rules",
        ])
        .expect("run explain");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "validate",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .expect("run validate");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "sarif",
            "--report",
            receipt_path.to_str().unwrap(),
            "--output",
            sarif_path.to_str().unwrap(),
        ])
        .expect("run sarif");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "junit",
            "--report",
            receipt_path.to_str().unwrap(),
            "--output",
            junit_path.to_str().unwrap(),
        ])
        .expect("run junit");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "csv",
            "--report",
            receipt_path.to_str().unwrap(),
            "--output",
            csv_path.to_str().unwrap(),
        ])
        .expect("run csv");
        assert_eq!(exit_code, 0);

        let exit_code = run_with_args([
            "diffguard",
            "init",
            "--output",
            init_path.to_str().unwrap(),
            "--preset",
            "minimal",
            "--force",
        ])
        .expect("run init");
        assert_eq!(exit_code, 0);
        assert!(init_path.exists());
    }

    #[test]
    fn confirm_overwrite_parses_input() {
        let mut yes = std::io::Cursor::new("yes\n");
        let mut sink = Vec::new();
        let ok = confirm_overwrite(&mut yes, &mut sink, Path::new("diffguard.toml")).unwrap();
        assert!(ok);

        let mut no = std::io::Cursor::new("n\n");
        let mut sink2 = Vec::new();
        let ok = confirm_overwrite(&mut no, &mut sink2, Path::new("diffguard.toml")).unwrap();
        assert!(!ok);
    }

    #[test]
    fn cmd_init_with_io_force_writes_file() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("nested/diffguard.toml");
        let args = InitArgs {
            preset: Preset::Minimal,
            output: output_path.clone(),
            force: true,
        };

        let mut input = std::io::Cursor::new("");
        let mut err = Vec::new();
        cmd_init_with_io(args, &mut input, &mut err).expect("init with force");
        assert!(output_path.exists());
    }

    #[test]
    fn cmd_init_with_io_respects_overwrite_prompt() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("diffguard.toml");
        std::fs::write(&output_path, "old").unwrap();

        let args = InitArgs {
            preset: Preset::Minimal,
            output: output_path.clone(),
            force: false,
        };

        let mut input = std::io::Cursor::new("n\n");
        let mut err = Vec::new();
        cmd_init_with_io(args, &mut input, &mut err).expect("init with prompt");
        let contents = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(contents, "old");
    }

    #[test]
    fn cmd_init_with_io_overwrites_when_confirmed() {
        let dir = TempDir::new().unwrap();
        let output_path = dir.path().join("diffguard.toml");
        std::fs::write(&output_path, "old").unwrap();

        let args = InitArgs {
            preset: Preset::Minimal,
            output: output_path.clone(),
            force: false,
        };

        let mut input = std::io::Cursor::new("y\n");
        let mut err = Vec::new();
        cmd_init_with_io(args, &mut input, &mut err).expect("init overwrite");
        let contents = std::fs::read_to_string(&output_path).unwrap();
        assert_ne!(contents, "old");
    }

    #[test]
    fn test_format_rule_explanation_basic() {
        let rule = RuleConfig {
            id: "test.rule".to_string(),
            severity: Severity::Warn,
            message: "Test message".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec![r"\.unwrap\(".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec!["**/tests/**".to_string()],
            ignore_comments: true,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: Some("Use ? operator instead.".to_string()),
            url: Some("https://example.com".to_string()),
            tags: vec![],
            test_cases: vec![],
        };

        let output = format_rule_explanation(&rule);

        assert!(output.contains("Rule: test.rule"));
        assert!(output.contains("Severity: warn"));
        assert!(output.contains("Message: Test message"));
        assert!(output.contains("Languages: rust"));
        assert!(output.contains("Paths: **/*.rs"));
        assert!(output.contains("Excludes: **/tests/**"));
        assert!(output.contains("Ignore comments: yes"));
        assert!(output.contains("Ignore strings: no"));
        assert!(output.contains("Remediation:"));
        assert!(output.contains("Use ? operator instead."));
        assert!(output.contains("See also: https://example.com"));
    }

    #[test]
    fn test_format_rule_explanation_minimal() {
        let rule = RuleConfig {
            id: "minimal.rule".to_string(),
            severity: Severity::Error,
            message: "Minimal rule".to_string(),
            languages: vec![],
            patterns: vec!["pattern".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let output = format_rule_explanation(&rule);

        assert!(output.contains("Rule: minimal.rule"));
        assert!(output.contains("Severity: error"));
        assert!(!output.contains("Languages:"));
        assert!(!output.contains("Remediation:"));
        assert!(!output.contains("See also:"));
    }

    #[test]
    fn test_find_similar_rules_exact_prefix() {
        let rules = vec![
            RuleConfig {
                id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "".to_string(),
                languages: vec![],
                patterns: vec![],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: Default::default(),
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec![],
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            },
            RuleConfig {
                id: "rust.no_dbg".to_string(),
                severity: Severity::Warn,
                message: "".to_string(),
                languages: vec![],
                patterns: vec![],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: Default::default(),
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec![],
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            },
        ];

        let suggestions = find_similar_rules("rust", &rules);
        assert!(suggestions.contains(&"rust.no_unwrap".to_string()));
        assert!(suggestions.contains(&"rust.no_dbg".to_string()));
    }

    #[test]
    fn test_find_similar_rules_typo() {
        let rules = vec![RuleConfig {
            id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "".to_string(),
            languages: vec![],
            patterns: vec![],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        }];

        let suggestions = find_similar_rules("rust.no_unwarp", &rules);
        assert!(suggestions.contains(&"rust.no_unwrap".to_string()));
    }

    #[test]
    fn test_simple_edit_distance() {
        assert_eq!(simple_edit_distance("", ""), 0);
        assert_eq!(simple_edit_distance("abc", "abc"), 0);
        assert_eq!(simple_edit_distance("abc", "ab"), 1);
        assert_eq!(simple_edit_distance("abc", "abd"), 1);
        assert_eq!(simple_edit_distance("kitten", "sitting"), 3);
    }

    // --- Environment Variable Expansion Tests ---

    #[test]
    fn test_expand_env_vars_no_vars() {
        let input = "hello world";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_expand_env_vars_with_default() {
        // Use a variable that's unlikely to be set
        let input = "port ${DIFFGUARD_TEST_UNLIKELY_VAR:-8080}";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "port 8080");
    }

    #[test]
    fn test_expand_env_vars_multiple() {
        let input = "${DIFFGUARD_TEST_A:-foo} and ${DIFFGUARD_TEST_B:-bar}";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "foo and bar");
    }

    #[test]
    fn test_expand_env_vars_empty_default() {
        let input = "value: ${DIFFGUARD_TEST_EMPTY:-}";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "value: ");
    }

    #[test]
    fn test_expand_env_vars_missing_no_default() {
        let input = "value: ${DIFFGUARD_TEST_MISSING_VAR}";
        let result = expand_env_vars(input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("DIFFGUARD_TEST_MISSING_VAR")
        );
    }

    #[test]
    fn test_expand_env_vars_from_environment() {
        // Set a test environment variable
        unsafe {
            std::env::set_var("DIFFGUARD_TEST_VAR", "test_value");
        }
        let input = "hello ${DIFFGUARD_TEST_VAR}!";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "hello test_value!");
        unsafe {
            std::env::remove_var("DIFFGUARD_TEST_VAR");
        }
    }

    #[test]
    fn test_expand_env_vars_preserves_other_syntax() {
        // Make sure we don't expand $VAR (without braces) or other patterns
        let input = "hello $VAR ${DIFFGUARD_TEST_X:-default} $OTHER";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "hello $VAR default $OTHER");
    }

    // --- Language Arg Tests ---

    #[test]
    fn test_language_arg_as_str() {
        assert_eq!(LanguageArg::Rust.as_str(), "rust");
        assert_eq!(LanguageArg::Python.as_str(), "python");
        assert_eq!(LanguageArg::Javascript.as_str(), "javascript");
        assert_eq!(LanguageArg::Typescript.as_str(), "typescript");
        assert_eq!(LanguageArg::Go.as_str(), "go");
        assert_eq!(LanguageArg::Ruby.as_str(), "ruby");
        assert_eq!(LanguageArg::C.as_str(), "c");
        assert_eq!(LanguageArg::Cpp.as_str(), "cpp");
        assert_eq!(LanguageArg::Csharp.as_str(), "csharp");
        assert_eq!(LanguageArg::Java.as_str(), "java");
        assert_eq!(LanguageArg::Kotlin.as_str(), "kotlin");
        assert_eq!(LanguageArg::Shell.as_str(), "shell");
        assert_eq!(LanguageArg::Swift.as_str(), "swift");
        assert_eq!(LanguageArg::Scala.as_str(), "scala");
        assert_eq!(LanguageArg::Sql.as_str(), "sql");
        assert_eq!(LanguageArg::Xml.as_str(), "xml");
        assert_eq!(LanguageArg::Php.as_str(), "php");
        assert_eq!(LanguageArg::Yaml.as_str(), "yaml");
        assert_eq!(LanguageArg::Toml.as_str(), "toml");
        assert_eq!(LanguageArg::Json.as_str(), "json");
    }

    #[test]
    fn resolve_mode_prefers_env_over_args() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DIFFGUARD_MODE", "cockpit");
        }

        let mut args = base_check_args();
        args.mode = Mode::Standard;
        assert!(matches!(resolve_mode(&args), Mode::Cockpit));

        unsafe {
            std::env::remove_var("DIFFGUARD_MODE");
        }
    }

    #[test]
    fn resolve_mode_ignores_invalid_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DIFFGUARD_MODE", "unknown");
        }

        let mut args = base_check_args();
        args.mode = Mode::Standard;
        assert!(matches!(resolve_mode(&args), Mode::Standard));

        unsafe {
            std::env::remove_var("DIFFGUARD_MODE");
        }
    }

    #[test]
    fn resolve_out_path_respects_mode_and_sensor() {
        let mut args = base_check_args();
        assert_eq!(
            resolve_out_path(&args, Mode::Standard),
            PathBuf::from("artifacts/diffguard/report.json")
        );

        args.sensor = Some(PathBuf::from("artifacts/diffguard/report.json"));
        assert_eq!(
            resolve_out_path(&args, Mode::Cockpit),
            PathBuf::from("artifacts/diffguard/extras/check.json")
        );

        args.out = Some(PathBuf::from("custom/out.json"));
        assert_eq!(
            resolve_out_path(&args, Mode::Cockpit),
            PathBuf::from("custom/out.json")
        );
    }

    #[test]
    fn resolve_extras_paths_rewrites_defaults_in_cockpit_mode() {
        let mut args = base_check_args();
        args.sensor = Some(PathBuf::from("artifacts/diffguard/report.json"));
        args.sarif = Some(PathBuf::from("artifacts/diffguard/report.sarif.json"));
        args.junit = Some(PathBuf::from("artifacts/diffguard/report.xml"));
        args.csv = Some(PathBuf::from("artifacts/diffguard/report.csv"));
        args.tsv = Some(PathBuf::from("artifacts/diffguard/report.tsv"));
        args.rule_stats = Some(PathBuf::from("artifacts/diffguard/rule-stats.json"));
        args.write_false_positive_baseline =
            Some(PathBuf::from("artifacts/diffguard/false-positives.json"));
        args.trend_history = Some(PathBuf::from("artifacts/diffguard/trend-history.json"));

        resolve_extras_paths(&mut args, Mode::Cockpit);

        assert_eq!(
            args.sarif.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/report.sarif.json")
        );
        assert_eq!(
            args.junit.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/report.xml")
        );
        assert_eq!(
            args.csv.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/report.csv")
        );
        assert_eq!(
            args.tsv.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/report.tsv")
        );
        assert_eq!(
            args.rule_stats.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/rule-stats.json")
        );
        assert_eq!(
            args.write_false_positive_baseline.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/false-positives.json")
        );
        assert_eq!(
            args.trend_history.as_ref().unwrap(),
            Path::new("artifacts/diffguard/extras/trend-history.json")
        );
    }

    #[test]
    fn resolve_extras_paths_keeps_custom_paths() {
        let mut args = base_check_args();
        args.sensor = Some(PathBuf::from("artifacts/diffguard/report.json"));
        args.csv = Some(PathBuf::from("custom/report.csv"));
        resolve_extras_paths(&mut args, Mode::Cockpit);
        assert_eq!(args.csv.as_ref().unwrap(), Path::new("custom/report.csv"));
    }

    #[test]
    fn build_rule_metadata_includes_help_url_and_tags() {
        let cfg = ConfigFile {
            includes: vec![],
            defaults: Defaults::default(),
            rule: vec![RuleConfig {
                id: "rule.one".to_string(),
                severity: Severity::Warn,
                message: "msg".to_string(),
                languages: vec![],
                patterns: vec!["x".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: Default::default(),
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec![],
                help: Some("help".to_string()),
                url: Some("https://example.com".to_string()),
                tags: vec!["tag1".to_string(), "tag2".to_string()],
                test_cases: vec![],
            }],
        };

        let meta = build_rule_metadata(&cfg);
        let entry = meta.get("rule.one").expect("metadata entry");
        assert_eq!(entry.help.as_deref(), Some("help"));
        assert_eq!(entry.url.as_deref(), Some("https://example.com"));
        assert_eq!(entry.tags, vec!["tag1".to_string(), "tag2".to_string()]);
    }

    #[test]
    fn load_false_positive_baseline_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing-baseline.json");
        let baseline = load_false_positive_baseline(&path).expect("baseline");
        assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
        assert!(baseline.entries.is_empty());
    }

    #[test]
    fn load_false_positive_baseline_rejects_wrong_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, r#"{"schema":"wrong.schema","entries":[]}"#).unwrap();
        let err = load_false_positive_baseline(&path).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported false-positive baseline schema")
        );
    }

    #[test]
    fn parse_blame_porcelain_extracts_line_metadata() {
        let porcelain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 10 1\n\
author Alice\n\
author-mail <alice@example.com>\n\
author-time 1700000000\n\
summary Commit\n\
filename src/lib.rs\n\
\tlet x = 1;\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 2 11 2\n\
author Bob\n\
author-mail <bob@example.com>\n\
author-time 1700500000\n\
summary Commit\n\
filename src/lib.rs\n\
\tlet y = 2;\n";
        let map = parse_blame_porcelain(porcelain).expect("parse");
        assert_eq!(map.get(&10).map(|m| m.author.as_str()), Some("Alice"));
        assert_eq!(
            map.get(&10).map(|m| m.author_mail.as_str()),
            Some("alice@example.com")
        );
        assert_eq!(map.get(&11).map(|m| m.author.as_str()), Some("Bob"));
        assert_eq!(map.get(&12).map(|m| m.author.as_str()), Some("Bob"));
    }

    #[test]
    fn blame_filters_match_author_and_age() {
        let filters = BlameFilters {
            author_patterns: vec!["alice".to_string()],
            max_age_days: Some(30),
        };
        let now = 1_800_000_000i64;
        let line = BlameLineMeta {
            author: "Alice Example".to_string(),
            author_mail: "alice@example.com".to_string(),
            author_time: now - (10 * 86_400),
        };
        assert!(filters.matches(&line, now));

        let stale = BlameLineMeta {
            author_time: now - (120 * 86_400),
            ..line.clone()
        };
        assert!(!filters.matches(&stale, now));
    }

    #[test]
    fn cockpit_error_classification_and_detail() {
        let source = anyhow::anyhow!("missing base ref");
        let err = CockpitSkipError {
            token: REASON_MISSING_BASE,
            source,
        };
        let wrapped = anyhow::anyhow!(err).context("top level");

        assert_eq!(classify_cockpit_error(&wrapped), Some(REASON_MISSING_BASE));
        assert_eq!(cockpit_error_detail(&wrapped), "missing base ref");

        let other = anyhow::anyhow!("other error");
        assert_eq!(classify_cockpit_error(&other), None);
        assert_eq!(cockpit_error_detail(&other), "other error");
    }

    #[test]
    fn build_tool_error_receipt_uses_defaults_and_sets_reason() {
        let args = base_check_args();
        let receipt = build_tool_error_receipt(&args, "boom");

        assert_eq!(receipt.diff.base, "origin/main");
        assert_eq!(receipt.diff.head, "HEAD");
        assert_eq!(receipt.diff.context_lines, 0);
        assert_eq!(receipt.diff.scope, Scope::Added);
        assert_eq!(receipt.verdict.status, VerdictStatus::Fail);
        assert_eq!(receipt.verdict.counts.error, 1);
        assert!(
            receipt
                .verdict
                .reasons
                .contains(&REASON_TOOL_ERROR.to_string())
        );

        let finding = &receipt.findings[0];
        assert_eq!(finding.rule_id, CHECK_ID_INTERNAL);
        assert_eq!(finding.message, "boom");
    }

    #[test]
    fn build_tool_error_sensor_context_and_report() {
        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let ended_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 1).unwrap();
        let ctx = build_tool_error_sensor_context(&started_at, &ended_at, 1000, "bad git");

        let cap = ctx.capabilities.get(CAP_GIT).expect("git capability");
        assert_eq!(cap.status, CAP_STATUS_UNAVAILABLE);
        assert_eq!(cap.reason.as_deref(), Some(REASON_TOOL_ERROR));
        assert_eq!(cap.detail.as_deref(), Some("bad git"));

        let args = base_check_args();
        let report = build_tool_error_sensor_report(&args, "bad git", &ctx);

        assert_eq!(report.schema, diffguard_types::SENSOR_REPORT_SCHEMA_V1);
        assert_eq!(report.verdict.status, VerdictStatus::Fail);
        assert!(
            report
                .verdict
                .reasons
                .contains(&REASON_TOOL_ERROR.to_string())
        );
        assert_eq!(report.findings.len(), 1);

        let finding = &report.findings[0];
        assert_eq!(finding.check_id, CHECK_ID_INTERNAL);
        assert_eq!(finding.code, CODE_TOOL_RUNTIME_ERROR);
        assert_eq!(finding.message, "bad git");
        assert_eq!(finding.fingerprint.len(), 64);
    }

    #[test]
    fn merge_with_built_in_overrides_by_id() {
        let user = ConfigFile {
            includes: vec![],
            defaults: Defaults {
                base: Some("custom/base".to_string()),
                ..Defaults::default()
            },
            rule: vec![
                RuleConfig {
                    id: "rust.no_unwrap".to_string(),
                    severity: Severity::Info,
                    message: "custom message".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec![r"\.unwrap\(".to_string()],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    match_mode: Default::default(),
                    multiline: false,
                    multiline_window: None,
                    context_patterns: vec![],
                    context_window: None,
                    escalate_patterns: vec![],
                    escalate_window: None,
                    escalate_to: None,
                    depends_on: vec![],
                    help: None,
                    url: None,
                    tags: vec![],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "custom.rule".to_string(),
                    severity: Severity::Warn,
                    message: "custom".to_string(),
                    languages: vec![],
                    patterns: vec!["x".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    match_mode: Default::default(),
                    multiline: false,
                    multiline_window: None,
                    context_patterns: vec![],
                    context_window: None,
                    escalate_patterns: vec![],
                    escalate_window: None,
                    escalate_to: None,
                    depends_on: vec![],
                    help: None,
                    url: None,
                    tags: vec![],
                    test_cases: vec![],
                },
            ],
        };

        let merged = merge_with_built_in(user);
        assert_eq!(merged.defaults.base.as_deref(), Some("custom/base"));

        let mut rule_map = std::collections::HashMap::new();
        for rule in &merged.rule {
            rule_map.insert(rule.id.as_str(), rule);
        }

        let override_rule = rule_map.get("rust.no_unwrap").expect("override rule");
        assert_eq!(override_rule.message, "custom message");
        assert_eq!(override_rule.severity, Severity::Info);
        assert!(rule_map.contains_key("custom.rule"));
        assert!(rule_map.contains_key("rust.no_dbg"));
    }

    #[test]
    fn write_json_and_text_create_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let json_path = dir.path().join("nested/out.json");
        let text_path = dir.path().join("nested/out.txt");

        let payload = serde_json::json!({ "ok": true });
        write_json(&json_path, &payload).expect("write json");
        write_text(&text_path, "hello").expect("write text");

        let json_content = serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(&json_path).unwrap(),
        )
        .unwrap();
        assert_eq!(json_content.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(std::fs::read_to_string(&text_path).unwrap(), "hello");
    }

    #[test]
    fn find_similar_rules_contains_match() {
        let rules = vec![RuleConfig {
            id: "alpha.rule".to_string(),
            severity: Severity::Warn,
            message: "".to_string(),
            languages: vec![],
            patterns: vec![],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        }];

        let suggestions = find_similar_rules("pha", &rules);
        assert!(suggestions.contains(&"alpha.rule".to_string()));
    }

    #[test]
    fn find_similar_rules_edit_distance_match() {
        let rules = vec![RuleConfig {
            id: "alpha.rule".to_string(),
            severity: Severity::Warn,
            message: "".to_string(),
            languages: vec![],
            patterns: vec![],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        }];

        let suggestions = find_similar_rules("alpah.rule", &rules);
        assert_eq!(suggestions, vec!["alpha.rule".to_string()]);
    }

    #[test]
    fn simple_edit_distance_handles_empty_rhs() {
        assert_eq!(simple_edit_distance("abc", ""), 3);
    }

    #[test]
    fn cmd_rules_json_renders() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
        );

        let args = RulesArgs {
            config: Some(config_path),
            no_default_rules: true,
            format: RulesFormat::Json,
        };
        cmd_rules(args).expect("cmd_rules");
    }

    #[test]
    fn cmd_explain_found_and_missing() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
        );

        let args = ExplainArgs {
            rule_id: "alpha.rule".to_string(),
            config: Some(config_path.clone()),
            no_default_rules: true,
        };
        cmd_explain(args).expect("explain should succeed");

        let args = ExplainArgs {
            rule_id: "alpha.rul".to_string(),
            config: Some(config_path),
            no_default_rules: true,
        };
        let err = cmd_explain(args).expect_err("explain should fail");
        assert!(err.to_string().contains("Did you mean"));
    }

    #[test]
    fn cmd_validate_uses_default_config_path_and_strict_warnings() {
        let dir = TempDir::new().unwrap();
        write_config(
            dir.path(),
            r#"
[[rule]]
id = "warn.rule"
severity = "warn"
message = ""
patterns = ["todo"]
"#,
        );

        let args = ValidateArgs {
            config: None,
            strict: true,
            format: ValidateFormat::Text,
        };

        let code = with_current_dir(dir.path(), || cmd_validate(args).unwrap());
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_validate_missing_config_errors() {
        let dir = TempDir::new().unwrap();
        let args = ValidateArgs {
            config: None,
            strict: false,
            format: ValidateFormat::Text,
        };

        let err = with_current_dir(dir.path(), || cmd_validate(args).unwrap_err());
        assert!(err.to_string().contains("No configuration file found"));
    }

    #[test]
    fn cmd_validate_json_reports_errors() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "bad.rule"
severity = "warn"
message = "Bad"
patterns = ["("]
"#,
        );

        let args = ValidateArgs {
            config: Some(config_path),
            strict: false,
            format: ValidateFormat::Json,
        };
        let code = cmd_validate(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_validate_text_reports_errors_and_warnings() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "dup.rule"
severity = "warn"
message = ""
patterns = []

[[rule]]
id = "dup.rule"
severity = "warn"
message = "x"
patterns = ["["]
paths = ["["]
exclude_paths = ["["]
"#,
        );

        let args = ValidateArgs {
            config: Some(config_path),
            strict: true,
            format: ValidateFormat::Text,
        };
        let code = cmd_validate(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_validate_reports_invalid_globs_and_strict_warnings() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "warn.rule"
severity = "warn"
message = ""
patterns = ["TODO"]
paths = ["[a"]
exclude_paths = ["[a"]
"#,
        );

        let args = ValidateArgs {
            config: Some(config_path),
            strict: true,
            format: ValidateFormat::Text,
        };
        let code = cmd_validate(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_test_no_cases_text() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Text,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_test_text_success_no_failures() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "pass.rule"
severity = "warn"
message = "Pass"
patterns = ["TODO"]

[[rule.test_cases]]
input = "TODO"
should_match = true
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Text,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_test_json_success_and_failure() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]

[[rule.test_cases]]
input = "TODO"
should_match = true
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Json,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 0);

        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "fail.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]

[[rule.test_cases]]
input = "OK"
should_match = true
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Json,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_test_rule_filter_missing() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: Some("missing".to_string()),
            format: TestFormat::Text,
        };
        let err = cmd_test(args).expect_err("missing rule filter should error");
        assert!(err.to_string().contains("No rules match filter"));
    }

    #[test]
    fn cmd_test_compile_error_records_failures() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "bad.rule"
severity = "warn"
message = "Bad"
patterns = ["("]

[[rule.test_cases]]
input = "x"
should_match = true
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Json,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_check_inner_writes_outputs() {
        let (dir, base_sha, head_sha, config_path) = setup_repo_with_match();
        let out_path = dir.path().join("artifacts/diffguard/report.json");
        let md_path = dir.path().join("artifacts/diffguard/comment.md");
        let sarif_path = dir.path().join("artifacts/diffguard/report.sarif.json");
        let junit_path = dir.path().join("artifacts/diffguard/report.xml");
        let csv_path = dir.path().join("artifacts/diffguard/report.csv");
        let tsv_path = dir.path().join("artifacts/diffguard/report.tsv");
        let stats_path = dir.path().join("artifacts/diffguard/rule-stats.json");
        let sensor_path = dir.path().join("artifacts/diffguard/sensor.json");

        let mut args = base_check_args();
        args.base = vec![base_sha];
        args.head = Some(head_sha);
        args.config = Some(config_path);
        args.out = Some(out_path.clone());
        args.md = Some(md_path.clone());
        args.sarif = Some(sarif_path.clone());
        args.junit = Some(junit_path.clone());
        args.csv = Some(csv_path.clone());
        args.tsv = Some(tsv_path.clone());
        args.rule_stats = Some(stats_path.clone());
        args.sensor = Some(sensor_path.clone());
        args.github_annotations = true;
        args.language = Some(LanguageArg::Rust);

        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let exit_code = with_current_dir(dir.path(), || {
            cmd_check_inner(&args, Mode::Standard, &started_at, &out_path).unwrap()
        });

        assert_eq!(exit_code, 0);
        assert!(out_path.exists());
        assert!(md_path.exists());
        assert!(sarif_path.exists());
        assert!(junit_path.exists());
        assert!(csv_path.exists());
        assert!(tsv_path.exists());
        assert!(stats_path.exists());
        assert!(sensor_path.exists());
    }

    #[test]
    fn cmd_check_inner_applies_false_positive_baseline() {
        let (dir, base_sha, head_sha, config_path) = setup_repo_with_match();
        let out_path = dir.path().join("artifacts/diffguard/report.json");
        let baseline_path = dir.path().join("artifacts/diffguard/false-positives.json");

        let mut first_args = base_check_args();
        first_args.base = vec![base_sha.clone()];
        first_args.head = Some(head_sha.clone());
        first_args.config = Some(config_path.clone());
        first_args.no_default_rules = true;
        first_args.out = Some(out_path.clone());
        first_args.fail_on = Some(FailOnArg::Warn);

        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let first_code = with_current_dir(dir.path(), || {
            cmd_check_inner(&first_args, Mode::Standard, &started_at, &out_path).unwrap()
        });
        assert_eq!(first_code, 3);

        let receipt_text = std::fs::read_to_string(&out_path).unwrap();
        let receipt: CheckReceipt = serde_json::from_str(&receipt_text).unwrap();
        assert_eq!(receipt.findings.len(), 1);
        let finding = receipt.findings[0].clone();
        let fingerprint = diffguard_core::compute_fingerprint(&finding);

        let baseline = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![diffguard_analytics::FalsePositiveEntry {
                fingerprint,
                rule_id: finding.rule_id,
                path: finding.path,
                line: finding.line,
                note: Some("intentional false positive".to_string()),
            }],
        };
        write_json(&baseline_path, &baseline).unwrap();

        let mut second_args = base_check_args();
        second_args.base = vec![base_sha];
        second_args.head = Some(head_sha);
        second_args.config = Some(config_path);
        second_args.no_default_rules = true;
        second_args.out = Some(out_path.clone());
        second_args.fail_on = Some(FailOnArg::Warn);
        second_args.false_positive_baseline = Some(baseline_path);

        let second_code = with_current_dir(dir.path(), || {
            cmd_check_inner(&second_args, Mode::Standard, &started_at, &out_path).unwrap()
        });
        assert_eq!(second_code, 0);

        let filtered_text = std::fs::read_to_string(&out_path).unwrap();
        let filtered: CheckReceipt = serde_json::from_str(&filtered_text).unwrap();
        assert!(filtered.findings.is_empty());
        assert_eq!(filtered.verdict.counts.warn, 0);
    }

    #[test]
    fn cmd_check_inner_reads_diff_file_and_applies_language_override() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "rust.no_unwrap"
severity = "warn"
message = "no unwrap"
languages = ["rust"]
patterns = ["\\.unwrap\\("]
paths = ["**/*.custom"]
ignore_comments = true
ignore_strings = true
"#,
        );

        let diff_path = dir.path().join("input.diff");
        std::fs::write(
            &diff_path,
            r#"
diff --git a/src/code.custom b/src/code.custom
--- a/src/code.custom
+++ b/src/code.custom
@@ -0,0 +1,1 @@
+let x = y.unwrap();
"#,
        )
        .unwrap();

        let out_path = dir.path().join("artifacts/diffguard/report.json");
        let mut args = base_check_args();
        args.diff_file = Some(diff_path);
        args.config = Some(config_path);
        args.no_default_rules = true;
        args.language = Some(LanguageArg::Rust);

        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let code = with_current_dir(dir.path(), || {
            cmd_check_inner(&args, Mode::Standard, &started_at, &out_path).unwrap()
        });
        assert_eq!(code, 0);

        let receipt_text = std::fs::read_to_string(&out_path).unwrap();
        let receipt: CheckReceipt = serde_json::from_str(&receipt_text).unwrap();
        assert_eq!(receipt.findings.len(), 1);
        assert_eq!(receipt.findings[0].rule_id, "rust.no_unwrap");
    }

    #[test]
    fn cmd_check_inner_multi_base_dedupes_findings() {
        let (dir, base_sha, head_sha, config_path) = setup_repo_with_match();
        let out_path = dir.path().join("artifacts/diffguard/report.json");

        let mut args = base_check_args();
        args.base = vec![base_sha.clone(), base_sha];
        args.head = Some(head_sha);
        args.config = Some(config_path);
        args.no_default_rules = true;
        args.out = Some(out_path.clone());

        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let code = with_current_dir(dir.path(), || {
            cmd_check_inner(&args, Mode::Standard, &started_at, &out_path).unwrap()
        });
        assert_eq!(code, 0);

        let receipt_text = std::fs::read_to_string(&out_path).unwrap();
        let receipt: CheckReceipt = serde_json::from_str(&receipt_text).unwrap();
        assert_eq!(receipt.findings.len(), 1);
        assert_eq!(receipt.verdict.counts.warn, 1);
    }

    #[test]
    fn cmd_check_cockpit_skip_and_tool_error_paths() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (dir, _base_sha, _head_sha, config_path) = setup_repo_with_match();
        let out_path = dir.path().join("artifacts/diffguard/report.json");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.base = vec!["missing-ref".to_string()];
        args.head = Some("HEAD".to_string());
        args.config = Some(config_path);
        args.out = Some(out_path.clone());

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        assert_eq!(code, 0);
        assert!(out_path.exists());

        let dir2 = TempDir::new().unwrap();
        let bad_config = dir2.path().join("bad.toml");
        std::fs::write(&bad_config, "not toml").unwrap();

        let sensor_path = dir2.path().join("sensor.json");
        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.config = Some(bad_config);
        args.sensor = Some(sensor_path.clone());
        args.out = Some(dir2.path().join("report.json"));

        let code = cmd_check(args).unwrap();
        assert_eq!(code, 0);
        assert!(sensor_path.exists());
    }

    #[test]
    fn cmd_check_standard_and_cockpit_success() {
        let (dir, base_sha, head_sha, config_path) = setup_repo_with_match();

        let mut standard_args = base_check_args();
        standard_args.base = vec![base_sha.clone()];
        standard_args.head = Some(head_sha.clone());
        standard_args.config = Some(config_path.clone());
        standard_args.no_default_rules = true;
        standard_args.mode = Mode::Standard;

        let code = with_current_dir(dir.path(), || cmd_check(standard_args).unwrap());
        assert_eq!(code, 0);
        assert!(dir.path().join("artifacts/diffguard/report.json").exists());

        let mut cockpit_args = base_check_args();
        cockpit_args.base = vec![base_sha];
        cockpit_args.head = Some(head_sha);
        cockpit_args.config = Some(config_path);
        cockpit_args.no_default_rules = true;
        cockpit_args.mode = Mode::Cockpit;

        let code = with_current_dir(dir.path(), || cmd_check(cockpit_args).unwrap());
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_check_cockpit_skip_writes_sensor_report() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (dir, _base_sha, _head_sha, config_path) = setup_repo_with_match();
        let sensor_path = dir.path().join("artifacts/diffguard/sensor.json");
        let out_path = dir.path().join("artifacts/diffguard/report.json");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.base = vec!["missing-ref".to_string()];
        args.head = Some("HEAD".to_string());
        args.config = Some(config_path);
        args.sensor = Some(sensor_path.clone());
        args.out = Some(out_path);

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        assert_eq!(code, 0);
        assert!(sensor_path.exists());
    }

    #[test]
    fn cmd_check_cockpit_catastrophic_failure_when_writes_fail() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let bad_config = dir.path().join("bad.toml");
        std::fs::write(&bad_config, "not toml").unwrap();

        let out_dir = dir.path().join("out_dir");
        let sensor_dir = dir.path().join("sensor_dir");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(&sensor_dir).unwrap();

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.config = Some(bad_config);
        args.out = Some(out_dir);
        args.sensor = Some(sensor_dir);

        let code = cmd_check(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_check_inner_handles_staged_diff() {
        let dir = TempDir::new().unwrap();
        run_git(dir.path(), &["init"]);
        run_git(dir.path(), &["config", "user.email", "test@example.com"]);
        run_git(dir.path(), &["config", "user.name", "Test"]);

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "fn base() {}\n").unwrap();
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-m", "base"]);

        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.match"
severity = "warn"
message = "Test match"
patterns = ["test_match"]
paths = ["**/*.rs"]
"#,
        );

        std::fs::write(
            dir.path().join("src/lib.rs"),
            "fn base() { let _ = test_match(); }\n",
        )
        .unwrap();
        run_git(dir.path(), &["add", "."]);

        let out_path = dir.path().join("artifacts/diffguard/report.json");
        let mut args = base_check_args();
        args.staged = true;
        args.config = Some(config_path);
        args.no_default_rules = true;

        let started_at = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let code = with_current_dir(dir.path(), || {
            cmd_check_inner(&args, Mode::Standard, &started_at, &out_path).unwrap()
        });

        assert_eq!(code, 0);
        assert!(out_path.exists());
    }

    #[test]
    fn cmd_renderers_write_outputs() {
        let dir = TempDir::new().unwrap();
        let receipt_path = write_sample_receipt(dir.path());

        let sarif_path = dir.path().join("out.sarif.json");
        cmd_sarif(SarifArgs {
            report: receipt_path.clone(),
            output: Some(sarif_path.clone()),
        })
        .expect("sarif");
        assert!(sarif_path.exists());

        let junit_path = dir.path().join("out.xml");
        cmd_junit(JunitArgs {
            report: receipt_path.clone(),
            output: Some(junit_path.clone()),
        })
        .expect("junit");
        assert!(junit_path.exists());

        let csv_path = dir.path().join("out.csv");
        cmd_csv(CsvArgs {
            report: receipt_path,
            output: Some(csv_path.clone()),
            tsv: false,
        })
        .expect("csv");
        assert!(csv_path.exists());
    }

    #[test]
    fn cmd_renderers_stdout_and_tsv() {
        let dir = TempDir::new().unwrap();
        let receipt_path = write_sample_receipt(dir.path());

        cmd_sarif(SarifArgs {
            report: receipt_path.clone(),
            output: None,
        })
        .expect("sarif stdout");

        cmd_junit(JunitArgs {
            report: receipt_path.clone(),
            output: None,
        })
        .expect("junit stdout");

        cmd_csv(CsvArgs {
            report: receipt_path,
            output: None,
            tsv: true,
        })
        .expect("tsv stdout");
    }

    #[test]
    fn run_with_args_dispatches_test_command() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]

[[rule.test_cases]]
input = "TODO"
should_match = true
"#,
        );

        let exit_code = run_with_args([
            "diffguard",
            "test",
            "--config",
            config_path.to_str().unwrap(),
            "--no-default-rules",
            "--format",
            "json",
        ])
        .unwrap();
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn run_with_args_dispatches_trend_command() {
        let dir = TempDir::new().unwrap();
        let history_path = dir.path().join("trend-history.json");
        std::fs::write(
            &history_path,
            r#"{"schema":"diffguard.trend_history.v1","runs":[]}"#,
        )
        .unwrap();

        let exit_code = run_with_args([
            "diffguard",
            "trend",
            "--history",
            history_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .unwrap();
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn cmd_validate_accepts_valid_globs_and_strict_no_warnings() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "ok.rule"
severity = "warn"
message = "Ok"
help = "Help text"
tags = ["tag"]
patterns = ["TODO"]
paths = ["src/**/*.rs"]
exclude_paths = ["target/**"]
"#,
        );

        let args = ValidateArgs {
            config: Some(config_path),
            strict: true,
            format: ValidateFormat::Text,
        };
        let code = cmd_validate(args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_validate_forced_compile_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DIFFGUARD_TEST_FORCE_COMPILE_ERROR", "1");
        }

        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "ok.rule"
severity = "warn"
message = "Ok"
patterns = ["TODO"]
"#,
        );

        let args = ValidateArgs {
            config: Some(config_path),
            strict: false,
            format: ValidateFormat::Text,
        };
        let code = cmd_validate(args).unwrap();
        unsafe {
            std::env::remove_var("DIFFGUARD_TEST_FORCE_COMPILE_ERROR");
        }
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_explain_suggests_similar_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
        );

        let args = ExplainArgs {
            rule_id: "alpah.rule".to_string(),
            config: Some(config_path),
            no_default_rules: true,
        };
        let err = cmd_explain(args).expect_err("missing rule should error");
        let msg = err.to_string();
        assert!(msg.contains("Did you mean"));
        assert!(msg.contains("alpha.rule"));
    }

    #[test]
    fn cmd_explain_missing_rule_without_suggestions() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
        );

        let args = ExplainArgs {
            rule_id: "completely.unrelated".to_string(),
            config: Some(config_path),
            no_default_rules: true,
        };
        let err = cmd_explain(args).expect_err("missing rule should error");
        let msg = err.to_string();
        assert!(!msg.contains("Did you mean"));
        assert!(msg.contains("Rule 'completely.unrelated' not found."));
    }

    #[test]
    fn find_similar_rules_uses_edit_distance() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "alpha.rule"
severity = "warn"
message = "Alpha"
patterns = ["alpha"]
"#,
        );

        let cfg = load_config(Some(config_path), true).expect("load config");
        let suggestions = find_similar_rules("alpah.rule", &cfg.rule);
        assert!(suggestions.contains(&"alpha.rule".to_string()));
    }

    #[test]
    fn cmd_check_cockpit_skip_fails_to_write_receipts() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let sensor_dir = dir.path().join("sensor");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&sensor_dir).unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.staged = true;
        args.sensor = Some(sensor_dir);
        args.out = Some(out_dir);

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_check_cockpit_tool_error_writes_receipt_when_sensor_fails() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let sensor_dir = dir.path().join("sensor");
        std::fs::create_dir_all(&sensor_dir).unwrap();
        let out_file = dir.path().join("out.json");
        let missing_config = dir.path().join("missing.toml");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.sensor = Some(sensor_dir);
        args.out = Some(out_file.clone());
        args.config = Some(missing_config);

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        assert_eq!(code, 0);
        assert!(out_file.exists());
    }

    #[test]
    fn cmd_check_cockpit_skip_sensor_json_error_falls_back_to_out() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DIFFGUARD_TEST_FORCE_SENSOR_JSON_ERROR", "1");
        }

        let dir = TempDir::new().unwrap();
        let sensor_path = dir.path().join("sensor.json");
        let out_file = dir.path().join("out.json");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.staged = true;
        args.sensor = Some(sensor_path);
        args.out = Some(out_file.clone());

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        unsafe {
            std::env::remove_var("DIFFGUARD_TEST_FORCE_SENSOR_JSON_ERROR");
        }
        assert_eq!(code, 0);
        assert!(out_file.exists());
    }

    #[test]
    fn cmd_check_cockpit_tool_error_sensor_json_error_falls_back_to_out() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DIFFGUARD_TEST_FORCE_SENSOR_JSON_ERROR", "1");
        }

        let dir = TempDir::new().unwrap();
        let sensor_path = dir.path().join("sensor.json");
        let out_file = dir.path().join("out.json");
        let missing_config = dir.path().join("missing.toml");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.sensor = Some(sensor_path);
        args.out = Some(out_file.clone());
        args.config = Some(missing_config);

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        unsafe {
            std::env::remove_var("DIFFGUARD_TEST_FORCE_SENSOR_JSON_ERROR");
        }
        assert_eq!(code, 0);
        assert!(out_file.exists());
    }

    #[test]
    fn cmd_check_cockpit_tool_error_without_sensor_writes_receipt() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let out_file = dir.path().join("out.json");
        let missing_config = dir.path().join("missing.toml");

        let mut args = base_check_args();
        args.mode = Mode::Cockpit;
        args.out = Some(out_file.clone());
        args.config = Some(missing_config);

        let code = with_current_dir_unlocked(dir.path(), || cmd_check(args).unwrap());
        assert_eq!(code, 0);
        assert!(out_file.exists());
    }

    #[test]
    fn cmd_check_inner_staged_error_maps_to_skip() {
        let dir = TempDir::new().unwrap();
        let mut args = base_check_args();
        args.staged = true;
        let started_at = Utc::now();
        let out_path = dir.path().join("out.json");

        let err = with_current_dir(dir.path(), || {
            cmd_check_inner(&args, Mode::Cockpit, &started_at, &out_path)
        })
        .expect_err("staged diff should error in non-git dir");
        assert!(err.to_string().contains(REASON_NO_DIFF_INPUT));
    }

    #[test]
    fn cmd_init_with_io_no_parent_path() {
        let dir = TempDir::new().unwrap();
        let output = PathBuf::from("diffguard.toml");

        with_current_dir(dir.path(), || {
            let args = InitArgs {
                preset: Preset::Minimal,
                output,
                force: true,
            };
            let mut input = std::io::Cursor::new("");
            let mut err = Vec::new();
            cmd_init_with_io(args, &mut input, &mut err).unwrap();
        });

        assert!(dir.path().join("diffguard.toml").exists());
    }

    #[test]
    fn cmd_init_with_io_empty_path_errors() {
        let dir = TempDir::new().unwrap();
        let output = PathBuf::from("");

        with_current_dir(dir.path(), || {
            let args = InitArgs {
                preset: Preset::Minimal,
                output,
                force: true,
            };
            let mut input = std::io::Cursor::new("");
            let mut err = Vec::new();
            let res = cmd_init_with_io(args, &mut input, &mut err);
            assert!(res.is_err());
        });
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    #[test]
    fn confirm_overwrite_accepts_yes_variants() {
        let output = Path::new("diffguard.toml");

        let mut input = std::io::Cursor::new("y\n");
        let accepted = confirm_overwrite(&mut input, Vec::new(), output).unwrap();
        assert!(accepted);

        let mut input = std::io::Cursor::new("YES\n");
        let accepted = confirm_overwrite(&mut input, Vec::new(), output).unwrap();
        assert!(accepted);
    }

    #[test]
    fn confirm_overwrite_rejects_default_or_no() {
        let output = Path::new("diffguard.toml");

        let mut input = std::io::Cursor::new("\n");
        let accepted = confirm_overwrite(&mut input, Vec::new(), output).unwrap();
        assert!(!accepted);

        let mut input = std::io::Cursor::new("n\n");
        let accepted = confirm_overwrite(&mut input, Vec::new(), output).unwrap();
        assert!(!accepted);
    }

    #[test]
    fn confirm_overwrite_propagates_flush_error() {
        let output = Path::new("diffguard.toml");
        let mut input = std::io::Cursor::new("y\n");
        let err = confirm_overwrite(&mut input, FailingWriter, output).unwrap_err();
        assert!(err.to_string().contains("flush stderr"));
    }

    #[test]
    fn cmd_test_no_rules_defined_errors() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(dir.path(), "");

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Text,
        };
        let err = cmd_test(args).expect_err("empty config should error");
        assert!(err.to_string().contains("No rules defined"));
    }

    #[test]
    fn cmd_test_no_cases_json() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["TODO"]
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Json,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_test_text_failure_outputs_details() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "empty.rule"
severity = "warn"
message = "Empty"
patterns = ["EMPTY"]

[[rule]]
id = "fail.rule"
severity = "warn"
message = "Fail"
patterns = ["TODO"]

[[rule.test_cases]]
input = "OK"
should_match = true
description = "Expected TODO"
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Text,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn cmd_test_text_failures_with_empty_and_missing_description() {
        let dir = TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
[[rule]]
id = "desc.rule"
severity = "warn"
message = "Desc"
patterns = ["TODO"]

[[rule.test_cases]]
input = "OK"
should_match = true
description = ""

[[rule.test_cases]]
input = "NOPE"
should_match = true
"#,
        );

        let args = TestArgs {
            config: Some(config_path),
            no_default_rules: true,
            rule: None,
            format: TestFormat::Text,
        };
        let code = cmd_test(args).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn git_staged_diff_errors_outside_repo() {
        let dir = TempDir::new().unwrap();
        let err = with_current_dir(dir.path(), || git_staged_diff(0).expect_err("no repo"));
        assert!(err.to_string().contains("git diff --cached failed"));
    }

    #[test]
    fn write_json_and_text_without_parent() {
        let dir = TempDir::new().unwrap();
        with_current_dir(dir.path(), || {
            let json_path = Path::new("out.json");
            let text_path = Path::new("out.txt");
            write_json(json_path, &serde_json::json!({"ok": true})).unwrap();
            write_text(text_path, "hi").unwrap();
        });

        assert!(dir.path().join("out.json").exists());
        assert!(dir.path().join("out.txt").exists());
    }

    #[test]
    fn write_json_and_text_with_no_parent_errors() {
        let dir = TempDir::new().unwrap();
        with_current_dir(dir.path(), || {
            let json_path = Path::new("");
            let text_path = Path::new("");
            assert!(write_json(json_path, &serde_json::json!({"ok": true})).is_err());
            assert!(write_text(text_path, "hi").is_err());
        });
    }
}
