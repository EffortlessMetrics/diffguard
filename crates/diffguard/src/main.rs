use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use tracing::{debug, info};

use diffguard_app::{
    render_csv_for_receipt, render_junit_for_receipt, render_sarif_json, render_sensor_json,
    render_tsv_for_receipt, run_check, CheckPlan, RuleMetadata, SensorReportContext,
};
use diffguard_domain::compile_rules;
use diffguard_types::{
    Artifact, CapabilityStatus, CheckReceipt, ConfigFile, DiffMeta, FailOn, RuleConfig, Scope,
    ToolMeta, Verdict, VerdictCounts, VerdictStatus,
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
    /// Evaluate rules against added/changed lines in a git diff.
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

    /// Check only staged changes (for pre-commit hooks).
    ///
    /// Uses `git diff --cached` instead of base...head range.
    /// Mutually exclusive with --base and --head.
    #[arg(long, conflicts_with_all = ["base", "head"])]
    staged: bool,

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

    /// Enable rules with these tags (reserved for future use). Repeatable.
    #[arg(long, action = clap::ArgAction::Append, hide = true)]
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
    /// csharp, java, kotlin, shell, swift, scala, sql, xml, php
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
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on flags
    init_logging(cli.verbose, cli.debug);

    match cli.command {
        Commands::Check(args) => cmd_check(*args),
        Commands::Rules(args) => cmd_rules(args),
        Commands::Explain(args) => cmd_explain(args),
        Commands::Validate(args) => cmd_validate(args),
        Commands::Sarif(args) => cmd_sarif(args),
        Commands::Junit(args) => cmd_junit(args),
        Commands::Csv(args) => cmd_csv(args),
        Commands::Init(args) => cmd_init(args),
        Commands::Test(args) => cmd_test(args),
    }
}

/// Initialize tracing/logging based on CLI flags.
fn init_logging(verbose: bool, debug: bool) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let level = if debug {
        "debug"
    } else if verbose {
        "info"
    } else {
        "warn"
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();

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

fn cmd_validate(args: ValidateArgs) -> Result<()> {
    info!("Validating configuration file");

    // Determine config path
    let config_path = args.config.clone().or_else(|| {
        let p = PathBuf::from("diffguard.toml");
        if p.exists() {
            Some(p)
        } else {
            None
        }
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
        if let Err(e) = compile_rules(&cfg.rule) {
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

    if errors.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
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
                },
            )
        })
        .collect()
}

fn cmd_check(args: CheckArgs) -> Result<()> {
    let mode = resolve_mode(&args);
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
            std::process::exit(exit_code);
        }
        Mode::Cockpit => {
            // Cockpit mode: always try to write a receipt, exit 0 if successful
            match result {
                Ok(_exit_code) => {
                    // Check ran successfully, exit 0 (receipt was written)
                    std::process::exit(0);
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
                                "git".to_string(),
                                CapabilityStatus {
                                    status: "unavailable".to_string(),
                                    reason: Some(detail.clone()),
                                },
                            );

                            let ctx = SensorReportContext {
                                started_at: started_at.to_rfc3339(),
                                ended_at: ended_at.to_rfc3339(),
                                duration_ms,
                                capabilities,
                                artifacts: vec![],
                                rule_metadata: HashMap::new(),
                            };

                            // Try to write the sensor report
                            if let Some(sensor_path) = &args.sensor {
                                if let Ok(json) = render_sensor_json(&skip_receipt, &ctx) {
                                    if write_text(sensor_path, &json).is_ok() {
                                        eprintln!("diffguard: check skipped: {detail}");
                                        std::process::exit(0);
                                    }
                                }
                            }

                            // Also write the regular receipt
                            if write_json(&out_path, &skip_receipt).is_ok() {
                                eprintln!("diffguard: check skipped: {detail}");
                                std::process::exit(0);
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
                                if let Ok(json) = serde_json::to_string_pretty(&sensor_report) {
                                    if write_text(sensor_path, &json).is_ok() {
                                        eprintln!("diffguard: tool error: {detail}");
                                        std::process::exit(0);
                                    }
                                }
                            }

                            // Also write the regular receipt
                            if write_json(&out_path, &fail_receipt).is_ok() {
                                eprintln!("diffguard: tool error: {detail}");
                                std::process::exit(0);
                            }
                        }
                    }

                    // Could not write any receipt - catastrophic failure
                    eprintln!("diffguard: catastrophic failure: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Marker error type for cockpit skip classification.
///
/// When wrapped via `.context(CockpitSkipReason("token"))`, the classifier can
/// distinguish prerequisite-missing errors (→ Skip) from runtime errors (→ Fail).
#[derive(Debug)]
struct CockpitSkipReason(&'static str);

impl std::fmt::Display for CockpitSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CockpitSkipReason {}

/// Checks if the error chain contains a `CockpitSkipReason` marker and returns
/// the reason token if found. Untagged errors are treated as tool errors.
fn classify_cockpit_error(err: &anyhow::Error) -> Option<&'static str> {
    for cause in err.chain() {
        if let Some(reason) = cause.downcast_ref::<CockpitSkipReason>() {
            return Some(reason.0);
        }
    }
    None
}

/// Extracts the original error detail, skipping the `CockpitSkipReason` marker layer.
fn cockpit_error_detail(err: &anyhow::Error) -> String {
    // Walk the chain and collect messages, skipping the CockpitSkipReason marker itself
    let messages: Vec<String> = err
        .chain()
        .filter(|cause| cause.downcast_ref::<CockpitSkipReason>().is_none())
        .map(|cause| cause.to_string())
        .collect();
    messages.join(": ")
}

/// Builds a fail receipt for tool/runtime errors in cockpit mode.
fn build_tool_error_receipt(args: &CheckArgs, detail: &str) -> CheckReceipt {
    let base = args
        .base
        .clone()
        .unwrap_or_else(|| "origin/main".to_string());
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
            rule_id: "diffguard.internal".to_string(),
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
            reasons: vec!["tool_error".to_string()],
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
        "git".to_string(),
        CapabilityStatus {
            status: "unavailable".to_string(),
            reason: Some(detail.to_string()),
        },
    );
    SensorReportContext {
        started_at: started_at.to_rfc3339(),
        ended_at: ended_at.to_rfc3339(),
        duration_ms,
        capabilities,
        artifacts: vec![],
        rule_metadata: HashMap::new(),
    }
}

/// Builds a sensor.report.v1 directly for tool errors (without going through
/// the normal render pipeline, since the error may have prevented check setup).
fn build_tool_error_sensor_report(
    args: &CheckArgs,
    detail: &str,
    ctx: &SensorReportContext,
) -> diffguard_types::SensorReport {
    use diffguard_app::compute_fingerprint_raw;

    let base = args
        .base
        .clone()
        .unwrap_or_else(|| "origin/main".to_string());
    let head = args.head.clone().unwrap_or_else(|| "HEAD".to_string());

    let fingerprint_input = format!("diffguard.internal:runtime_error:{detail}");
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
            reasons: vec!["tool_error".to_string()],
        },
        findings: vec![diffguard_types::SensorFinding {
            check_id: "diffguard.internal".to_string(),
            code: "runtime_error".to_string(),
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
    let base = args
        .base
        .clone()
        .unwrap_or_else(|| "origin/main".to_string());
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

    // Handle --staged mode vs base/head mode
    let (base, head, diff_text) = if args.staged {
        info!("Checking staged changes");
        let diff_text =
            git_staged_diff(diff_context).context(CockpitSkipReason("no_diff_input"))?;
        ("(staged)".to_string(), "HEAD".to_string(), diff_text)
    } else {
        // Merge defaults (CLI overrides config).
        let base = args
            .base
            .clone()
            .or_else(|| cfg.defaults.base.clone())
            .unwrap_or_else(|| "origin/main".to_string());

        let head = args
            .head
            .clone()
            .or_else(|| cfg.defaults.head.clone())
            .unwrap_or_else(|| "HEAD".to_string());

        info!("Checking diff: {}...{}", base, head);
        let diff_text =
            git_diff(&base, &head, diff_context).context(CockpitSkipReason("missing_base"))?;
        (base, head, diff_text)
    };

    debug!("Diff text length: {} bytes", diff_text.len());

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
    };

    let run = run_check(&plan, &cfg, &diff_text)?;

    info!(
        "Check complete: {} findings, verdict={:?}",
        run.receipt.findings.len(),
        run.receipt.verdict.status
    );

    // Collect artifacts
    let mut artifacts = vec![Artifact {
        path: out_path.display().to_string().replace('\\', "/"),
        format: "json".to_string(),
    }];

    write_json(out_path, &run.receipt)?;

    if let Some(md_path) = &args.md {
        write_text(md_path, &run.markdown)?;
        artifacts.push(Artifact {
            path: md_path.display().to_string().replace('\\', "/"),
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
            path: sarif_path.display().to_string().replace('\\', "/"),
            format: "sarif".to_string(),
        });
    }

    if let Some(junit_path) = &args.junit {
        let junit = render_junit_for_receipt(&run.receipt);
        write_text(junit_path, &junit)?;
        artifacts.push(Artifact {
            path: junit_path.display().to_string().replace('\\', "/"),
            format: "junit".to_string(),
        });
    }

    if let Some(csv_path) = &args.csv {
        let csv = render_csv_for_receipt(&run.receipt);
        write_text(csv_path, &csv)?;
        artifacts.push(Artifact {
            path: csv_path.display().to_string().replace('\\', "/"),
            format: "csv".to_string(),
        });
    }

    if let Some(tsv_path) = &args.tsv {
        let tsv = render_tsv_for_receipt(&run.receipt);
        write_text(tsv_path, &tsv)?;
        artifacts.push(Artifact {
            path: tsv_path.display().to_string().replace('\\', "/"),
            format: "tsv".to_string(),
        });
    }

    // Write sensor report if requested
    if let Some(sensor_path) = &args.sensor {
        let ended_at = Utc::now();
        let duration_ms = (ended_at - *started_at).num_milliseconds().max(0) as u64;

        let mut capabilities = HashMap::new();
        capabilities.insert(
            "git".to_string(),
            CapabilityStatus {
                status: "available".to_string(),
                reason: None,
            },
        );

        artifacts.push(Artifact {
            path: sensor_path.display().to_string().replace('\\', "/"),
            format: "json".to_string(),
        });

        let ctx = SensorReportContext {
            started_at: started_at.to_rfc3339(),
            ended_at: ended_at.to_rfc3339(),
            duration_ms,
            capabilities,
            artifacts,
            rule_metadata: build_rule_metadata(&cfg),
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

fn cmd_init(args: InitArgs) -> Result<()> {
    let output_path = &args.output;

    // Check if file already exists
    if output_path.exists() && !args.force {
        // Prompt for confirmation
        eprint!(
            "Configuration file '{}' already exists. Overwrite? [y/N] ",
            output_path.display()
        );
        io::stderr().flush().context("flush stderr")?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).context("read stdin")?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            println!("Aborted.");
            return Ok(());
        }
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

fn cmd_test(args: TestArgs) -> Result<()> {
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
        if args.rule.is_some() {
            bail!("No rules match filter '{}'", args.rule.as_ref().unwrap());
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
        return Ok(());
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

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
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
    use diffguard_types::Severity;

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
            help: Some("Use ? operator instead.".to_string()),
            url: Some("https://example.com".to_string()),
            tags: vec![],
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
            help: None,
            url: None,
            tags: vec![],
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
                help: None,
                url: None,
                tags: vec![],
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
                help: None,
                url: None,
                tags: vec![],
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
            help: None,
            url: None,
            tags: vec![],
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("DIFFGUARD_TEST_MISSING_VAR"));
    }

    #[test]
    fn test_expand_env_vars_from_environment() {
        // Set a test environment variable
        std::env::set_var("DIFFGUARD_TEST_VAR", "test_value");
        let input = "hello ${DIFFGUARD_TEST_VAR}!";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "hello test_value!");
        std::env::remove_var("DIFFGUARD_TEST_VAR");
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
    }
}
