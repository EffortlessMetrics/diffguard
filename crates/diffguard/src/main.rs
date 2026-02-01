use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use diffguard_app::{
    render_csv_for_receipt, render_junit_for_receipt, render_sarif_json, render_tsv_for_receipt,
    run_check, CheckPlan,
};
use diffguard_types::{CheckReceipt, ConfigFile, FailOn, RuleConfig, Scope};

mod presets;
use presets::Preset;

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

    /// Show detailed information about a specific rule.
    Explain(ExplainArgs),

    /// Convert a JSON receipt to SARIF format (render-only mode).
    Sarif(SarifArgs),

    /// Convert a JSON receipt to JUnit XML format (render-only mode).
    Junit(JunitArgs),

    /// Convert a JSON receipt to CSV or TSV format (render-only mode).
    Csv(CsvArgs),

    /// Initialize a new diffguard.toml configuration file.
    Init(InitArgs),
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
        Commands::Explain(args) => cmd_explain(args),
        Commands::Sarif(args) => cmd_sarif(args),
        Commands::Junit(args) => cmd_junit(args),
        Commands::Csv(args) => cmd_csv(args),
        Commands::Init(args) => cmd_init(args),
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

fn cmd_check(args: CheckArgs) -> Result<()> {
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

    // Handle --staged mode vs base/head mode
    let (base, head, diff_text) = if args.staged {
        let diff_text = git_staged_diff(diff_context)?;
        ("(staged)".to_string(), "HEAD".to_string(), diff_text)
    } else {
        // Merge defaults (CLI overrides config).
        let base = args
            .base
            .or_else(|| cfg.defaults.base.clone())
            .unwrap_or_else(|| "origin/main".to_string());

        let head = args
            .head
            .or_else(|| cfg.defaults.head.clone())
            .unwrap_or_else(|| "HEAD".to_string());

        let diff_text = git_diff(&base, &head, diff_context)?;
        (base, head, diff_text)
    };

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

    if let Some(sarif_path) = args.sarif {
        let sarif = render_sarif_json(&run.receipt).context("render SARIF")?;
        write_text(&sarif_path, &sarif)?;
    }

    if let Some(junit_path) = args.junit {
        let junit = render_junit_for_receipt(&run.receipt);
        write_text(&junit_path, &junit)?;
    }

    if let Some(csv_path) = args.csv {
        let csv = render_csv_for_receipt(&run.receipt);
        write_text(&csv_path, &csv)?;
    }

    if let Some(tsv_path) = args.tsv {
        let tsv = render_tsv_for_receipt(&run.receipt);
        write_text(&tsv_path, &tsv)?;
    }

    std::process::exit(run.exit_code);
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
}
