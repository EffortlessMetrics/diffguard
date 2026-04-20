     1|#![allow(clippy::collapsible_if)]
     2|
     3|use std::collections::{BTreeMap, BTreeSet, HashMap};
     4|use std::io::{self, BufRead, IsTerminal, Read, Write};
     5|use std::path::{Path, PathBuf};
     6|use std::process::Command;
     7|use std::time::Instant;
     8|
     9|use anyhow::{Context, Result, bail};
    10|use chrono::Utc;
    11|use clap::{ColorChoice, Parser, Subcommand, ValueEnum};
    12|use tracing::{debug, info};
    13|
    14|use diffguard_analytics::{
    15|    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, TREND_HISTORY_SCHEMA_V1,
    16|    TrendHistory, append_trend_run, baseline_from_receipt, false_positive_fingerprint_set,
    17|    fingerprint_for_finding, merge_false_positive_baselines, normalize_false_positive_baseline,
    18|    normalize_trend_history, summarize_trend_history, trend_run_from_receipt,
    19|};
    20|use diffguard_core::{
    21|    CheckPlan, RuleMetadata, SensorReportContext, render_checkstyle_for_receipt,
    22|    render_csv_for_receipt, render_gitlab_quality_json, render_junit_for_receipt,
    23|    render_sarif_json, render_sensor_json, render_tsv_for_receipt, run_check,
    24|};
    25|use diffguard_diff::parse_unified_diff;
    26|use diffguard_domain::{DirectoryRuleOverride, compile_rules};
    27|use diffguard_types::{
    28|    Artifact, CAP_GIT, CAP_STATUS_AVAILABLE, CAP_STATUS_UNAVAILABLE, CHECK_ID_INTERNAL,
    29|    CHECK_SCHEMA_V1, CODE_TOOL_RUNTIME_ERROR, CapabilityStatus, CheckReceipt, ConfigFile, DiffMeta,
    30|    DirectoryOverrideConfig, FailOn, Finding, MatchMode, REASON_MISSING_BASE, REASON_NO_DIFF_INPUT,
    31|    REASON_TOOL_ERROR, RuleConfig, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    32|    VerdictStatus,
    33|};
    34|
    35|mod config_loader;
    36|mod presets;
    37|
    38|use config_loader::load_config_with_includes;
    39|use presets::Preset;
    40|
    41|#[derive(Parser)]
    42|#[command(name = "diffguard")]
    43|#[command(about = "Diff-scoped governance lint", long_about = None)]
    44|#[command(version)]
    45|struct Cli {
    46|    /// Enable verbose (info-level) logging to stderr.
    47|    #[arg(long, short = 'v', global = true)]
    48|    verbose: bool,
    49|
    50|    /// Enable debug-level logging to stderr.
    51|    #[arg(long, global = true)]
    52|    debug: bool,
    53|
    54|    /// Control colored output. never, always, auto.
    55|    #[arg(long, value_enum, global = true)]
    56|    color: Option<ColorChoice>,
    57|
    58|    #[command(subcommand)]
    59|    command: Commands,
    60|}
    61|
    62|#[derive(Subcommand)]
    63|enum Commands {
    64|    /// Evaluate rules against diff-scoped lines in a git diff.
    65|    Check(Box<CheckArgs>),
    66|
    67|    /// Print the effective rules (built-in + optional config merge).
    68|    Rules(RulesArgs),
    69|
    70|    /// Show detailed information about a specific rule.
    71|    Explain(ExplainArgs),
    72|
    73|    /// Validate the configuration file (check regex patterns and globs).
    74|    Validate(ValidateArgs),
    75|
    76|    /// Convert a JSON receipt to SARIF format (render-only mode).
    77|    Sarif(SarifArgs),
    78|
    79|    /// Convert a JSON receipt to JUnit XML format (render-only mode).
    80|    Junit(JunitArgs),
    81|
    82|    /// Convert a JSON receipt to CSV or TSV format (render-only mode).
    83|    Csv(CsvArgs),
    84|
    85|    /// Initialize a new diffguard.toml configuration file.
    86|    Init(InitArgs),
    87|
    88|    /// Run test cases defined in rule configurations.
    89|    Test(TestArgs),
    90|
    91|    /// Summarize historical check trends from a trend history file.
    92|    Trend(TrendArgs),
    93|
    94|    /// Check environment prerequisites (git, config, etc.).
    95|    Doctor(DoctorArgs),
    96|}
    97|
    98|#[derive(Parser, Debug)]
    99|struct RulesArgs {
   100|    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
   101|    #[arg(long)]
   102|    config: Option<PathBuf>,
   103|
   104|    /// Disable built-in rules; only use the config file.
   105|    #[arg(long)]
   106|    no_default_rules: bool,
   107|
   108|    #[arg(long, value_enum, default_value_t = RulesFormat::Toml)]
   109|    format: RulesFormat,
   110|}
   111|
   112|#[derive(Clone, Copy, Debug, ValueEnum)]
   113|enum RulesFormat {
   114|    Toml,
   115|    Json,
   116|}
   117|
   118|#[derive(Parser, Debug)]
   119|struct CheckArgs {
   120|    /// Base git ref (repeatable for multi-base comparison).
   121|    ///
   122|    /// Examples:
   123|    ///   --base origin/main
   124|    ///   --base origin/main --base origin/release/1.0
   125|    ///
   126|    /// When omitted, defaults to config defaults, else origin/main.
   127|    #[arg(long, action = clap::ArgAction::Append)]
   128|    base: Vec<String>,
   129|
   130|    /// Head git ref (defaults to config defaults, else HEAD).
   131|    #[arg(long)]
   132|    head: Option<String>,
   133|
   134|    /// Check only staged changes (for pre-commit hooks).
   135|    ///
   136|    /// Uses `git diff --cached` instead of base...head range.
   137|    /// Mutually exclusive with --base, --head, and --diff-file.
   138|    #[arg(long, conflicts_with_all = ["base", "head", "diff_file"])]
   139|    staged: bool,
   140|
   141|    /// Read unified diff input from a file (or '-' for stdin) instead of git.
   142|    ///
   143|    /// Mutually exclusive with --staged, --base, and --head.
   144|    #[arg(long, value_name = "PATH", conflicts_with_all = ["staged", "base", "head"])]
   145|    diff_file: Option<PathBuf>,
   146|
   147|    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
   148|    #[arg(long)]
   149|    config: Option<PathBuf>,
   150|
   151|    /// Disable built-in rules; only use the config file.
   152|    #[arg(long)]
   153|    no_default_rules: bool,
   154|
   155|    /// Scope of inspection.
   156|    #[arg(long, value_enum)]
   157|    scope: Option<ScopeArg>,
   158|
   159|    /// How many context lines to request from git (passed to --unified).
   160|    #[arg(long)]
   161|    diff_context: Option<u32>,
   162|
   163|    /// Fail policy.
   164|    #[arg(long, value_enum)]
   165|    fail_on: Option<FailOnArg>,
   166|
   167|    /// Maximum number of findings to include in the receipt.
   168|    #[arg(long)]
   169|    max_findings: Option<usize>,
   170|
   171|    /// Restrict to paths matching these glob patterns. Repeatable.
   172|    #[arg(long, action = clap::ArgAction::Append)]
   173|    paths: Vec<String>,
   174|
   175|    /// Only run rules that have at least one of these tags. Repeatable.
   176|    ///
   177|    /// When specified, rules without any matching tags are skipped.
   178|    /// Tags are matched case-insensitively.
   179|    #[arg(long, action = clap::ArgAction::Append)]
   180|    only_tags: Vec<String>,
   181|
   182|    /// Disable rules that have any of these tags. Repeatable.
   183|    ///
   184|    /// Rules with any matching tag are skipped. Applied after --only-tags.
   185|    /// Tags are matched case-insensitively.
   186|    #[arg(long, action = clap::ArgAction::Append)]
   187|    disable_tags: Vec<String>,
   188|
   189|    /// Add rules with these tags even when --only-tags is set. Repeatable.
   190|    #[arg(long, action = clap::ArgAction::Append)]
   191|    enable_tags: Vec<String>,
   192|
   193|    /// Where to write the JSON receipt.
   194|    ///
   195|    /// In standard mode, defaults to artifacts/diffguard/report.json.
   196|    /// In cockpit mode with --sensor, defaults to artifacts/diffguard/extras/check.json
   197|    /// (the canonical report.json path is used by the sensor envelope).
   198|    #[arg(long)]
   199|    out: Option<PathBuf>,
   200|
   201|    /// Write a Markdown summary.
   202|    ///
   203|    /// If provided with no value, defaults to artifacts/diffguard/comment.md
   204|    #[arg(
   205|        long,
   206|        value_name = "PATH",
   207|        num_args = 0..=1,
   208|        default_missing_value = "artifacts/diffguard/comment.md"
   209|    )]
   210|    md: Option<PathBuf>,
   211|
   212|    /// Emit GitHub Actions annotations to stdout.
   213|    #[arg(long)]
   214|    github_annotations: bool,
   215|
   216|    /// Write a SARIF report.
   217|    ///
   218|    /// If provided with no value, defaults to artifacts/diffguard/report.sarif.json
   219|    #[arg(
   220|        long,
   221|        value_name = "PATH",
   222|        num_args = 0..=1,
   223|        default_missing_value = "artifacts/diffguard/report.sarif.json"
   224|    )]
   225|    sarif: Option<PathBuf>,
   226|
   227|    /// Write a JUnit XML report.
   228|    ///
   229|    /// If provided with no value, defaults to artifacts/diffguard/report.xml
   230|    #[arg(
   231|        long,
   232|        value_name = "PATH",
   233|        num_args = 0..=1,
   234|        default_missing_value = "artifacts/diffguard/report.xml"
   235|    )]
   236|    junit: Option<PathBuf>,
   237|
   238|    /// Write a CSV report.
   239|    ///
   240|    /// If provided with no value, defaults to artifacts/diffguard/report.csv
   241|    #[arg(
   242|        long,
   243|        value_name = "PATH",
   244|        num_args = 0..=1,
   245|        default_missing_value = "artifacts/diffguard/report.csv"
   246|    )]
   247|    csv: Option<PathBuf>,
   248|
   249|    /// Write a TSV report.
   250|    ///
   251|    /// If provided with no value, defaults to artifacts/diffguard/report.tsv
   252|    #[arg(
   253|        long,
   254|        value_name = "PATH",
   255|        num_args = 0..=1,
   256|        default_missing_value = "artifacts/diffguard/report.tsv"
   257|    )]
   258|    tsv: Option<PathBuf>,
   259|
   260|    /// Write a GitLab Code Quality JSON report.
   261|    ///
   262|    /// If provided with no value, defaults to artifacts/diffguard/report.gitlab-quality.json
   263|    #[arg(
   264|        long,
   265|        value_name = "PATH",
   266|        num_args = 0..=1,
   267|        default_missing_value = "artifacts/diffguard/report.gitlab-quality.json"
   268|    )]
   269|    gitlab_quality: Option<PathBuf>,
   270|
   271|    /// Write a Checkstyle XML report.
   272|    ///
   273|    /// If provided with no value, defaults to artifacts/diffguard/report.checkstyle.xml
   274|    #[arg(
   275|        long,
   276|        value_name = "PATH",
   277|        num_args = 0..=1,
   278|        default_missing_value = "artifacts/diffguard/report.checkstyle.xml"
   279|    )]
   280|    checkstyle: Option<PathBuf>,
   281|
   282|    /// Write per-rule hit statistics as JSON.
   283|    ///
   284|    /// If provided with no value, defaults to artifacts/diffguard/rule-stats.json
   285|    #[arg(
   286|        long,
   287|        value_name = "PATH",
   288|        num_args = 0..=1,
   289|        default_missing_value = "artifacts/diffguard/rule-stats.json"
   290|    )]
   291|    rule_stats: Option<PathBuf>,
   292|
   293|    /// Read a false-positive baseline file and suppress matching findings.
   294|    #[arg(long, value_name = "PATH")]
   295|    false_positive_baseline: Option<PathBuf>,
   296|
   297|    /// Read a baseline receipt and annotate findings as baseline/new.
   298|    ///
   299|    /// When provided, findings are compared against the baseline receipt using
   300|    /// fingerprint matching (SHA-256 of rule_id:path:line:match_text).
   301|    /// Findings in the baseline are marked as "[BASELINE]", new findings as "[NEW]".
   302|    ///
   303|    /// Exit codes under baseline mode:
   304|    /// - 0: Only pre-existing (baseline) violations found
   305|    /// - 2: NEW violations found (fail CI/CD when new violations are introduced)
   306|    /// - 3: Only new warnings (when fail_on includes warn)
   307|    ///
   308|    /// NOTE: This is different from --false-positive-baseline which suppresses findings.
   309|    /// Baseline mode annotates all findings while tracking new violations separately.
   310|    #[arg(long, value_name = "PATH")]
   311|    baseline: Option<PathBuf>,
   312|
   313|    /// Report mode for baseline mode.
   314|    ///
   315|    /// - all: Show all findings with baseline/new annotations (default)
   316|    /// - new-only: Only show NEW findings (baseline findings are hidden)
   317|    #[arg(long, value_enum)]
   318|    report_mode: Option<ReportMode>,
   319|
   320|    /// Write/merge a false-positive baseline file from this run's findings.
   321|    ///
   322|    /// If provided with no value, defaults to artifacts/diffguard/false-positives.json
   323|    #[arg(
   324|        long,
   325|        value_name = "PATH",
   326|        num_args = 0..=1,
   327|        default_missing_value = "artifacts/diffguard/false-positives.json"
   328|    )]
   329|    write_false_positive_baseline: Option<PathBuf>,
   330|
   331|    /// Append this run to a trend history file for cross-run analytics.
   332|    ///
   333|    /// If provided with no value, defaults to artifacts/diffguard/trend-history.json
   334|    #[arg(
   335|        long,
   336|        value_name = "PATH",
   337|        num_args = 0..=1,
   338|        default_missing_value = "artifacts/diffguard/trend-history.json"
   339|    )]
   340|    trend_history: Option<PathBuf>,
   341|
   342|    /// Maximum number of runs to retain when writing trend history.
   343|    #[arg(long)]
   344|    trend_max_runs: Option<usize>,
   345|
   346|    /// Filter scoped lines to specific blame author patterns. Repeatable.
   347|    ///
   348|    /// Matches case-insensitive substrings against `author` and `author-mail`.
   349|    #[arg(long, action = clap::ArgAction::Append)]
   350|    blame_author: Vec<String>,
   351|
   352|    /// Filter scoped lines to commits no older than N days.
   353|    #[arg(long)]
   354|    blame_max_age_days: Option<u32>,
   355|
   356|    /// Execution mode.
   357|    ///
   358|    /// In standard mode, exit codes reflect the verdict (0=pass, 2=fail, 3=warn-fail).
   359|    /// In cockpit mode, exit 0 if a receipt was written, exit 1 only on catastrophic failure.
   360|    /// Can also be set via DIFFGUARD_MODE environment variable.
   361|    #[arg(long, value_enum, default_value_t = Mode::Standard)]
   362|    mode: Mode,
   363|
   364|    /// Write a sensor.report.v1 JSON file for Cockpit integration.
   365|    ///
   366|    /// If provided with no value, defaults to artifacts/diffguard/report.json
   367|    #[arg(
   368|        long,
   369|        value_name = "PATH",
   370|        num_args = 0..=1,
   371|        default_missing_value = "artifacts/diffguard/report.json"
   372|    )]
   373|    sensor: Option<PathBuf>,
   374|
   375|    /// Force all files to use the specified language for preprocessing.
   376|    ///
   377|    /// This overrides the auto-detected language from file extensions.
   378|    /// Valid values: rust, python, javascript, typescript, go, ruby, c, cpp,
   379|    /// csharp, java, kotlin, shell, swift, scala, sql, xml, php, yaml, toml, json
   380|    #[arg(long, value_enum)]
   381|    language: Option<LanguageArg>,
   382|}
   383|
   384|#[derive(Parser, Debug)]
   385|struct SarifArgs {
   386|    /// Path to a JSON receipt file to convert.
   387|    #[arg(long)]
   388|    report: PathBuf,
   389|
   390|    /// Output path for the SARIF file.
   391|    ///
   392|    /// If omitted, writes to stdout.
   393|    #[arg(long, short)]
   394|    output: Option<PathBuf>,
   395|}
   396|
   397|#[derive(Parser, Debug)]
   398|struct JunitArgs {
   399|    /// Path to a JSON receipt file to convert.
   400|    #[arg(long)]
   401|    report: PathBuf,
   402|
   403|    /// Output path for the JUnit XML file.
   404|    ///
   405|    /// If omitted, writes to stdout.
   406|    #[arg(long, short)]
   407|    output: Option<PathBuf>,
   408|}
   409|
   410|#[derive(Parser, Debug)]
   411|struct CsvArgs {
   412|    /// Path to a JSON receipt file to convert.
   413|    #[arg(long)]
   414|    report: PathBuf,
   415|
   416|    /// Output path for the CSV/TSV file.
   417|    ///
   418|    /// If omitted, writes to stdout.
   419|    #[arg(long, short)]
   420|    output: Option<PathBuf>,
   421|
   422|    /// Output as TSV instead of CSV.
   423|    #[arg(long)]
   424|    tsv: bool,
   425|}
   426|
   427|#[derive(Parser, Debug)]
   428|struct TrendArgs {
   429|    /// Path to the trend history JSON file.
   430|    #[arg(long, default_value = "artifacts/diffguard/trend-history.json")]
   431|    history: PathBuf,
   432|
   433|    /// Output format for trend summary.
   434|    #[arg(long, value_enum, default_value_t = TrendFormat::Text)]
   435|    format: TrendFormat,
   436|}
   437|
   438|#[derive(Clone, Copy, Debug, ValueEnum)]
   439|enum TrendFormat {
   440|    Text,
   441|    Json,
   442|}
   443|
   444|/// Report mode for baseline mode output filtering.
   445|#[derive(Clone, Copy, Debug, Default, ValueEnum)]
   446|enum ReportMode {
   447|    /// Show all findings with baseline/new annotations (default).
   448|    #[default]
   449|    All,
   450|    /// Show only new findings (baseline findings are hidden).
   451|    NewOnly,
   452|}
   453|
   454|#[derive(Parser, Debug)]
   455|struct ExplainArgs {
   456|    /// The rule ID to explain (e.g., "rust.no_unwrap").
   457|    rule_id: String,
   458|
   459|    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
   460|    #[arg(long)]
   461|    config: Option<PathBuf>,
   462|
   463|    /// Disable built-in rules; only use the config file.
   464|    #[arg(long)]
   465|    no_default_rules: bool,
   466|}
   467|
   468|#[derive(Parser, Debug)]
   469|struct InitArgs {
   470|    /// Configuration preset to use.
   471|    ///
   472|    /// Available presets:
   473|    /// - minimal: Basic starter config (default)
   474|    /// - rust-quality: Rust best practices
   475|    /// - secrets: Secret/credential detection
   476|    /// - js-console: JavaScript/TypeScript debugging
   477|    /// - python-debug: Python debugging
   478|    #[arg(long, short, value_enum, default_value_t = Preset::Minimal)]
   479|    preset: Preset,
   480|
   481|    /// Output path for the configuration file.
   482|    #[arg(long, short, default_value = "diffguard.toml")]
   483|    output: PathBuf,
   484|
   485|    /// Overwrite existing configuration file without prompting.
   486|    #[arg(long, short)]
   487|    force: bool,
   488|}
   489|
   490|#[derive(Parser, Debug)]
   491|struct ValidateArgs {
   492|    /// Path to a config file. If omitted, uses ./diffguard.toml if present.
   493|    #[arg(long)]
   494|    config: Option<PathBuf>,
   495|
   496|    /// Enable strict mode: also report best-practice warnings.
   497|    #[arg(long)]
   498|    strict: bool,
   499|
   500|    /// Output format for validation results.
   501|