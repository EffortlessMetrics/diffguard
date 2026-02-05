//! Data types (config + receipts) for diffguard.
//!
//! This crate is intentionally "dumb": pure DTOs with serde + schemars.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Schema Identifiers ─────────────────────────────────────────
pub const CHECK_SCHEMA_V1: &str = "diffguard.check.v1";
pub const SENSOR_REPORT_SCHEMA_V1: &str = "sensor.report.v1";

// ── Frozen Vocabulary ──────────────────────────────────────────
// Check IDs
pub const CHECK_ID_PATTERN: &str = "diffguard.pattern";
pub const CHECK_ID_INTERNAL: &str = "diffguard.internal";

// Reason tokens (snake_case)
pub const REASON_NO_DIFF_INPUT: &str = "no_diff_input";
pub const REASON_MISSING_BASE: &str = "missing_base";
pub const REASON_GIT_UNAVAILABLE: &str = "git_unavailable";
pub const REASON_TOOL_ERROR: &str = "tool_error";
/// Deprecated: no longer emitted in verdict.reasons (redundant with verdict.counts).
/// Retained for backward-compatible vocabulary validation.
pub const REASON_HAS_ERROR: &str = "has_error";
/// Deprecated: no longer emitted in verdict.reasons (redundant with verdict.counts).
/// Retained for backward-compatible vocabulary validation.
pub const REASON_HAS_WARNING: &str = "has_warning";
pub const REASON_TRUNCATED: &str = "truncated";

// Tool error code (R1 survivability)
pub const CODE_TOOL_RUNTIME_ERROR: &str = "tool.runtime_error";

// Capability names
pub const CAP_GIT: &str = "git";

// Capability statuses
pub const CAP_STATUS_AVAILABLE: &str = "available";
pub const CAP_STATUS_UNAVAILABLE: &str = "unavailable";
pub const CAP_STATUS_SKIPPED: &str = "skipped";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Added,
    Changed,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Added => "added",
            Scope::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailOn {
    Error,
    Warn,
    Never,
}

impl FailOn {
    pub fn as_str(self) -> &'static str {
        match self {
            FailOn::Error => "error",
            FailOn::Warn => "warn",
            FailOn::Never => "never",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiffMeta {
    pub base: String,
    pub head: String,
    pub context_lines: u32,
    pub scope: Scope,
    pub files_scanned: u32,
    pub lines_scanned: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub path: String,
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    pub match_text: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pass,
    Warn,
    Fail,
    /// For cockpit mode when inputs are missing or check cannot run.
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct VerdictCounts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
    /// Number of matches suppressed via inline directives.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suppressed: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub counts: VerdictCounts,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckReceipt {
    pub schema: String,
    pub tool: ToolMeta,
    pub diff: DiffMeta,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingMetrics>,
}

/// Timing metrics for performance analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimingMetrics {
    pub total_ms: u64,
    pub diff_parse_ms: u64,
    pub rule_compile_ms: u64,
    pub evaluation_ms: u64,
}

/// The on-disk configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigFile {
    /// Include other config files. Paths are relative to this config file's directory.
    /// Rules are merged: later definitions override earlier ones by rule ID.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,

    #[serde(default)]
    pub defaults: Defaults,

    #[serde(default)]
    pub rule: Vec<RuleConfig>,
}

impl ConfigFile {
    pub fn built_in() -> Self {
        Self {
            includes: vec![],
            defaults: Defaults::default(),
            rule: vec![
                // ============================================================
                // Rust rules
                // ============================================================
                RuleConfig {
                    id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap/expect in production code.".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec!["\\.unwrap\\(".to_string(), "\\.expect\\(".to_string()],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec![
                        "**/tests/**".to_string(),
                        "**/benches/**".to_string(),
                        "**/examples/**".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use the ? operator to propagate errors, or use expect() with a \
                        meaningful message that explains the invariant. Consider using \
                        anyhow or thiserror for structured error handling."
                            .to_string(),
                    ),
                    url: Some(
                        "https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html"
                            .to_string(),
                    ),
                    tags: vec!["safety".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "rust.no_dbg".to_string(),
                    severity: Severity::Warn,
                    message: "Remove dbg!/println! before merging.".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec![
                        "\\bdbg!\\(".to_string(),
                        "\\bprintln!\\(".to_string(),
                        "\\beprintln!\\(".to_string(),
                    ],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec![
                        "**/tests/**".to_string(),
                        "**/benches/**".to_string(),
                        "**/examples/**".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove debug output before merging. For logging, use the log or \
                        tracing crate instead. If you need to keep the output, consider \
                        using conditional compilation with #[cfg(debug_assertions)]."
                            .to_string(),
                    ),
                    url: Some("https://doc.rust-lang.org/std/macro.dbg.html".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "rust.no_todo".to_string(),
                    severity: Severity::Warn,
                    message: "Resolve TODO/FIXME comments before merging.".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec![
                        r"\bTODO\b".to_string(),
                        r"\bFIXME\b".to_string(),
                        r"\btodo!\s*\(".to_string(),
                        r"\bunimplemented!\s*\(".to_string(),
                    ],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: true,
                    help: Some(
                        "Address TODO/FIXME comments before merging, or create tracking \
                        issues for planned work. The todo! and unimplemented! macros will \
                        panic at runtime."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["style".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Python rules
                // ============================================================
                RuleConfig {
                    id: "python.no_print".to_string(),
                    severity: Severity::Warn,
                    message: "Remove print() before merging.".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![r"\bprint\s*\(".to_string()],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec!["**/tests/**".to_string(), "**/test_*.py".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use the logging module instead of print() for production code. \
                        Configure logging levels appropriately (DEBUG, INFO, WARNING, ERROR)."
                            .to_string(),
                    ),
                    url: Some("https://docs.python.org/3/library/logging.html".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "python.no_pdb".to_string(),
                    severity: Severity::Error,
                    message: "Remove debugger statements before merging.".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![
                        r"\bimport\s+pdb\b".to_string(),
                        r"\bpdb\.set_trace\s*\(".to_string(),
                    ],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove pdb debugger statements before merging. These will cause \
                        the application to pause and wait for interactive input in production."
                            .to_string(),
                    ),
                    url: Some("https://docs.python.org/3/library/pdb.html".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "python.no_breakpoint".to_string(),
                    severity: Severity::Error,
                    message: "Remove breakpoint() calls before merging.".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![r"\bbreakpoint\s*\(".to_string()],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove breakpoint() calls before merging. The breakpoint() function \
                        (Python 3.7+) invokes the debugger and will pause execution in production."
                            .to_string(),
                    ),
                    url: Some("https://docs.python.org/3/library/functions.html#breakpoint".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // JavaScript/TypeScript rules
                // ============================================================
                RuleConfig {
                    id: "js.no_console".to_string(),
                    severity: Severity::Warn,
                    message: "Remove console.log before merging.".to_string(),
                    languages: vec!["javascript".to_string(), "typescript".to_string()],
                    patterns: vec![r"\bconsole\.(log|debug|info)\s*\(".to_string()],
                    paths: vec![
                        "**/*.js".to_string(),
                        "**/*.ts".to_string(),
                        "**/*.jsx".to_string(),
                        "**/*.tsx".to_string(),
                    ],
                    exclude_paths: vec![
                        "**/tests/**".to_string(),
                        "**/*.test.*".to_string(),
                        "**/*.spec.*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use a proper logging library (e.g., winston, pino, bunyan) instead \
                        of console.log. For client-side code, consider using a logger that \
                        can be disabled in production builds."
                            .to_string(),
                    ),
                    url: Some(
                        "https://developer.mozilla.org/en-US/docs/Web/API/console".to_string(),
                    ),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "js.no_debugger".to_string(),
                    severity: Severity::Error,
                    message: "Remove debugger statements before merging.".to_string(),
                    languages: vec!["javascript".to_string(), "typescript".to_string()],
                    patterns: vec![r"\bdebugger\b".to_string()],
                    paths: vec![
                        "**/*.js".to_string(),
                        "**/*.ts".to_string(),
                        "**/*.jsx".to_string(),
                        "**/*.tsx".to_string(),
                    ],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove debugger statements before merging. These will pause \
                        execution in the browser's developer tools, which is not intended \
                        for production code."
                            .to_string(),
                    ),
                    url: Some(
                        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/debugger"
                            .to_string(),
                    ),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Ruby rules
                // ============================================================
                RuleConfig {
                    id: "ruby.no_binding_pry".to_string(),
                    severity: Severity::Error,
                    message: "Remove binding.pry before merging.".to_string(),
                    languages: vec!["ruby".to_string()],
                    patterns: vec![r"\bbinding\.pry\b".to_string()],
                    paths: vec!["**/*.rb".to_string(), "**/*.rake".to_string()],
                    exclude_paths: vec!["**/test/**".to_string(), "**/spec/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove binding.pry debugger statements before merging. These will \
                        pause execution and open an interactive REPL in production."
                            .to_string(),
                    ),
                    url: Some("https://github.com/pry/pry".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "ruby.no_byebug".to_string(),
                    severity: Severity::Error,
                    message: "Remove byebug statements before merging.".to_string(),
                    languages: vec!["ruby".to_string()],
                    patterns: vec![r"\bbyebug\b".to_string()],
                    paths: vec!["**/*.rb".to_string(), "**/*.rake".to_string()],
                    exclude_paths: vec!["**/test/**".to_string(), "**/spec/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Remove byebug debugger statements before merging. These will \
                        pause execution and open an interactive debugger in production."
                            .to_string(),
                    ),
                    url: Some("https://github.com/deivid-rodriguez/byebug".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Java rules
                // ============================================================
                RuleConfig {
                    id: "java.no_sout".to_string(),
                    severity: Severity::Warn,
                    message: "Remove System.out.println before merging.".to_string(),
                    languages: vec!["java".to_string()],
                    patterns: vec![r"\bSystem\.out\.println\s*\(".to_string()],
                    paths: vec!["**/*.java".to_string()],
                    exclude_paths: vec!["**/test/**".to_string(), "**/tests/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use a logging framework (e.g., SLF4J, Log4j, java.util.logging) instead \
                        of System.out.println for production code. Logging frameworks provide \
                        log levels, formatting, and configurable output destinations."
                            .to_string(),
                    ),
                    url: Some("https://www.slf4j.org/".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // C# rules
                // ============================================================
                RuleConfig {
                    id: "csharp.no_console".to_string(),
                    severity: Severity::Warn,
                    message: "Remove Console.WriteLine before merging.".to_string(),
                    languages: vec!["csharp".to_string()],
                    patterns: vec![r"\bConsole\.WriteLine\s*\(".to_string()],
                    paths: vec!["**/*.cs".to_string()],
                    exclude_paths: vec!["**/Tests/**".to_string(), "**/*.Tests/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use a logging framework (e.g., Serilog, NLog, Microsoft.Extensions.Logging) \
                        instead of Console.WriteLine for production code. Logging frameworks provide \
                        structured logging, log levels, and configurable sinks."
                            .to_string(),
                    ),
                    url: Some("https://learn.microsoft.com/en-us/dotnet/core/extensions/logging".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Go rules
                // ============================================================
                RuleConfig {
                    id: "go.no_fmt_print".to_string(),
                    severity: Severity::Warn,
                    message: "Remove fmt.Print* before merging.".to_string(),
                    languages: vec!["go".to_string()],
                    patterns: vec![r"\bfmt\.(Print|Println|Printf)\s*\(".to_string()],
                    paths: vec!["**/*.go".to_string()],
                    exclude_paths: vec!["**/*_test.go".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use the log package or a structured logging library (e.g., zap, \
                        zerolog, logrus) instead of fmt.Print* for production code."
                            .to_string(),
                    ),
                    url: Some("https://pkg.go.dev/log".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "go.no_panic".to_string(),
                    severity: Severity::Warn,
                    message: "Avoid panic() in production code.".to_string(),
                    languages: vec!["go".to_string()],
                    patterns: vec![r"\bpanic\s*\(".to_string()],
                    paths: vec!["**/*.go".to_string()],
                    exclude_paths: vec!["**/*_test.go".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Return errors instead of panicking. Use panic only for truly \
                        unrecoverable situations. Consider using errors.New() or fmt.Errorf() \
                        to create descriptive error values that callers can handle gracefully."
                            .to_string(),
                    ),
                    url: Some("https://go.dev/doc/effective_go#errors".to_string()),
                    tags: vec!["safety".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Kotlin rules
                // ============================================================
                RuleConfig {
                    id: "kotlin.no_println".to_string(),
                    severity: Severity::Warn,
                    message: "Remove println() before merging.".to_string(),
                    languages: vec!["kotlin".to_string()],
                    patterns: vec![r"\bprintln\s*\(".to_string()],
                    paths: vec!["**/*.kt".to_string(), "**/*.kts".to_string()],
                    exclude_paths: vec!["**/test/**".to_string(), "**/tests/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use a logging framework (e.g., SLF4J, Logback, kotlin-logging) instead \
                        of println() for production code. Logging frameworks provide log levels, \
                        structured output, and configurable destinations."
                            .to_string(),
                    ),
                    url: Some("https://www.slf4j.org/".to_string()),
                    tags: vec!["debug".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Secret/Credential detection rules
                // ============================================================
                RuleConfig {
                    id: "secrets.aws_access_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential AWS Access Key ID detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"AKIA[0-9A-Z]{16}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "AWS Access Key IDs should never be committed to source control. \
                        Use environment variables, AWS IAM roles, or a secrets manager \
                        (e.g., AWS Secrets Manager, HashiCorp Vault) to manage credentials."
                            .to_string(),
                    ),
                    url: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.github_token".to_string(),
                    severity: Severity::Error,
                    message: "Potential GitHub token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "GitHub tokens should never be committed to source control. \
                        Use environment variables or GitHub Actions secrets to manage tokens. \
                        If a token was accidentally committed, revoke it immediately."
                            .to_string(),
                    ),
                    url: Some("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.generic_api_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential API key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']{16,}["']"#.to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/CHANGELOG*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "API keys should not be hardcoded in source files. \
                        Use environment variables or a secrets manager to inject credentials \
                        at runtime. Consider using .env files (excluded from version control) \
                        for local development."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.private_key".to_string(),
                    severity: Severity::Error,
                    message: "Private key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Private keys must never be committed to source control. \
                        Store private keys securely using a secrets manager, encrypted storage, \
                        or environment variables. If a private key was accidentally committed, \
                        consider it compromised and generate a new key pair."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.slack_token".to_string(),
                    severity: Severity::Error,
                    message: "Potential Slack token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"xox[baprs]-[0-9a-zA-Z]{10,}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Slack tokens should never be committed to source control. \
                        Use environment variables or a secrets manager. If a token was \
                        accidentally committed, revoke it in your Slack workspace settings."
                            .to_string(),
                    ),
                    url: Some("https://api.slack.com/authentication/token-types".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.stripe_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential Stripe API key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"(sk|rk)_live_[0-9a-zA-Z]{24,}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Stripe live API keys should never be committed to source control. \
                        Use environment variables or a secrets manager. If a key was \
                        accidentally committed, rotate it immediately in your Stripe dashboard."
                            .to_string(),
                    ),
                    url: Some("https://stripe.com/docs/keys".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.google_api_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential Google API key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"AIza[0-9A-Za-z\-_]{35}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Google API keys should not be committed to source control. \
                        Use environment variables or Google Cloud Secret Manager. \
                        Restrict the key's allowed APIs and referrers in the Google Cloud Console."
                            .to_string(),
                    ),
                    url: Some("https://cloud.google.com/docs/authentication/api-keys".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.twilio_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential Twilio API key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"SK[0-9a-fA-F]{32}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Twilio API keys should not be committed to source control. \
                        Use environment variables or a secrets manager. If compromised, \
                        revoke the key in your Twilio console."
                            .to_string(),
                    ),
                    url: Some("https://www.twilio.com/docs/iam/api-keys".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.npm_token".to_string(),
                    severity: Severity::Error,
                    message: "Potential npm token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"npm_[0-9a-zA-Z]{36}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "npm tokens should not be committed to source control. \
                        Use environment variables or npm's built-in .npmrc configuration. \
                        If compromised, revoke the token on npmjs.com."
                            .to_string(),
                    ),
                    url: Some("https://docs.npmjs.com/about-access-tokens".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.pypi_token".to_string(),
                    severity: Severity::Error,
                    message: "Potential PyPI token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"pypi-[0-9a-zA-Z_-]{50,}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "PyPI tokens should not be committed to source control. \
                        Use environment variables or a secrets manager. \
                        If compromised, revoke the token on pypi.org."
                            .to_string(),
                    ),
                    url: Some("https://pypi.org/help/#apitoken".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.password_assignment".to_string(),
                    severity: Severity::Warn,
                    message: "Potential hardcoded password detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#.to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/*.example*".to_string(),
                        "**/*test*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: false,
                    help: Some(
                        "Passwords should not be hardcoded in source files. \
                        Use environment variables, a secrets manager, or secure configuration \
                        files excluded from version control."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "secrets.jwt_token".to_string(),
                    severity: Severity::Warn,
                    message: "Potential JWT token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/*test*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: false,
                    help: Some(
                        "JWT tokens should not be hardcoded in source files. \
                        They may contain sensitive claims or grant unauthorized access. \
                        Generate tokens dynamically at runtime."
                            .to_string(),
                    ),
                    url: Some("https://jwt.io/introduction".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                // ============================================================
                // Security-focused rules
                // ============================================================
                RuleConfig {
                    id: "security.hardcoded_ipv4".to_string(),
                    severity: Severity::Warn,
                    message: "Hardcoded IPv4 address detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/*test*".to_string(),
                        "**/Dockerfile*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: false,
                    help: Some(
                        "Hardcoded IP addresses make code inflexible and can expose internal \
                        network topology. Use configuration files, environment variables, \
                        or DNS names instead."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "security.http_url".to_string(),
                    severity: Severity::Warn,
                    message: "Non-HTTPS URL detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r#"["']http://[^"']+["']"#.to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/*test*".to_string(),
                        "**/localhost*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: false,
                    help: Some(
                        "Use HTTPS instead of HTTP for secure communication. \
                        HTTP transmits data in plaintext, making it vulnerable to \
                        man-in-the-middle attacks."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "js.no_eval".to_string(),
                    severity: Severity::Error,
                    message: "Avoid eval() - potential code injection risk.".to_string(),
                    languages: vec!["javascript".to_string(), "typescript".to_string()],
                    patterns: vec![r"\beval\s*\(".to_string(), r"\bFunction\s*\(".to_string()],
                    paths: vec![
                        "**/*.js".to_string(),
                        "**/*.ts".to_string(),
                        "**/*.jsx".to_string(),
                        "**/*.tsx".to_string(),
                    ],
                    exclude_paths: vec!["**/*test*".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "eval() and the Function constructor execute arbitrary code, \
                        creating severe security risks. Use safer alternatives like \
                        JSON.parse() for data or template literals for strings."
                            .to_string(),
                    ),
                    url: Some("https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "python.no_eval".to_string(),
                    severity: Severity::Error,
                    message: "Avoid eval()/exec() - potential code injection risk.".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![r"\beval\s*\(".to_string(), r"\bexec\s*\(".to_string()],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec!["**/*test*".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "eval() and exec() execute arbitrary Python code, creating severe \
                        security risks. Use ast.literal_eval() for safe literal evaluation \
                        or find alternative approaches."
                            .to_string(),
                    ),
                    url: Some("https://docs.python.org/3/library/functions.html#eval".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "ruby.no_eval".to_string(),
                    severity: Severity::Error,
                    message: "Avoid eval/instance_eval - potential code injection risk.".to_string(),
                    languages: vec!["ruby".to_string()],
                    patterns: vec![r"\beval\s*[\(\s]".to_string(), r"\binstance_eval\s*[\(\s{]".to_string()],
                    paths: vec!["**/*.rb".to_string(), "**/*.rake".to_string()],
                    exclude_paths: vec!["**/*test*".to_string(), "**/spec/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "eval and instance_eval execute arbitrary Ruby code, creating severe \
                        security risks. Use safer metaprogramming techniques like \
                        define_method or public_send."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "php.no_eval".to_string(),
                    severity: Severity::Error,
                    message: "Avoid eval()/create_function() - potential code injection risk.".to_string(),
                    languages: vec!["php".to_string()],
                    patterns: vec![r"\beval\s*\(".to_string(), r"\bcreate_function\s*\(".to_string()],
                    paths: vec!["**/*.php".to_string()],
                    exclude_paths: vec!["**/*test*".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "eval() and create_function() execute arbitrary PHP code, creating \
                        severe security risks. Use anonymous functions or other safe alternatives."
                            .to_string(),
                    ),
                    url: Some("https://www.php.net/manual/en/function.eval.php".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "shell.no_eval".to_string(),
                    severity: Severity::Error,
                    message: "Avoid eval in shell scripts - potential code injection risk.".to_string(),
                    languages: vec!["shell".to_string()],
                    patterns: vec![r"\beval\s+".to_string()],
                    paths: vec![
                        "**/*.sh".to_string(),
                        "**/*.bash".to_string(),
                        "**/*.zsh".to_string(),
                    ],
                    exclude_paths: vec!["**/*test*".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "eval in shell scripts executes arbitrary commands, creating \
                        severe security risks especially with user input. Use safer \
                        alternatives like arrays or direct command execution."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "security.sql_concat".to_string(),
                    severity: Severity::Warn,
                    message: "Potential SQL injection - avoid string concatenation in queries.".to_string(),
                    languages: vec![],
                    patterns: vec![
                        r#"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+.*["']"#.to_string(),
                        r#"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*["'].*\+"#.to_string(),
                    ],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*test*".to_string(),
                        "**/*.md".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: false,
                    help: Some(
                        "String concatenation in SQL queries can lead to SQL injection attacks. \
                        Use parameterized queries or prepared statements instead."
                            .to_string(),
                    ),
                    url: Some("https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html".to_string()),
                    tags: vec!["security".to_string()],
                    test_cases: vec![],
                },
                RuleConfig {
                    id: "go.no_panic".to_string(),
                    severity: Severity::Warn,
                    message: "Avoid panic() in production code.".to_string(),
                    languages: vec!["go".to_string()],
                    patterns: vec![r"\bpanic\s*\(".to_string()],
                    paths: vec!["**/*.go".to_string()],
                    exclude_paths: vec!["**/*_test.go".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Return errors instead of panicking. Use panic only for truly \
                        unrecoverable situations. Consider using errors.New() or fmt.Errorf() \
                        to create descriptive error values that callers can handle gracefully."
                            .to_string(),
                    ),
                    url: Some("https://go.dev/doc/effective_go#errors".to_string()),
                    tags: vec!["safety".to_string()],
                },
                // ============================================================
                // Kotlin rules
                // ============================================================
                RuleConfig {
                    id: "kotlin.no_println".to_string(),
                    severity: Severity::Warn,
                    message: "Remove println() before merging.".to_string(),
                    languages: vec!["kotlin".to_string()],
                    patterns: vec![r"\bprintln\s*\(".to_string()],
                    paths: vec!["**/*.kt".to_string(), "**/*.kts".to_string()],
                    exclude_paths: vec!["**/test/**".to_string(), "**/tests/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: Some(
                        "Use a logging framework (e.g., SLF4J, Logback, kotlin-logging) instead \
                        of println() for production code. Logging frameworks provide log levels, \
                        structured output, and configurable destinations."
                            .to_string(),
                    ),
                    url: Some("https://www.slf4j.org/".to_string()),
                    tags: vec!["debug".to_string()],
                },
                // ============================================================
                // Secret/Credential detection rules
                // ============================================================
                RuleConfig {
                    id: "secrets.aws_access_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential AWS Access Key ID detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"AKIA[0-9A-Z]{16}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "AWS Access Key IDs should never be committed to source control. \
                        Use environment variables, AWS IAM roles, or a secrets manager \
                        (e.g., AWS Secrets Manager, HashiCorp Vault) to manage credentials."
                            .to_string(),
                    ),
                    url: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html".to_string()),
                    tags: vec!["security".to_string()],
                },
                RuleConfig {
                    id: "secrets.github_token".to_string(),
                    severity: Severity::Error,
                    message: "Potential GitHub token detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "GitHub tokens should never be committed to source control. \
                        Use environment variables or GitHub Actions secrets to manage tokens. \
                        If a token was accidentally committed, revoke it immediately."
                            .to_string(),
                    ),
                    url: Some("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens".to_string()),
                    tags: vec!["security".to_string()],
                },
                RuleConfig {
                    id: "secrets.generic_api_key".to_string(),
                    severity: Severity::Error,
                    message: "Potential API key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']{16,}["']"#.to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                        "**/CHANGELOG*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "API keys should not be hardcoded in source files. \
                        Use environment variables or a secrets manager to inject credentials \
                        at runtime. Consider using .env files (excluded from version control) \
                        for local development."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                },
                RuleConfig {
                    id: "secrets.private_key".to_string(),
                    severity: Severity::Error,
                    message: "Private key detected.".to_string(),
                    languages: vec![],
                    patterns: vec![r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string()],
                    paths: vec![],
                    exclude_paths: vec![
                        "**/*.md".to_string(),
                        "**/README*".to_string(),
                    ],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: Some(
                        "Private keys must never be committed to source control. \
                        Store private keys securely using a secrets manager, encrypted storage, \
                        or environment variables. If a private key was accidentally committed, \
                        consider it compromised and generate a new key pair."
                            .to_string(),
                    ),
                    url: None,
                    tags: vec!["security".to_string()],
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Defaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<FailOn>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_findings: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_context: Option<u32>,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(Scope::Added),
            fail_on: Some(FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleConfig {
    pub id: String,
    pub severity: Severity,
    pub message: String,

    /// Optional language tags (e.g. "rust"). Empty means "all".
    #[serde(default)]
    pub languages: Vec<String>,

    /// One or more regex patterns.
    pub patterns: Vec<String>,

    /// Include path globs. Empty means "all".
    #[serde(default)]
    pub paths: Vec<String>,

    /// Exclude path globs.
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    #[serde(default)]
    pub ignore_comments: bool,

    #[serde(default)]
    pub ignore_strings: bool,

    /// Optional help text explaining how to fix violations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,

    /// Optional URL with more information about the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Tags for grouping/filtering rules (e.g., "debug", "security", "style").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Test cases for validating this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_cases: Vec<RuleTestCase>,
}

/// A test case for validating a rule's behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleTestCase {
    /// The input line to test against the rule.
    pub input: String,

    /// Whether the rule should match this input.
    pub should_match: bool,

    /// Optional: override ignore_comments for this test case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_comments: Option<bool>,

    /// Optional: override ignore_strings for this test case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_strings: Option<bool>,

    /// Optional: specify a language for preprocessing (e.g., "rust", "python").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// Optional: description of what this test case validates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ============================================================================
// Per-directory override types
// ============================================================================

/// Per-directory override configuration (.diffguard.toml).
///
/// These files can be placed in any directory to override rule behavior
/// for files in that directory and its subdirectories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct DirectoryOverrideConfig {
    /// Rule-specific overrides.
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleOverride>,
}

/// Override settings for a specific rule in a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleOverride {
    /// The rule ID to override (e.g., "rust.no_unwrap").
    pub id: String,

    /// Set to false to disable this rule for this directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Override the severity for this directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,

    /// Additional paths to exclude within this directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
}

// ============================================================================
// sensor.report.v1 types (Cockpit ecosystem integration)
// ============================================================================

/// The `sensor.report.v1` envelope for Cockpit ecosystem integration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SensorReport {
    /// Schema identifier, always "sensor.report.v1".
    pub schema: String,
    /// Tool metadata.
    pub tool: ToolMeta,
    /// Run timing and capability information.
    pub run: RunMeta,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Findings in sensor format.
    pub findings: Vec<SensorFinding>,
    /// List of artifacts produced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    /// Additional data payload (diff metadata, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Run timing and capability status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunMeta {
    /// ISO 8601 timestamp when the run started.
    pub started_at: String,
    /// ISO 8601 timestamp when the run ended.
    pub ended_at: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Capability status map (e.g., "git" -> available/unavailable).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub capabilities: HashMap<String, CapabilityStatus>,
}

/// Status of a capability (e.g., git availability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityStatus {
    /// Status: "available", "unavailable", or "skipped".
    pub status: String,
    /// Stable token reason (e.g., "missing_base", "tool_error").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable detail for diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A finding in sensor.report.v1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SensorFinding {
    /// Check identifier (constant: "diffguard.pattern").
    pub check_id: String,
    /// Rule code (maps from rule_id, e.g., "rust.no_unwrap").
    pub code: String,
    /// Finding severity.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Location in the source.
    pub location: SensorLocation,
    /// Stable fingerprint (full SHA-256, 64 hex chars).
    pub fingerprint: String,
    /// Optional help text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Optional URL for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Additional data (match_text, snippet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Location in sensor.report.v1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SensorLocation {
    /// Repo-relative path with forward slashes.
    pub path: String,
    /// Line number (1-based).
    pub line: u32,
    /// Optional column number (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// An artifact produced by the sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    /// Path to the artifact file.
    pub path: String,
    /// Format of the artifact (e.g., "json", "sarif", "markdown").
    pub format: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_scope_failon_as_str() {
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Warn.as_str(), "warn");
        assert_eq!(Severity::Error.as_str(), "error");

        assert_eq!(Scope::Added.as_str(), "added");
        assert_eq!(Scope::Changed.as_str(), "changed");

        assert_eq!(FailOn::Error.as_str(), "error");
        assert_eq!(FailOn::Warn.as_str(), "warn");
        assert_eq!(FailOn::Never.as_str(), "never");
    }

    #[test]
    fn defaults_match_expected_values() {
        let defaults = Defaults::default();
        assert_eq!(defaults.base.as_deref(), Some("origin/main"));
        assert_eq!(defaults.head.as_deref(), Some("HEAD"));
        assert_eq!(defaults.scope, Some(Scope::Added));
        assert_eq!(defaults.fail_on, Some(FailOn::Error));
        assert_eq!(defaults.max_findings, Some(200));
        assert_eq!(defaults.diff_context, Some(0));
    }

    #[test]
    fn verdict_counts_suppressed_is_omitted_when_zero() {
        let counts = VerdictCounts::default();
        let value = serde_json::to_value(&counts).expect("serialize verdict counts");
        let obj = value.as_object().expect("counts should be object");
        assert!(!obj.contains_key("suppressed"));

        let with_suppressed = VerdictCounts {
            suppressed: 2,
            ..VerdictCounts::default()
        };
        let value = serde_json::to_value(&with_suppressed).expect("serialize verdict counts");
        let obj = value.as_object().expect("counts should be object");
        assert_eq!(obj.get("suppressed").and_then(|v| v.as_u64()), Some(2));
    }

    #[test]
    fn built_in_config_contains_expected_rules_and_unique_ids() {
        let cfg = ConfigFile::built_in();
        assert!(cfg.rule.len() > 10, "built-in rules should be non-trivial");

        let ids: std::collections::HashSet<&str> = cfg.rule.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            cfg.rule.len(),
            "built-in rule IDs should be unique"
        );

        for expected in [
            "rust.no_unwrap",
            "rust.no_dbg",
            "python.no_print",
            "js.no_console",
            "ruby.no_binding_pry",
            "security.hardcoded_ipv4",
        ] {
            assert!(
                ids.contains(expected),
                "expected built-in rule '{expected}'"
            );
        }

        assert_eq!(cfg.defaults, Defaults::default());
    }
}

// ============================================================================
// sensor.report.v1 types (Cockpit ecosystem integration)
// ============================================================================

/// The `sensor.report.v1` envelope for Cockpit ecosystem integration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SensorReport {
    /// Schema identifier, always "sensor.report.v1".
    pub schema: String,
    /// Tool metadata.
    pub tool: ToolMeta,
    /// Run timing and capability information.
    pub run: RunMeta,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Findings in sensor format.
    pub findings: Vec<SensorFinding>,
    /// List of artifacts produced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    /// Additional data payload (diff metadata, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Run timing and capability status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunMeta {
    /// ISO 8601 timestamp when the run started.
    pub started_at: String,
    /// ISO 8601 timestamp when the run ended.
    pub ended_at: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Capability status map (e.g., "git" -> available/unavailable).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub capabilities: HashMap<String, CapabilityStatus>,
}

/// Status of a capability (e.g., git availability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityStatus {
    /// Status: "available", "unavailable", or "skipped".
    pub status: String,
    /// Optional reason for unavailability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A finding in sensor.report.v1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SensorFinding {
    /// Check identifier (constant: "diffguard.pattern").
    pub check_id: String,
    /// Rule code (maps from rule_id, e.g., "rust.no_unwrap").
    pub code: String,
    /// Finding severity.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Location in the source.
    pub location: SensorLocation,
    /// Stable fingerprint (SHA-256 truncated to 16 hex chars).
    pub fingerprint: String,
    /// Optional help text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Optional URL for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Additional data (match_text, snippet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Location in sensor.report.v1 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SensorLocation {
    /// Repo-relative path with forward slashes.
    pub path: String,
    /// Line number (1-based).
    pub line: u32,
    /// Optional column number (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// An artifact produced by the sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    /// Path to the artifact file.
    pub path: String,
    /// Format of the artifact (e.g., "json", "sarif", "markdown").
    pub format: String,
}
