//! Data types (config + receipts) for diffguard.
//!
//! This crate is intentionally "dumb": pure DTOs with serde + schemars.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CHECK_SCHEMA_V1: &str = "diffguard.check.v1";
pub const SENSOR_REPORT_SCHEMA_V1: &str = "sensor.report.v1";

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
}

/// The on-disk configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigFile {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub rule: Vec<RuleConfig>,
}

impl ConfigFile {
    pub fn built_in() -> Self {
        Self {
            defaults: Defaults::default(),
            rule: vec![
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
                },
                // Python rules
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
                },
                // JavaScript/TypeScript rules
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
                },
                // Go rules
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
                },
                // Go: no_panic (Phase 5.6)
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
                },
                // Kotlin rules
                // Kotlin: no_println (Phase 5.7)
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
