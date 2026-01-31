//! Data types (config + receipts) for diffguard.
//!
//! This crate is intentionally "dumb": pure DTOs with serde + schemars.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CHECK_SCHEMA_V1: &str = "diffguard.check.v1";

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct VerdictCounts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
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
}
