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
    #[must_use]
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
    Modified,
    Deleted,
}

impl Scope {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Added => "added",
            Scope::Changed => "changed",
            Scope::Modified => "modified",
            Scope::Deleted => "deleted",
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
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FailOn::Error => "error",
            FailOn::Warn => "warn",
            FailOn::Never => "never",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Emit a finding when at least one pattern matches (default behavior).
    #[default]
    Any,
    /// Emit a finding when none of the patterns match within the scoped file.
    Absent,
}

/// Metadata describing the tool that produced a check receipt.
///
/// Includes the tool name and version for traceability in CI/CD pipelines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
}

/// Metadata describing the git diff that was scanned.
///
/// Captures the base/head refs, context configuration, scope, and
/// aggregate scan statistics for reproducibility and auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiffMeta {
    pub base: String,
    pub head: String,
    pub context_lines: u32,
    pub scope: Scope,
    /// Number of distinct files that were scanned.
    ///
    /// Stored as `u64` to avoid silent truncation for very large repositories
    /// (those with more than 2^32 - 1 unique files).
    pub files_scanned: u64,
    pub lines_scanned: u32,
}

/// A single rule match within a scoped file.
///
/// Represents one finding with location, matched text, and an optional snippet
/// for context. Multiple findings are aggregated into a `Verdict`.
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

/// The overall disposition of a check run.
///
/// `VerdictStatus` is the top-level pass/fail/skip result, while `counts`
/// provides a breakdown by severity and `reasons` explains any non-pass outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pass,
    Warn,
    Fail,
    /// For cockpit mode when inputs are missing or check cannot run.
    Skip,
}

/// Severity counts for a check run.
///
/// `suppressed` tracks matches disabled by inline directives and is omitted
/// from serialized output when zero to keep receipts clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct VerdictCounts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
    /// Number of matches suppressed via inline directives.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suppressed: u32,
}

// WHY: Used as skip_serializing_if predicate — must take &T to match serde's Fn(&T) -> bool.
// The lint is suppressed because these are private helpers, not public API, and the reference
// is required for serde's callback interface.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The overall result of a check run.
///
/// `status` is the top-level disposition, `counts` breaks down findings by
/// severity, and `reasons` provides human-readable tokens explaining any
/// non-pass outcome (e.g., `no_diff_input`, `truncated`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub counts: VerdictCounts,
    pub reasons: Vec<String>,
}

/// The complete output of a single check run.
///
/// Encapsulates the tool identity, diff metadata, all findings, and the final
/// verdict. This is the primary output artifact of the diffguard pipeline.
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
    /// Returns the built-in configuration with default rules.
    ///
    /// Rules are loaded from `rules/built_in.json` at compile time via `include_str!`.
    /// This ensures the JSON is embedded in the binary and avoids any I/O at runtime.
    #[must_use]
    pub fn built_in() -> Self {
        serde_json::from_str(include_str!("rules/built_in.json"))
            .expect("built_in.json must be valid UTF-8 and parseable as ConfigFile JSON")
    }
}

/// Default values applied to any rule field that is omitted in a config file.
///
/// Allows configs to be concise — only fields that differ from the safe default
/// need to be specified explicitly.
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

/// A single rule definition within a `ConfigFile`.
///
/// `RuleConfig` is the user-facing YAML/TOML schema for specifying custom rules.
/// Each rule has one or more regex `patterns` and optional scope filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleConfig {
    pub id: String,
    pub severity: Severity,
    #[serde(default)]
    pub message: String,

    /// Optional description of the rule.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Optional language tags (e.g. "rust"). Empty means "all".
    #[serde(default)]
    pub languages: Vec<String>,

    /// One or more regex patterns.
    /// Also accepts `match` as a TOML shorthand.
    #[serde(default, alias = "match")]
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

    /// Matching mode:
    /// - `any` (default): emit when patterns match
    /// - `absent`: emit when patterns do not match in the scoped file
    #[serde(default, skip_serializing_if = "is_match_mode_any")]
    pub match_mode: MatchMode,

    /// Enable multi-line matching across consecutive scoped lines.
    #[serde(default, skip_serializing_if = "is_false")]
    pub multiline: bool,

    /// Number of consecutive scoped lines to include in a multiline window.
    /// If omitted and `multiline=true`, a default of 2 lines is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline_window: Option<u32>,

    /// Optional context patterns that must match near a primary match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_patterns: Vec<String>,

    /// Context search window (lines before/after the matched line).
    /// If omitted and `context_patterns` are set, a default of 3 is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,

    /// Optional patterns that escalate severity when found near a match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalate_patterns: Vec<String>,

    /// Escalation search window (lines before/after the matched line).
    /// If omitted and `escalate_patterns` are set, a default of 0 (same line) is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_window: Option<u32>,

    /// Escalation target severity. Defaults to `error` when escalation patterns match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<Severity>,

    /// Rule dependencies. This rule is only evaluated in files where all dependencies matched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,

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

// WHY: Used as a skip_serializing_if predicate — avoids emitting `false` values
// to keep output clean for default-flag fields.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !*v
}

// WHY: MatchMode::Any is the default; we skip it in serialized output to keep
// configs minimal — callers who need the default get it automatically.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_match_mode_any(mode: &MatchMode) -> bool {
    matches!(mode, MatchMode::Any)
}

// Utility for markdown escaping, used by rendering crates — kept here to avoid duplication across crates.
pub fn escape_md(s: &str) -> String {
    // Escapes special Markdown characters in table cell content.
    //
    // Escapes pipe (`|`), backtick (`` ` ``), hash (`#`), asterisk (`*`),
    // underscore (`_`), open bracket (`[`), close bracket (`]`), and greater-than
    // (`>`) characters by prefixing with backslash. Also escapes CRLF (`\r\n`)
    // and LF (`\n`) line endings to prevent breaking the markdown table structure.
    //
    // These escapes are needed to prevent breaking the markdown table structure
    // and prevent unintended markdown formatting.
    s.replace('|', "\\|")
        .replace('`', "\\`")
        .replace('#', "\\#")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('>', "\\>")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
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
        assert_eq!(Scope::Modified.as_str(), "modified");
        assert_eq!(Scope::Deleted.as_str(), "deleted");

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
