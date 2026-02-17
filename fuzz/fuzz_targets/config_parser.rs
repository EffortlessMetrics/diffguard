//! Fuzz target for TOML config parsing.
//!
//! This target exercises the config file parsing pipeline to discover edge cases
//! in TOML parsing, deserialization, and rule compilation.
//!
//! It tests three layers:
//! 1. Raw TOML parsing (should handle any bytes gracefully)
//! 2. Config deserialization (ConfigFile struct from diffguard-types)
//! 3. Rule compilation from parsed config (regex/glob compilation)
//!
//! Requirements: 1.11 from ROADMAP.md - Config parse fuzz target

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_domain::compile_rules;
use diffguard_types::{ConfigFile, Defaults, FailOn, RuleConfig, Scope, Severity};

/// Structured fuzz input for generating valid-ish TOML configs.
/// This exercises more paths than purely random bytes.
#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    /// Whether to use structured input or raw bytes
    use_structured: bool,
    /// Raw bytes for unstructured fuzzing
    raw_bytes: Vec<u8>,
    /// Structured config for targeted fuzzing
    structured: StructuredConfig,
}

/// A structured config that generates valid TOML structure
/// but with potentially problematic values.
#[derive(Arbitrary, Debug)]
struct StructuredConfig {
    defaults: FuzzDefaults,
    rules: Vec<FuzzRuleConfig>,
}

/// Fuzz-friendly defaults section.
#[derive(Arbitrary, Debug)]
struct FuzzDefaults {
    base: Option<String>,
    head: Option<String>,
    scope: Option<u8>,
    fail_on: Option<u8>,
    max_findings: Option<u32>,
    diff_context: Option<u32>,
}

/// Fuzz-friendly rule config.
#[derive(Arbitrary, Debug)]
struct FuzzRuleConfig {
    id: String,
    severity: u8,
    message: String,
    languages: Vec<String>,
    patterns: Vec<String>,
    paths: Vec<String>,
    exclude_paths: Vec<String>,
    ignore_comments: bool,
    ignore_strings: bool,
    match_mode: Default::default(),
    multiline: false,
    multiline_window: None,
    context_patterns: vec![],
    context_window: None,
    escalate_patterns: vec![],
    escalate_window: None,
    escalate_to: None,
    depends_on: vec![],
    help: Option<String>,
    url: Option<String>,
}

impl StructuredConfig {
    /// Convert to TOML string for parsing.
    fn to_toml_string(&self) -> String {
        let mut out = String::new();

        // Defaults section
        out.push_str("[defaults]\n");
        if let Some(ref base) = self.defaults.base {
            out.push_str(&format!("base = {}\n", escape_toml_string(base)));
        }
        if let Some(ref head) = self.defaults.head {
            out.push_str(&format!("head = {}\n", escape_toml_string(head)));
        }
        if let Some(scope) = self.defaults.scope {
            let scope_str = match scope % 4 {
                0 => "added",
                1 => "changed",
                2 => "modified",
                _ => "deleted",
            };
            out.push_str(&format!("scope = \"{}\"\n", scope_str));
        }
        if let Some(fail_on) = self.defaults.fail_on {
            let fail_str = match fail_on % 3 {
                0 => "error",
                1 => "warn",
                _ => "never",
            };
            out.push_str(&format!("fail_on = \"{}\"\n", fail_str));
        }
        if let Some(max) = self.defaults.max_findings {
            out.push_str(&format!("max_findings = {}\n", max));
        }
        if let Some(ctx) = self.defaults.diff_context {
            out.push_str(&format!("diff_context = {}\n", ctx));
        }

        // Rules
        for rule in &self.rules {
            out.push_str("\n[[rule]]\n");
            out.push_str(&format!("id = {}\n", escape_toml_string(&rule.id)));
            let sev = match rule.severity % 3 {
                0 => "info",
                1 => "warn",
                _ => "error",
            };
            out.push_str(&format!("severity = \"{}\"\n", sev));
            out.push_str(&format!("message = {}\n", escape_toml_string(&rule.message)));

            if !rule.languages.is_empty() {
                out.push_str(&format!(
                    "languages = [{}]\n",
                    rule.languages
                        .iter()
                        .map(|s| escape_toml_string(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            if !rule.patterns.is_empty() {
                out.push_str(&format!(
                    "patterns = [{}]\n",
                    rule.patterns
                        .iter()
                        .map(|s| escape_toml_string(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            if !rule.paths.is_empty() {
                out.push_str(&format!(
                    "paths = [{}]\n",
                    rule.paths
                        .iter()
                        .map(|s| escape_toml_string(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            if !rule.exclude_paths.is_empty() {
                out.push_str(&format!(
                    "exclude_paths = [{}]\n",
                    rule.exclude_paths
                        .iter()
                        .map(|s| escape_toml_string(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            out.push_str(&format!("ignore_comments = {}\n", rule.ignore_comments));
            out.push_str(&format!("ignore_strings = {}\n", rule.ignore_strings));

            if let Some(ref help) = rule.help {
                out.push_str(&format!("help = {}\n", escape_toml_string(help)));
            }
            if let Some(ref url) = rule.url {
                out.push_str(&format!("url = {}\n", escape_toml_string(url)));
            }
        }

        out
    }
}

/// Escape a string for TOML, handling special characters.
fn escape_toml_string(s: &str) -> String {
    // Use basic string with escapes for simplicity
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                // Skip other control characters
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fuzz_target!(|input: FuzzConfig| {
    if input.use_structured {
        // === Structured fuzzing: Generate valid TOML with potentially problematic values ===
        let toml_str = input.structured.to_toml_string();

        // Try to parse as raw TOML value
        let _ = toml::from_str::<toml::Value>(&toml_str);

        // Try to deserialize as ConfigFile
        if let Ok(config) = toml::from_str::<ConfigFile>(&toml_str) {
            // Try to compile rules
            let _ = compile_rules(&config.rule);

            // Verify defaults parsing worked correctly
            let _ = config.defaults.base;
            let _ = config.defaults.head;
            let _ = config.defaults.scope;
            let _ = config.defaults.fail_on;
            let _ = config.defaults.max_findings;
            let _ = config.defaults.diff_context;
        }
    } else {
        // === Unstructured fuzzing: Raw bytes as TOML ===
        if let Ok(s) = std::str::from_utf8(&input.raw_bytes) {
            // Skip excessively long inputs to avoid timeout
            if s.len() > 10000 {
                return;
            }

            // Try to parse as raw TOML value - should not panic on malformed input
            let _ = toml::from_str::<toml::Value>(s);

            // Try to deserialize as ConfigFile - should not panic on invalid schema
            if let Ok(config) = toml::from_str::<ConfigFile>(s) {
                // Try to compile rules - should return error for invalid patterns, never panic
                let _ = compile_rules(&config.rule);
            }

            // Also try to deserialize just the Defaults struct
            let _ = toml::from_str::<Defaults>(s);

            // And individual RuleConfig (wrapped in a table)
            let wrapped = format!("[rule]\n{}", s);
            let _ = toml::from_str::<RuleConfig>(&wrapped);
        }
    }

    // === Test enum parsing edge cases ===
    // These should never panic, even with invalid values
    let _ = toml::from_str::<Severity>("\"invalid\"");
    let _ = toml::from_str::<Scope>("\"invalid\"");
    let _ = toml::from_str::<FailOn>("\"invalid\"");

    // Test with numeric values (wrong type)
    let _ = toml::from_str::<Severity>("123");
    let _ = toml::from_str::<Scope>("456");
    let _ = toml::from_str::<FailOn>("789");
});
