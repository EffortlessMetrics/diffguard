use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use diffguard_domain::DirectoryRuleOverride;
use diffguard_types::{ConfigFile, DirectoryOverrideConfig, MatchMode, RuleConfig, Severity};
use lsp_types::{Diagnostic, NumberOrString};
use regex::Regex;

const DIRECTORY_OVERRIDE_NAME: &str = ".diffguard.toml";
const MAX_INCLUDE_DEPTH: usize = 10;

/// Loads the effective configuration for diffguard.
///
/// If `path` is `None`, returns the built-in configuration. Otherwise, parses
/// the config file at the given path (including any files it includes), then
/// merges with the built-in rules unless `no_default_rules` is `true`.
///
/// # Arguments
///
/// * `path` - Optional path to a `.diffguard.toml` config file
/// * `no_default_rules` - If `true`, skip merging with built-in rules
///
/// # Returns
///
/// The merged `ConfigFile` with all includes resolved
pub fn load_effective_config(path: Option<&Path>, no_default_rules: bool) -> Result<ConfigFile> {
    let Some(path) = path else {
        return Ok(ConfigFile::built_in());
    };

    let parsed = load_config_with_includes(path)?;
    if no_default_rules {
        Ok(parsed)
    } else {
        Ok(merge_with_built_in(parsed))
    }
}

/// Resolves the path to a config file based on workspace root and optional override.
///
/// Resolution order:
/// 1. If `override_path` is absolute, use it directly
/// 2. If `override_path` is relative, join it with `workspace_root` (if provided)
/// 3. If no override, look for `default_name` in `workspace_root`
/// 4. If no workspace root, look for `default_name` in current directory
///
/// # Arguments
///
/// * `workspace_root` - The root directory of the workspace (typically `.git` parent)
/// * `override_path` - Optional explicit path to config file
/// * `default_name` - Default config filename to search for (e.g., `.diffguard.toml`)
///
/// # Returns
///
/// The resolved path to the config file, or `None` if not found
pub fn resolve_config_path(
    workspace_root: Option<&Path>,
    override_path: Option<String>,
    default_name: &str,
) -> Option<PathBuf> {
    if let Some(raw) = override_path {
        let candidate = PathBuf::from(raw);
        if candidate.is_absolute() {
            return Some(candidate);
        }
        return Some(
            workspace_root
                .map(|root| root.join(candidate.clone()))
                .unwrap_or(candidate),
        );
    }

    if let Some(root) = workspace_root {
        let candidate = root.join(default_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        return None;
    }

    let candidate = PathBuf::from(default_name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Checks if two paths refer to the same file on disk.
///
/// Uses canonicalization when available (follows symlinks, resolves `..`).
/// Falls back to string comparison of normalized paths if canonicalization fails.
///
/// # Arguments
///
/// * `left` - First path to compare
/// * `right` - Second path to compare
///
/// # Returns
///
/// `true` if both paths resolve to the same file, `false` otherwise
pub fn paths_match(left: &Path, right: &Path) -> bool {
    let left_canonical = left.canonicalize().ok();
    let right_canonical = right.canonicalize().ok();
    if let (Some(left), Some(right)) = (left_canonical, right_canonical) {
        return left == right;
    }
    normalize_path(left) == normalize_path(right)
}

/// Normalizes a path to use forward slashes and strip trailing separators.
///
/// Primarily used for consistent string comparison of paths across platforms.
/// Windows paths with backslashes are converted to forward slashes.
///
/// # Arguments
///
/// * `path` - The path to normalize
///
/// # Returns
///
/// A string representation of the path with forward slashes
pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Converts an absolute file path to a workspace-relative path string.
///
/// If `workspace_root` is provided, strips the prefix from `file_path`.
/// The result is normalized (forward slashes) and has `./` prefix stripped.
///
/// # Arguments
///
/// * `workspace_root` - The root directory to strip from the path
/// * `file_path` - The absolute path to convert
///
/// # Returns
///
/// A relative path string suitable for display or matching
pub fn to_workspace_relative_path(workspace_root: Option<&Path>, file_path: &Path) -> String {
    let normalized = if let Some(root) = workspace_root {
        if let Ok(stripped) = file_path.strip_prefix(root) {
            normalize_path(stripped)
        } else {
            normalize_path(file_path)
        }
    } else {
        normalize_path(file_path)
    };

    normalized.trim_start_matches("./").to_string()
}

/// Extracts the rule ID from an LSP diagnostic.
///
/// Tries two sources in order:
/// 1. The `code` field if it's a string (e.g., `"rust.no_unwrap"`)
/// 2. The `data.ruleId` JSON field if present
///
/// # Arguments
///
/// * `diagnostic` - The LSP diagnostic to extract from
///
/// # Returns
///
/// The rule ID string, or `None` if not found
pub fn extract_rule_id(diagnostic: &Diagnostic) -> Option<String> {
    if let Some(NumberOrString::String(rule_id)) = diagnostic.code.as_ref() {
        return Some(rule_id.clone());
    }

    diagnostic
        .data
        .as_ref()
        .and_then(|value| value.get("ruleId"))
        .and_then(|value| value.as_str())
        .map(|s| s.to_string())
}

/// Finds a rule in a config file by its ID.
///
/// # Arguments
///
/// * `config` - The config file to search
/// * `rule_id` - The rule ID to find
///
/// # Returns
///
/// A reference to the matching `RuleConfig`, or `None` if not found
pub fn find_rule<'a>(config: &'a ConfigFile, rule_id: &str) -> Option<&'a RuleConfig> {
    config.rule.iter().find(|rule| rule.id == rule_id)
}

/// Formats a rule into a human-readable explanation string.
///
/// Produces a multi-line output describing the rule's ID, severity, message,
/// patterns, semantics, and other configuration. Used for displaying detailed
/// rule information to users.
///
/// # Arguments
///
/// * `rule` - The rule configuration to format
///
/// # Returns
///
/// A string containing the formatted rule explanation
pub fn format_rule_explanation(rule: &RuleConfig) -> String {
    let mut output = String::new();
    output.push_str(&format!("Rule: {}\n", rule.id));
    output.push_str(&format!("Severity: {}\n", rule.severity.as_str()));
    output.push_str(&format!("Message: {}\n", rule.message));
    output.push_str("Patterns:\n");
    for pattern in &rule.patterns {
        output.push_str(&format!("- {}\n", pattern));
    }
    output.push_str("Semantics:\n");
    let match_mode = match rule.match_mode {
        MatchMode::Any => "any",
        MatchMode::Absent => "absent",
    };
    output.push_str(&format!("- Match mode: {}\n", match_mode));
    output.push_str(&format!(
        "- Multiline: {}{}\n",
        if rule.multiline { "yes" } else { "no" },
        rule.multiline_window
            .map(|window| format!(" (window={})", window))
            .unwrap_or_default()
    ));
    if !rule.context_patterns.is_empty() {
        output.push_str(&format!(
            "- Context patterns (window={}): {}\n",
            rule.context_window.unwrap_or(3),
            rule.context_patterns.join(", ")
        ));
    }
    if !rule.escalate_patterns.is_empty() {
        output.push_str(&format!(
            "- Escalate to {} (window={}): {}\n",
            rule.escalate_to.unwrap_or(Severity::Error).as_str(),
            rule.escalate_window.unwrap_or(0),
            rule.escalate_patterns.join(", ")
        ));
    }
    if !rule.depends_on.is_empty() {
        output.push_str(&format!("- Depends on: {}\n", rule.depends_on.join(", ")));
    }
    if !rule.languages.is_empty() {
        output.push_str(&format!("Languages: {}\n", rule.languages.join(", ")));
    }
    if !rule.paths.is_empty() {
        output.push_str(&format!("Paths: {}\n", rule.paths.join(", ")));
    }
    if !rule.exclude_paths.is_empty() {
        output.push_str(&format!("Excludes: {}\n", rule.exclude_paths.join(", ")));
    }
    output.push_str(&format!(
        "Ignore comments: {}\n",
        if rule.ignore_comments { "yes" } else { "no" }
    ));
    output.push_str(&format!(
        "Ignore strings: {}\n",
        if rule.ignore_strings { "yes" } else { "no" }
    ));
    if let Some(help) = &rule.help {
        output.push_str("Help:\n");
        for line in help.lines() {
            output.push_str(&format!("{}\n", line));
        }
    }
    if let Some(url) = &rule.url {
        output.push_str(&format!("URL: {}\n", url));
    }
    output
}

/// Finds rules with IDs similar to the given rule ID for typo suggestions.
///
/// Uses multiple strategies to find similar IDs:
/// - Exact prefix match (score 0)
/// - Substring match (score 1)
/// - Levenshtein distance ≤ 3 (score = distance + 2)
///
/// Results are sorted by score and truncated to 5.
///
/// # Arguments
///
/// * `rule_id` - The rule ID to find similar matches for
/// * `rules` - Slice of rule configurations to search
///
/// # Returns
///
/// A vector of up to 5 rule IDs sorted by similarity
pub fn find_similar_rules(rule_id: &str, rules: &[RuleConfig]) -> Vec<String> {
    let rule_id_lower = rule_id.to_lowercase();
    let mut candidates: Vec<(String, usize)> = Vec::new();

    for rule in rules {
        let id_lower = rule.id.to_lowercase();
        if id_lower.starts_with(&rule_id_lower) || rule_id_lower.starts_with(&id_lower) {
            candidates.push((rule.id.clone(), 0));
            continue;
        }
        if id_lower.contains(&rule_id_lower) || rule_id_lower.contains(&id_lower) {
            candidates.push((rule.id.clone(), 1));
            continue;
        }
        let distance = simple_edit_distance(&rule_id_lower, &id_lower);
        if distance <= 3 {
            candidates.push((rule.id.clone(), distance + 2));
        }
    }

    candidates.sort_by_key(|(_, score)| *score);
    candidates.truncate(5);
    candidates.into_iter().map(|(id, _)| id).collect()
}

/// Loads directory-level rule overrides for a given file path.
///
/// Searches for `.diffguard.toml` files in the directory hierarchy from the
/// file's directory up to the workspace root. Overrides are collected from all
/// matching files, sorted by depth (shallowest first), then merged.
///
/// # Arguments
///
/// * `workspace_root` - The root directory of the workspace
/// * `relative_file_path` - The file path relative to the workspace root
///
/// # Returns
///
/// A merged vector of `DirectoryRuleOverride` from all applicable override files
///
/// # Errors
///
/// Returns an error if an override file exists but cannot be read or parsed
pub fn load_directory_overrides_for_file(
    workspace_root: &Path,
    relative_file_path: &str,
) -> Result<Vec<DirectoryRuleOverride>> {
    let mut candidates = BTreeSet::<PathBuf>::new();
    collect_override_candidates_for_path(relative_file_path, &mut candidates);

    let mut ordered_candidates: Vec<PathBuf> = candidates.into_iter().collect();
    ordered_candidates.sort_by(|left, right| {
        let left_parent = left.parent().unwrap_or_else(|| Path::new(""));
        let right_parent = right.parent().unwrap_or_else(|| Path::new(""));
        directory_depth(left_parent)
            .cmp(&directory_depth(right_parent))
            .then_with(|| left.to_string_lossy().cmp(&right.to_string_lossy()))
    });

    let mut overrides = Vec::new();
    for candidate in ordered_candidates {
        let full_path = workspace_root.join(&candidate);
        if !full_path.is_file() {
            continue;
        }

        let content = std::fs::read_to_string(&full_path)
            .with_context(|| format!("read directory override '{}'", full_path.display()))?;
        let expanded = expand_env_vars(&content).with_context(|| {
            format!(
                "expand env vars in directory override '{}'",
                full_path.display()
            )
        })?;

        let parsed: DirectoryOverrideConfig = toml::from_str(&expanded)
            .with_context(|| format!("parse directory override '{}'", full_path.display()))?;

        let directory =
            normalize_override_directory(candidate.parent().unwrap_or_else(|| Path::new("")));
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

fn load_config_with_includes(path: &Path) -> Result<ConfigFile> {
    let mut visited = HashSet::new();
    load_config_recursive(path, &mut visited, 0)
}

fn load_config_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<ConfigFile> {
    if depth > MAX_INCLUDE_DEPTH {
        bail!(
            "include depth exceeded maximum of {} at '{}'",
            MAX_INCLUDE_DEPTH,
            path.display()
        );
    }

    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize config path '{}'", path.display()))?;
    if !visited.insert(canonical.clone()) {
        bail!("circular include detected at '{}'", path.display());
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read config '{}'", path.display()))?;
    let expanded = expand_env_vars(&content)?;
    let parsed: ConfigFile =
        toml::from_str(&expanded).with_context(|| format!("parse config '{}'", path.display()))?;

    if parsed.includes.is_empty() {
        return Ok(parsed);
    }

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut merged = ConfigFile {
        includes: vec![],
        defaults: diffguard_types::Defaults::default(),
        rule: vec![],
    };

    for include in &parsed.includes {
        let include_path = base_dir.join(include);
        if !include_path.exists() {
            bail!(
                "included config file not found: '{}' (from '{}')",
                include_path.display(),
                include
            );
        }

        let included = load_config_recursive(&include_path, visited, depth + 1)?;
        merged = merge_configs(merged, included);
    }

    let current = ConfigFile {
        includes: vec![],
        defaults: parsed.defaults,
        rule: parsed.rule,
    };
    Ok(merge_configs(merged, current))
}

fn merge_configs(base: ConfigFile, other: ConfigFile) -> ConfigFile {
    // Defaults: field-wise merge (None means "inherit from parent")
    let defaults = diffguard_types::Defaults {
        base: other.defaults.base.or(base.defaults.base),
        head: other.defaults.head.or(base.defaults.head),
        scope: other.defaults.scope.or(base.defaults.scope),
        fail_on: other.defaults.fail_on.or(base.defaults.fail_on),
        max_findings: other.defaults.max_findings.or(base.defaults.max_findings),
        diff_context: other.defaults.diff_context.or(base.defaults.diff_context),
    };

    let mut rules = std::collections::BTreeMap::new();
    for rule in base.rule {
        rules.insert(rule.id.clone(), rule);
    }
    for rule in other.rule {
        rules.insert(rule.id.clone(), rule);
    }

    ConfigFile {
        includes: vec![],
        defaults,
        rule: rules.into_values().collect(),
    }
}

fn merge_with_built_in(user: ConfigFile) -> ConfigFile {
    let mut built_in = ConfigFile::built_in();
    built_in.defaults = user.defaults;

    let mut rules = std::collections::BTreeMap::<String, RuleConfig>::new();
    for rule in built_in.rule {
        rules.insert(rule.id.clone(), rule);
    }
    for rule in user.rule {
        rules.insert(rule.id.clone(), rule);
    }

    built_in.rule = rules.into_values().collect();
    built_in
}

/// Expands environment variable references in config content.
///
/// Supports `${VAR}` and `${VAR:-default}` syntax. If a variable is not set
/// and no default is provided, returns an error.
///
/// The regex pattern `${[A-Za-z_][A-Za-z0-9_]*:-?}` matches:
/// - Variable names: alphanumeric with underscore, starting with letter or underscore
/// - Optional default value after `:-`
fn expand_env_vars(content: &str) -> Result<String> {
    let regex = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
        .expect("env var regex must compile");
    let mut result = String::with_capacity(content.len());
    let mut last_end = 0usize;

    for capture in regex.captures_iter(content) {
        let full = capture
            .get(0)
            .expect("full regex match should always be present");
        let variable = capture
            .get(1)
            .expect("variable capture should always be present")
            .as_str();
        let default = capture.get(2).map(|m| m.as_str());

        result.push_str(&content[last_end..full.start()]);
        match std::env::var(variable) {
            Ok(value) => result.push_str(&value),
            Err(_) => {
                if let Some(default) = default {
                    result.push_str(default);
                } else {
                    bail!(
                        "environment variable '{}' is not set and no default was provided",
                        variable
                    );
                }
            }
        }
        last_end = full.end();
    }

    result.push_str(&content[last_end..]);
    Ok(result)
}

fn collect_override_candidates_for_path(file_path: &str, output: &mut BTreeSet<PathBuf>) {
    let path = Path::new(file_path);
    let mut current = path.parent();

    if current.is_none() {
        output.insert(PathBuf::from(DIRECTORY_OVERRIDE_NAME));
        return;
    }

    while let Some(directory) = current {
        let mut candidate = PathBuf::new();
        if !directory.as_os_str().is_empty() {
            candidate.push(directory);
        }
        candidate.push(DIRECTORY_OVERRIDE_NAME);
        output.insert(candidate);

        if directory.as_os_str().is_empty() {
            break;
        }
        current = directory.parent();
    }
}

fn normalize_override_directory(path: &Path) -> String {
    let normalized = normalize_path(path);
    let trimmed = normalized.trim_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn directory_depth(path: &Path) -> usize {
    path.components().count()
}

/// Computes the Levenshtein edit distance between two strings.
///
/// Used by `find_similar_rules` to suggest rule IDs when a user types an invalid one.
/// Returns the minimum number of single-character edits (insertions, deletions,
/// or substitutions) needed to transform `left` into `right`.
///
/// # Arguments
///
/// * `left` - First string
/// * `right` - Second string
///
/// # Returns
///
/// The edit distance (0 means identical strings)
fn simple_edit_distance(left: &str, right: &str) -> usize {
    let left_chars: Vec<char> = left.chars().collect();
    let right_chars: Vec<char> = right.chars().collect();

    let left_len = left_chars.len();
    let right_len = right_chars.len();
    if left_len == 0 {
        return right_len;
    }
    if right_len == 0 {
        return left_len;
    }

    let mut previous: Vec<usize> = (0..=right_len).collect();
    let mut current: Vec<usize> = vec![0; right_len + 1];
    for i in 1..=left_len {
        current[0] = i;
        for j in 1..=right_len {
            let cost = usize::from(left_chars[i - 1] != right_chars[j - 1]);
            current[j] = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right_len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::Defaults;
    use tempfile::TempDir;

    #[test]
    fn extract_rule_id_from_code_or_data() {
        let diagnostic_with_code = Diagnostic {
            code: Some(NumberOrString::String("rust.no_unwrap".to_string())),
            ..Diagnostic::default()
        };
        assert_eq!(
            extract_rule_id(&diagnostic_with_code),
            Some("rust.no_unwrap".to_string())
        );

        let diagnostic_with_data = Diagnostic {
            data: Some(serde_json::json!({ "ruleId": "security.no_eval" })),
            ..Diagnostic::default()
        };
        assert_eq!(
            extract_rule_id(&diagnostic_with_data),
            Some("security.no_eval".to_string())
        );
    }

    #[test]
    fn format_rule_explanation_contains_semantics() {
        let rule = RuleConfig {
            id: "rust.no_unwrap".to_string(),
            description: String::new(),
            severity: Severity::Error,
            message: "Avoid unwrap".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec![r"\.unwrap\(".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec!["**/tests/**".to_string()],
            ignore_comments: true,
            ignore_strings: true,
            match_mode: MatchMode::Any,
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: Some("Use pattern matching instead.".to_string()),
            url: Some("https://example.com/rules/no_unwrap".to_string()),
            tags: vec!["safety".to_string()],
            test_cases: vec![],
        };

        let explanation = format_rule_explanation(&rule);
        assert!(explanation.contains("Rule: rust.no_unwrap"));
        assert!(explanation.contains("Severity: error"));
        assert!(explanation.contains("Use pattern matching instead."));
        assert!(explanation.contains("URL: https://example.com/rules/no_unwrap"));
    }

    #[test]
    fn find_similar_rules_prefers_close_matches() {
        let rules = vec![
            RuleConfig {
                id: "rust.no_unwrap".to_string(),
                description: String::new(),
                severity: Severity::Warn,
                message: "msg".to_string(),
                languages: vec![],
                patterns: vec!["a".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: MatchMode::Any,
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
                id: "security.no_eval".to_string(),
                description: String::new(),
                severity: Severity::Warn,
                message: "msg".to_string(),
                languages: vec![],
                patterns: vec!["a".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: MatchMode::Any,
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

        let suggestions = find_similar_rules("rust.no_unwra", &rules);
        assert!(suggestions.contains(&"rust.no_unwrap".to_string()));
    }

    #[test]
    fn load_config_with_includes_merges_rules() {
        let temp = TempDir::new().expect("temp dir");
        let base = temp.path().join("base.toml");
        let main = temp.path().join("main.toml");

        std::fs::write(
            &base,
            r#"
[[rule]]
id = "base.rule"
severity = "warn"
message = "Base rule"
patterns = ["base"]
"#,
        )
        .expect("write base");

        std::fs::write(
            &main,
            r#"
includes = ["base.toml"]
[[rule]]
id = "main.rule"
severity = "error"
message = "Main rule"
patterns = ["main"]
"#,
        )
        .expect("write main");

        let loaded = load_effective_config(Some(&main), true).expect("load config");
        let ids: BTreeSet<String> = loaded.rule.into_iter().map(|rule| rule.id).collect();
        assert!(ids.contains("base.rule"));
        assert!(ids.contains("main.rule"));
    }

    // -------------------------------------------------------------------------
    // Tests for merge_configs field-wise Defaults merging
    // These tests verify the correct field-wise merge semantics for Defaults:
    //   - Some in other → override base
    //   - None in other → inherit from base
    //
    // The buggy implementation used:
    //   if other.defaults != Defaults::default() { other.defaults } else { base.defaults }
    //
    // This causes two failure modes:
    //   1. When other has partial None fields: returns other directly (loses base values)
    //   2. When other == Defaults::default(): returns base (ignores other's explicit values)
    // -------------------------------------------------------------------------

    #[test]
    fn test_merge_configs_partial_defaults_inherit() {
        // When other.defaults has some None fields (simulating partial TOML config),
        // those None fields should inherit from base.defaults (field-wise merge).
        //
        // Bug: other.defaults != Defaults::default() is true (because None != Some),
        // so other.defaults is returned directly with None fields preserved.
        // Result: base.defaults values are lost for unspecified fields.
        //
        // Fix: field-wise merge with .or() - None.or(base_value) returns base_value.

        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("origin/develop".to_string()),
                head: Some("HEAD".to_string()),
                scope: Some(diffguard_types::Scope::Added),
                fail_on: Some(diffguard_types::FailOn::Error),
                max_findings: Some(200),
                diff_context: Some(0),
            },
            rule: vec![],
        };

        // other has only fail_on set; base/scope/head/max_findings/diff_context are None
        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: None,
                head: None,
                scope: None,
                fail_on: Some(diffguard_types::FailOn::Warn),
                max_findings: None,
                diff_context: None,
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);

        // These should pass with the fix (field-wise merge):
        // - fail_on from other (Some(Warn))
        // - other None fields inherit from base
        assert_eq!(
            merged.defaults.fail_on,
            Some(diffguard_types::FailOn::Warn),
            "fail_on should be overridden by other (Some(Warn))"
        );
        assert_eq!(
            merged.defaults.base.as_deref(),
            Some("origin/develop"),
            "base=None in other should inherit from base.defaults.base=Some('origin/develop')"
        );
        assert_eq!(
            merged.defaults.scope,
            Some(diffguard_types::Scope::Added),
            "scope=None in other should inherit from base.defaults.scope"
        );
    }

    #[test]
    fn test_merge_configs_explicit_defaults_respected() {
        // When other.defaults exactly equals Defaults::default() (user explicitly set
        // all defaults to match the built-in defaults), the merged result should use
        // other's defaults, NOT fall back to base.defaults.
        //
        // Bug: other.defaults == Defaults::default(), so condition is false,
        // and base.defaults is returned instead of other.defaults.
        //
        // Fix: field-wise merge uses other's Some values (which happen to match
        // Defaults::default()) to override base.

        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("origin/develop".to_string()), // differs from default
                head: Some("HEAD".to_string()),
                scope: Some(diffguard_types::Scope::Added),
                fail_on: Some(diffguard_types::FailOn::Error),
                max_findings: Some(200),
                diff_context: Some(0),
            },
            rule: vec![],
        };

        // other.defaults exactly matches Defaults::default()
        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![],
        };

        let merged = merge_configs(base, other);

        // With field-wise merge: other's base="origin/main" (from Defaults::default())
        // should override base.defaults.base="origin/develop"
        // With bug: base.defaults is returned unchanged, so base="origin/develop"
        assert_eq!(
            merged.defaults.base.as_deref(),
            Some("origin/main"),
            "base should be 'origin/main' from Defaults::default(), not 'origin/develop' from base"
        );
    }

    // -------------------------------------------------------------------------
    // Property-based tests for merge_configs field-wise Defaults merging
    // These tests verify invariants using multiple deterministic test cases.
    // While not using proptest, they exercise the same invariants across many
    // different input combinations to catch edge cases.
    // -------------------------------------------------------------------------

    /// Helper to create a ConfigFile with given defaults
    fn make_config(defaults: diffguard_types::Defaults) -> ConfigFile {
        ConfigFile {
            includes: vec![],
            defaults,
            rule: vec![],
        }
    }

    /// Property-like test: Field-wise override - Some in other should override base.
    /// Tests multiple deterministic combinations to verify the invariant.
    #[test]
    fn test_merge_configs_field_override_property() {
        // Test 1: Both have Some, other's should win
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let other = make_config(diffguard_types::Defaults {
            base: Some("origin/develop".to_string()),
            head: Some("feature".to_string()),
            scope: Some(diffguard_types::Scope::Changed),
            fail_on: Some(diffguard_types::FailOn::Warn),
            max_findings: Some(100),
            diff_context: Some(5),
        });
        let merged = merge_configs(base.clone(), other.clone());
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/develop"));
        assert_eq!(merged.defaults.head.as_deref(), Some("feature"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Changed));
        assert_eq!(merged.defaults.fail_on, Some(diffguard_types::FailOn::Warn));
        assert_eq!(merged.defaults.max_findings, Some(100));
        assert_eq!(merged.defaults.diff_context, Some(5));

        // Test 2: other has Some, base has None - other's should win
        let base = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let other = make_config(diffguard_types::Defaults {
            base: Some("origin/feature".to_string()),
            head: Some("feature".to_string()),
            scope: Some(diffguard_types::Scope::Changed),
            fail_on: Some(diffguard_types::FailOn::Never),
            max_findings: Some(50),
            diff_context: Some(10),
        });
        let merged = merge_configs(base.clone(), other.clone());
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/feature"));
        assert_eq!(merged.defaults.head.as_deref(), Some("feature"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Changed));
        assert_eq!(
            merged.defaults.fail_on,
            Some(diffguard_types::FailOn::Never)
        );
        assert_eq!(merged.defaults.max_findings, Some(50));
        assert_eq!(merged.defaults.diff_context, Some(10));

        // Test 3: Partial override - only some fields set in other
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let other = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: Some(diffguard_types::FailOn::Warn),
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(base.clone(), other.clone());
        // only fail_on is Some in other, so only that should come from other
        assert_eq!(merged.defaults.fail_on, Some(diffguard_types::FailOn::Warn));
        // others should inherit from base
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/main"));
        assert_eq!(merged.defaults.head.as_deref(), Some("HEAD"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Added));
        assert_eq!(merged.defaults.max_findings, Some(200));
        assert_eq!(merged.defaults.diff_context, Some(0));
    }

    /// Property-like test: Field-wise inheritance - None in other should inherit from base.
    #[test]
    fn test_merge_configs_field_inheritance_property() {
        // Test 1: All None in other, all Some in base - should inherit all
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/develop".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let other = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(base.clone(), other.clone());
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/develop"));
        assert_eq!(merged.defaults.head.as_deref(), Some("HEAD"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Added));
        assert_eq!(
            merged.defaults.fail_on,
            Some(diffguard_types::FailOn::Error)
        );
        assert_eq!(merged.defaults.max_findings, Some(200));
        assert_eq!(merged.defaults.diff_context, Some(0));

        // Test 2: Some None in other, mixed in base - None should inherit
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let other = make_config(diffguard_types::Defaults {
            base: None,
            head: Some("feature".to_string()), // Only head is Some
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(base.clone(), other.clone());
        // Only head should come from other (Some)
        assert_eq!(merged.defaults.head.as_deref(), Some("feature"));
        // Others should inherit from base
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/main"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Added));
        assert_eq!(
            merged.defaults.fail_on,
            Some(diffguard_types::FailOn::Error)
        );
        assert_eq!(merged.defaults.max_findings, Some(200));
        assert_eq!(merged.defaults.diff_context, Some(0));
    }

    /// Property-like test: Idempotent - merging a config with itself preserves defaults.
    #[test]
    fn test_merge_configs_idempotent_property() {
        // Test 1: Config with all Some values
        let config = make_config(diffguard_types::Defaults {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let merged = merge_configs(config.clone(), config.clone());
        assert_eq!(merged.defaults.base, config.defaults.base);
        assert_eq!(merged.defaults.head, config.defaults.head);
        assert_eq!(merged.defaults.scope, config.defaults.scope);
        assert_eq!(merged.defaults.fail_on, config.defaults.fail_on);
        assert_eq!(merged.defaults.max_findings, config.defaults.max_findings);
        assert_eq!(merged.defaults.diff_context, config.defaults.diff_context);

        // Test 2: Config with all None values
        let config = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(config.clone(), config.clone());
        assert_eq!(merged.defaults.base, config.defaults.base);
        assert_eq!(merged.defaults.head, config.defaults.head);
        assert_eq!(merged.defaults.scope, config.defaults.scope);
        assert_eq!(merged.defaults.fail_on, config.defaults.fail_on);
        assert_eq!(merged.defaults.max_findings, config.defaults.max_findings);
        assert_eq!(merged.defaults.diff_context, config.defaults.diff_context);

        // Test 3: Config with mixed Some/None values
        let config = make_config(diffguard_types::Defaults {
            base: Some("origin/feature".to_string()),
            head: None,
            scope: Some(diffguard_types::Scope::Changed),
            fail_on: None,
            max_findings: Some(100),
            diff_context: None,
        });
        let merged = merge_configs(config.clone(), config.clone());
        assert_eq!(merged.defaults.base, config.defaults.base);
        assert_eq!(merged.defaults.head, config.defaults.head);
        assert_eq!(merged.defaults.scope, config.defaults.scope);
        assert_eq!(merged.defaults.fail_on, config.defaults.fail_on);
        assert_eq!(merged.defaults.max_findings, config.defaults.max_findings);
        assert_eq!(merged.defaults.diff_context, config.defaults.diff_context);
    }

    /// Property-like test: All-None other inherits all values from base.
    #[test]
    fn test_merge_configs_all_none_other_inherits_all_property() {
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/develop".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let all_none_other = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(base.clone(), all_none_other);
        assert_eq!(merged.defaults.base, base.defaults.base);
        assert_eq!(merged.defaults.head, base.defaults.head);
        assert_eq!(merged.defaults.scope, base.defaults.scope);
        assert_eq!(merged.defaults.fail_on, base.defaults.fail_on);
        assert_eq!(merged.defaults.max_findings, base.defaults.max_findings);
        assert_eq!(merged.defaults.diff_context, base.defaults.diff_context);
    }

    /// Property-like test: Partial defaults - only some fields set to Some in other.
    #[test]
    fn test_merge_configs_partial_override_property() {
        // Test: First 3 fields None, last 3 Some in other
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/main".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        let other = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: Some(diffguard_types::FailOn::Warn),
            max_findings: Some(50),
            diff_context: Some(10),
        });
        let merged = merge_configs(base.clone(), other.clone());

        // Fields set to Some in other should override
        assert_eq!(merged.defaults.fail_on, Some(diffguard_types::FailOn::Warn));
        assert_eq!(merged.defaults.max_findings, Some(50));
        assert_eq!(merged.defaults.diff_context, Some(10));

        // Fields set to None in other should inherit from base
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/main"));
        assert_eq!(merged.defaults.head.as_deref(), Some("HEAD"));
        assert_eq!(merged.defaults.scope, Some(diffguard_types::Scope::Added));
    }

    /// Property-like test: All 6 fields explicitly set to Defaults::default() values.
    /// This was the bug case - when other.defaults == Defaults::default(),
    /// the buggy code would return base.defaults instead.
    #[test]
    fn test_merge_configs_explicit_defaults_default_values() {
        let base = make_config(diffguard_types::Defaults {
            base: Some("origin/develop".to_string()),
            head: Some("HEAD".to_string()),
            scope: Some(diffguard_types::Scope::Added),
            fail_on: Some(diffguard_types::FailOn::Error),
            max_findings: Some(200),
            diff_context: Some(0),
        });
        // other.defaults exactly matches Defaults::default()
        let other = make_config(diffguard_types::Defaults::default());
        let merged = merge_configs(base.clone(), other.clone());

        // With the fix, other's defaults should win (field-wise)
        // Defaults::default() has base: Some("origin/main")
        assert_eq!(
            merged.defaults.base.as_deref(),
            Some("origin/main"),
            "base should be 'origin/main' from Defaults::default(), not 'origin/develop' from base"
        );
        // All fields should match Defaults::default()
        assert_eq!(merged.defaults.base, Defaults::default().base);
        assert_eq!(merged.defaults.head, Defaults::default().head);
        assert_eq!(merged.defaults.scope, Defaults::default().scope);
        assert_eq!(merged.defaults.fail_on, Defaults::default().fail_on);
        assert_eq!(
            merged.defaults.max_findings,
            Defaults::default().max_findings
        );
        assert_eq!(
            merged.defaults.diff_context,
            Defaults::default().diff_context
        );
    }

    /// Property-like test: All 6 fields None in other, base also has None.
    /// Edge case where both are None.
    #[test]
    fn test_merge_configs_both_none_inherits_none() {
        let base = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let other = make_config(diffguard_types::Defaults {
            base: None,
            head: None,
            scope: None,
            fail_on: None,
            max_findings: None,
            diff_context: None,
        });
        let merged = merge_configs(base.clone(), other.clone());
        // All should be None (inheriting None from both)
        assert_eq!(merged.defaults.base, None);
        assert_eq!(merged.defaults.head, None);
        assert_eq!(merged.defaults.scope, None);
        assert_eq!(merged.defaults.fail_on, None);
        assert_eq!(merged.defaults.max_findings, None);
        assert_eq!(merged.defaults.diff_context, None);
    }
}
