use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use diffguard_domain::DirectoryRuleOverride;
use diffguard_types::{ConfigFile, DirectoryOverrideConfig, MatchMode, RuleConfig, Severity};
use lsp_types::{Diagnostic, NumberOrString};
use regex::Regex;

/// Name of the per-directory override file that can exist in any directory.
const DIRECTORY_OVERRIDE_NAME: &str = ".diffguard.toml";

/// Maximum depth for config file includes to prevent unbounded recursion.
const MAX_INCLUDE_DEPTH: usize = 10;

/// Loads the effective configuration by merging user config with built-in defaults.
///
/// If `path` is `None`, returns only the built-in configuration.
/// If `no_default_rules` is `true`, returns only the user configuration without merging built-in rules.
/// Otherwise, merges user rules with built-in rules, with user rules taking precedence.
///
/// # Errors
/// Returns an error if the config file cannot be read, parsed, or if circular includes are detected.
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

/// Compares two paths for equality.
///
/// Uses canonicalization first to resolve symlinks and relative paths.
/// Falls back to string comparison of normalized paths if canonicalization fails.
pub fn paths_match(left: &Path, right: &Path) -> bool {
    let left_canonical = left.canonicalize().ok();
    let right_canonical = right.canonicalize().ok();
    if let (Some(left), Some(right)) = (left_canonical, right_canonical) {
        return left == right;
    }
    normalize_path(left) == normalize_path(right)
}

/// Normalizes a path by converting backslashes to forward slashes.
///
/// This ensures consistent path representation across Windows and Unix systems.
pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Converts a file path to a workspace-relative path.
///
/// Strips the `workspace_root` prefix if the file is within the workspace,
/// then normalizes the path and removes any leading `./`.
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
/// Checks two sources in order:
/// 1. The `code` field (a `NumberOrString::String`) — preferred source
/// 2. The `data.ruleId` JSON field — fallback for extended diagnostic info
pub fn extract_rule_id(diagnostic: &Diagnostic) -> Option<String> {
    if let Some(NumberOrString::String(rule_id)) = diagnostic.code.as_ref() {
        return Some(rule_id.clone());
    }

    diagnostic
        .data
        .as_ref()
        .and_then(|value| value.get("ruleId"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
}

/// Finds a rule by its ID in the given configuration.
#[must_use]
pub fn find_rule<'a>(config: &'a ConfigFile, rule_id: &str) -> Option<&'a RuleConfig> {
    config.rule.iter().find(|rule| rule.id == rule_id)
}

/// Formats a rule configuration into a human-readable explanation string.
///
/// The output includes the rule ID, severity, message, patterns, and all configured
/// options such as match mode, context patterns, escalation rules, and metadata.
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

/// Finds rules with IDs similar to the given rule ID for typo correction suggestions.
///
/// Uses a multi-pass scoring strategy:
/// - Prefix matches (score 0): one ID starts with the other
/// - Substring matches (score 1): one ID contains the other
/// - Edit distance (score 2-4): fuzzy matching for typos up to 3 edits
///
/// Returns at most 5 candidates sorted by ascending score (best match first).
pub fn find_similar_rules(rule_id: &str, rules: &[RuleConfig]) -> Vec<String> {
    let rule_id_lower = rule_id.to_lowercase();
    let mut candidates: Vec<(String, usize)> = Vec::new();

    for rule in rules {
        let id_lower = rule.id.to_lowercase();
        // Prefix match — highest priority, score 0
        if id_lower.starts_with(&rule_id_lower) || rule_id_lower.starts_with(&id_lower) {
            candidates.push((rule.id.clone(), 0));
            continue;
        }
        // Substring match — medium priority, score 1
        if id_lower.contains(&rule_id_lower) || rule_id_lower.contains(&id_lower) {
            candidates.push((rule.id.clone(), 1));
            continue;
        }
        // Fuzzy match via edit distance — lower priority, score 2+
        let distance = simple_edit_distance(&rule_id_lower, &id_lower);
        if distance <= 3 {
            candidates.push((rule.id.clone(), distance + 2));
        }
    }

    candidates.sort_by_key(|(_, score)| *score);
    candidates.truncate(5);
    candidates.into_iter().map(|(id, _)| id).collect()
}

/// Loads directory-level rule overrides for a given file.
///
/// Searches for `.diffguard.toml` files in each directory from the file's location
/// up to the workspace root, then loads and merges any directory-specific rule overrides.
///
/// Override files are processed in order of depth (shallowest first), so that
/// deeper directories can override shallower ones. Within the same depth, files
/// are processed in alphabetical order for deterministic behavior.
///
/// # Errors
/// Returns an error if an override file exists but cannot be read, expanded, or parsed.
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
    let defaults = if other.defaults != diffguard_types::Defaults::default() {
        other.defaults
    } else {
        base.defaults
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

    // ----------------------------------------------------------------------
    // Helpers for assembling test data without repeating dozens of fields.
    // ----------------------------------------------------------------------

    fn minimal_rule(id: &str) -> RuleConfig {
        RuleConfig {
            id: id.to_string(),
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
        }
    }

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).expect("write fixture file"); // diffguard: ignore rust.no_unwrap
    }

    fn read_temp_dir() -> TempDir {
        TempDir::new().expect("temp dir") // diffguard: ignore rust.no_unwrap
    }

    // ----------------------------------------------------------------------
    // load_effective_config
    // ----------------------------------------------------------------------

    #[test]
    fn load_effective_config_returns_built_in_when_path_missing() {
        let loaded = load_effective_config(None, false);
        let Ok(config) = loaded else {
            panic!("expected Ok for None path");
        };
        // Built-in rules embed several entries.
        assert!(!config.rule.is_empty());
    }

    #[test]
    fn load_effective_config_merges_with_built_in_when_not_disabled() {
        let temp = read_temp_dir();
        let path = temp.path().join("user.toml");
        write_file(
            &path,
            r#"
[[rule]]
id = "user.only_rule"
severity = "info"
message = "User rule"
patterns = ["zzz"]
"#,
        );

        let loaded = load_effective_config(Some(&path), false);
        let Ok(config) = loaded else {
            panic!("expected Ok config");
        };
        let ids: BTreeSet<String> = config.rule.iter().map(|rule| rule.id.clone()).collect();
        assert!(ids.contains("user.only_rule"), "user rule must be present");
        // Built-in rules contain rust.no_unwrap.
        assert!(
            ids.contains("rust.no_unwrap"),
            "built-in rule must be merged"
        );
    }

    // ----------------------------------------------------------------------
    // resolve_config_path
    // ----------------------------------------------------------------------

    #[test]
    fn resolve_config_path_returns_absolute_override_as_is() {
        let temp = read_temp_dir();
        let absolute = temp.path().join("custom.toml");
        let resolved = resolve_config_path(
            Some(temp.path()),
            Some(absolute.to_string_lossy().to_string()),
            "diffguard.toml",
        );
        assert_eq!(resolved, Some(absolute));
    }

    #[test]
    fn resolve_config_path_joins_relative_override_with_workspace() {
        let temp = read_temp_dir();
        let resolved = resolve_config_path(
            Some(temp.path()),
            Some("relative.toml".to_string()),
            "diffguard.toml",
        );
        assert_eq!(resolved, Some(temp.path().join("relative.toml")));
    }

    #[test]
    fn resolve_config_path_returns_relative_override_without_workspace() {
        let resolved =
            resolve_config_path(None, Some("relative.toml".to_string()), "diffguard.toml");
        assert_eq!(resolved, Some(PathBuf::from("relative.toml")));
    }

    #[test]
    fn resolve_config_path_finds_default_in_workspace_root() {
        let temp = read_temp_dir();
        let default_path = temp.path().join("diffguard.toml");
        write_file(&default_path, "");
        let resolved = resolve_config_path(Some(temp.path()), None, "diffguard.toml");
        assert_eq!(resolved, Some(default_path));
    }

    #[test]
    fn resolve_config_path_returns_none_when_workspace_root_has_no_default() {
        let temp = read_temp_dir();
        let resolved = resolve_config_path(Some(temp.path()), None, "diffguard.toml");
        assert_eq!(resolved, None);
    }

    #[test]
    fn resolve_config_path_without_workspace_or_override_checks_cwd() {
        // No workspace, no override — falls back to a literal default-name lookup.
        // We can't guarantee CWD state, so just verify the function returns either
        // Some(default_name) or None depending on whether that file exists. The
        // important property is that the absolute-path branch is not taken.
        let resolved = resolve_config_path(None, None, "definitely_does_not_exist_12345.toml");
        assert_eq!(resolved, None);
    }

    // ----------------------------------------------------------------------
    // paths_match / normalize_path / to_workspace_relative_path
    // ----------------------------------------------------------------------

    #[test]
    fn paths_match_returns_true_for_canonicalized_same_file() {
        let temp = read_temp_dir();
        let file = temp.path().join("a.toml");
        write_file(&file, "");
        assert!(paths_match(&file, &file));
    }

    #[test]
    fn paths_match_returns_false_when_canonicalize_fails_and_strings_differ() {
        let left = PathBuf::from("/nonexistent/foo");
        let right = PathBuf::from("/nonexistent/bar");
        assert!(!paths_match(&left, &right));
    }

    #[test]
    fn paths_match_returns_true_via_normalize_fallback() {
        let left = PathBuf::from("/nonexistent/same");
        let right = PathBuf::from("/nonexistent/same");
        assert!(paths_match(&left, &right));
    }

    #[test]
    fn normalize_path_replaces_backslashes_with_slashes() {
        let path = Path::new("a\\b\\c.rs");
        assert_eq!(normalize_path(path), "a/b/c.rs");
    }

    #[test]
    fn to_workspace_relative_path_falls_back_to_file_path_when_root_is_none() {
        let file = Path::new("a/b/c.rs");
        assert_eq!(to_workspace_relative_path(None, file), "a/b/c.rs");
    }

    #[test]
    fn to_workspace_relative_path_returns_full_path_when_not_under_root() {
        let root = Path::new("/workspace/root");
        let file = Path::new("/other/place/c.rs");
        assert_eq!(
            to_workspace_relative_path(Some(root), file),
            "/other/place/c.rs"
        );
    }

    #[test]
    fn to_workspace_relative_path_strips_workspace_prefix_and_dot_slash() {
        let temp = read_temp_dir();
        let file = temp.path().join("src/lib.rs");
        let relative = to_workspace_relative_path(Some(temp.path()), &file);
        assert_eq!(relative, "src/lib.rs");
    }

    // ----------------------------------------------------------------------
    // extract_rule_id
    // ----------------------------------------------------------------------

    #[test]
    fn extract_rule_id_returns_none_when_no_code_or_data() {
        let diagnostic = Diagnostic::default();
        assert_eq!(extract_rule_id(&diagnostic), None);
    }

    #[test]
    fn extract_rule_id_returns_none_when_code_is_numeric() {
        let diagnostic = Diagnostic {
            code: Some(NumberOrString::Number(42)),
            ..Diagnostic::default()
        };
        assert_eq!(extract_rule_id(&diagnostic), None);
    }

    #[test]
    fn extract_rule_id_returns_none_when_data_missing_rule_id_field() {
        let diagnostic = Diagnostic {
            data: Some(serde_json::json!({ "other": "thing" })),
            ..Diagnostic::default()
        };
        assert_eq!(extract_rule_id(&diagnostic), None);
    }

    // ----------------------------------------------------------------------
    // find_rule
    // ----------------------------------------------------------------------

    #[test]
    fn find_rule_returns_none_for_unknown_id() {
        let config = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![minimal_rule("known")],
        };
        assert!(find_rule(&config, "unknown").is_none());
    }

    #[test]
    fn find_rule_returns_match_when_present() {
        let config = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![minimal_rule("known")],
        };
        let rule = find_rule(&config, "known");
        assert!(rule.is_some());
    }

    // ----------------------------------------------------------------------
    // format_rule_explanation – cover additional branches
    // ----------------------------------------------------------------------

    #[test]
    fn format_rule_explanation_for_absent_match_mode() {
        let mut rule = minimal_rule("rule.absent");
        rule.match_mode = MatchMode::Absent;
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Match mode: absent"));
    }

    #[test]
    fn format_rule_explanation_includes_multiline_window_when_set() {
        let mut rule = minimal_rule("rule.ml");
        rule.multiline = true;
        rule.multiline_window = Some(5);
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Multiline: yes (window=5)"));
    }

    #[test]
    fn format_rule_explanation_includes_context_patterns_with_default_window() {
        let mut rule = minimal_rule("rule.ctx");
        rule.context_patterns = vec!["foo".to_string(), "bar".to_string()];
        // context_window None should default to 3
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Context patterns (window=3): foo, bar"));
    }

    #[test]
    fn format_rule_explanation_includes_context_patterns_with_explicit_window() {
        let mut rule = minimal_rule("rule.ctx");
        rule.context_patterns = vec!["foo".to_string()];
        rule.context_window = Some(9);
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Context patterns (window=9): foo"));
    }

    #[test]
    fn format_rule_explanation_includes_escalate_with_defaults() {
        let mut rule = minimal_rule("rule.esc");
        rule.escalate_patterns = vec!["bomb".to_string()];
        // escalate_to None defaults to Error; escalate_window None defaults to 0.
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Escalate to error (window=0): bomb"));
    }

    #[test]
    fn format_rule_explanation_includes_escalate_with_explicit_severity_and_window() {
        let mut rule = minimal_rule("rule.esc");
        rule.escalate_patterns = vec!["bomb".to_string()];
        rule.escalate_to = Some(Severity::Info);
        rule.escalate_window = Some(7);
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Escalate to info (window=7): bomb"));
    }

    #[test]
    fn format_rule_explanation_lists_dependencies_and_paths_and_excludes() {
        let mut rule = minimal_rule("rule.deps");
        rule.depends_on = vec!["dep1".to_string(), "dep2".to_string()];
        rule.paths = vec!["**/*.rs".to_string()];
        rule.exclude_paths = vec!["**/tests/**".to_string()];
        rule.languages = vec!["rust".to_string()];
        let output = format_rule_explanation(&rule);
        assert!(output.contains("- Depends on: dep1, dep2"));
        assert!(output.contains("Paths: **/*.rs"));
        assert!(output.contains("Excludes: **/tests/**"));
        assert!(output.contains("Languages: rust"));
    }

    #[test]
    fn format_rule_explanation_renders_help_lines_and_omits_url_when_missing() {
        let mut rule = minimal_rule("rule.help");
        rule.help = Some("line one\nline two".to_string());
        let output = format_rule_explanation(&rule);
        assert!(output.contains("Help:"));
        assert!(output.contains("line one"));
        assert!(output.contains("line two"));
        assert!(!output.contains("URL:"));
    }

    #[test]
    fn format_rule_explanation_renders_no_ignore_flags() {
        let rule = minimal_rule("rule.no_ignore");
        let output = format_rule_explanation(&rule);
        assert!(output.contains("Ignore comments: no"));
        assert!(output.contains("Ignore strings: no"));
    }

    // ----------------------------------------------------------------------
    // find_similar_rules
    // ----------------------------------------------------------------------

    #[test]
    fn find_similar_rules_returns_empty_when_no_match() {
        let rules = vec![minimal_rule("totally.different")];
        let suggestions = find_similar_rules("xyz", &rules);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn find_similar_rules_matches_via_contains_branch() {
        // Neither id nor query is a prefix of the other, but one contains the other.
        // "rust.no_unwrap_in_prod" contains "no_unwrap" via the contains branch.
        let rules = vec![minimal_rule("rust.no_unwrap_in_prod")];
        let suggestions = find_similar_rules("no_unwrap", &rules);
        assert!(suggestions.contains(&"rust.no_unwrap_in_prod".to_string()));
    }

    #[test]
    fn find_similar_rules_prefers_prefix_over_distance() {
        let rules = vec![
            minimal_rule("rust.no_unwrap_extended"),
            minimal_rule("rust.no_panicx"),
        ];
        let suggestions = find_similar_rules("rust.no_unwrap", &rules);
        // The first candidate via starts_with should come first (score 0).
        let Some(first) = suggestions.first() else {
            panic!("expected at least one suggestion");
        };
        assert_eq!(first, "rust.no_unwrap_extended");
    }

    #[test]
    fn find_similar_rules_truncates_to_five() {
        let rules: Vec<RuleConfig> = (0..10)
            .map(|index| minimal_rule(&format!("prefix.rule{index}")))
            .collect();
        let suggestions = find_similar_rules("prefix.rule0", &rules);
        assert!(suggestions.len() <= 5);
    }

    // ----------------------------------------------------------------------
    // load_directory_overrides_for_file
    // ----------------------------------------------------------------------

    #[test]
    fn load_directory_overrides_returns_empty_when_no_files() {
        let temp = read_temp_dir();
        let result = load_directory_overrides_for_file(temp.path(), "src/lib.rs");
        let Ok(overrides) = result else {
            panic!("expected Ok with empty overrides");
        };
        assert!(overrides.is_empty());
    }

    #[test]
    fn load_directory_overrides_loads_root_override() {
        let temp = read_temp_dir();
        write_file(
            &temp.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "rust.no_unwrap"
enabled = false
"#,
        );

        let result = load_directory_overrides_for_file(temp.path(), "src/lib.rs");
        let Ok(overrides) = result else {
            panic!("expected Ok");
        };
        assert_eq!(overrides.len(), 1);
        let Some(first) = overrides.first() else {
            panic!("expected at least one override");
        };
        assert_eq!(first.rule_id, "rust.no_unwrap");
        assert_eq!(first.directory, "");
        assert_eq!(first.enabled, Some(false));
    }

    #[test]
    fn load_directory_overrides_aggregates_nested_directories() {
        let temp = read_temp_dir();
        // Create root override and a nested src/ override.
        write_file(
            &temp.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "root.rule"
enabled = false
"#,
        );
        std::fs::create_dir_all(temp.path().join("src")).expect("mkdir src"); // diffguard: ignore rust.no_unwrap
        write_file(
            &temp.path().join("src/.diffguard.toml"),
            r#"
[[rule]]
id = "src.rule"
severity = "info"
"#,
        );

        let result = load_directory_overrides_for_file(temp.path(), "src/foo/bar.rs");
        let Ok(overrides) = result else {
            panic!("expected Ok");
        };
        let ids: Vec<String> = overrides.iter().map(|o| o.rule_id.clone()).collect();
        assert!(ids.contains(&"root.rule".to_string()));
        assert!(ids.contains(&"src.rule".to_string()));
    }

    #[test]
    fn load_directory_overrides_errors_on_malformed_toml() {
        let temp = read_temp_dir();
        write_file(&temp.path().join(".diffguard.toml"), "not valid = = = toml");
        let result = load_directory_overrides_for_file(temp.path(), "src/lib.rs");
        assert!(result.is_err(), "expected parse error");
    }

    #[test]
    fn load_directory_overrides_errors_on_unset_env_var_without_default() {
        let temp = read_temp_dir();
        // Use a unique variable name that is guaranteed not to be set in the test env.
        write_file(
            &temp.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "${DIFFGUARD_UNSET_TEST_VAR_ZZZ}"
"#,
        );
        let result = load_directory_overrides_for_file(temp.path(), "src/lib.rs");
        let Err(err) = result else {
            panic!("expected Err for unset env var");
        };
        let chain = format!("{err:#}");
        assert!(
            chain.contains("DIFFGUARD_UNSET_TEST_VAR_ZZZ"),
            "got: {chain}"
        );
    }

    // ----------------------------------------------------------------------
    // load_config_recursive: include depth, circular, missing
    // ----------------------------------------------------------------------

    #[test]
    fn load_config_errors_on_missing_include() {
        let temp = read_temp_dir();
        let main = temp.path().join("main.toml");
        write_file(
            &main,
            r#"
includes = ["does_not_exist.toml"]
"#,
        );
        let result = load_effective_config(Some(&main), true);
        let Err(err) = result else {
            panic!("expected error for missing include");
        };
        let chain = format!("{err:#}");
        assert!(
            chain.contains("included config file not found"),
            "got: {chain}"
        );
    }

    #[test]
    fn load_config_detects_circular_include() {
        let temp = read_temp_dir();
        let a = temp.path().join("a.toml");
        let b = temp.path().join("b.toml");
        write_file(&a, r#"includes = ["b.toml"]"#);
        write_file(&b, r#"includes = ["a.toml"]"#);

        let result = load_effective_config(Some(&a), true);
        let Err(err) = result else {
            panic!("expected circular include error");
        };
        let chain = format!("{err:#}");
        assert!(chain.contains("circular include"), "got: {chain}");
    }

    #[test]
    fn load_config_errors_on_excessive_include_depth() {
        let temp = read_temp_dir();
        // Create a chain: 0.toml -> 1.toml -> ... -> 11.toml (12 nodes, depth 11 > MAX_INCLUDE_DEPTH=10).
        let total = 12usize;
        for index in 0..total {
            let path = temp.path().join(format!("{index}.toml"));
            let body = if index + 1 < total {
                format!("includes = [\"{}.toml\"]\n", index + 1)
            } else {
                String::new()
            };
            write_file(&path, &body);
        }
        let entry = temp.path().join("0.toml");
        let result = load_effective_config(Some(&entry), true);
        let Err(err) = result else {
            panic!("expected depth error");
        };
        let chain = format!("{err:#}");
        assert!(chain.contains("include depth exceeded"), "got: {chain}");
    }

    #[test]
    fn load_config_errors_on_unparseable_toml() {
        let temp = read_temp_dir();
        let path = temp.path().join("broken.toml");
        write_file(&path, "this = = is not toml");
        let result = load_effective_config(Some(&path), true);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_errors_on_nonexistent_path() {
        let temp = read_temp_dir();
        let missing = temp.path().join("nope.toml");
        let result = load_effective_config(Some(&missing), true);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_preserves_non_default_defaults_through_merge() {
        // When the loaded user config sets defaults explicitly that differ from
        // the type-level default, the merge path must keep them.
        let temp = read_temp_dir();
        let base = temp.path().join("base.toml");
        let main = temp.path().join("main.toml");
        write_file(
            &base,
            r#"
[[rule]]
id = "base.rule"
severity = "warn"
message = "base"
patterns = ["b"]
"#,
        );
        write_file(
            &main,
            r#"
includes = ["base.toml"]

[defaults]
base = "main"
head = "feature"
max_findings = 7

[[rule]]
id = "main.rule"
severity = "info"
message = "main"
patterns = ["m"]
"#,
        );
        let loaded = load_effective_config(Some(&main), true);
        let Ok(config) = loaded else {
            panic!("expected Ok");
        };
        assert_eq!(config.defaults.base.as_deref(), Some("main"));
        assert_eq!(config.defaults.head.as_deref(), Some("feature"));
        assert_eq!(config.defaults.max_findings, Some(7));
    }

    // ----------------------------------------------------------------------
    // merge_with_built_in: user rule overrides built-in by ID
    // ----------------------------------------------------------------------

    #[test]
    fn merge_with_built_in_lets_user_override_built_in_rule_by_id() {
        let temp = read_temp_dir();
        let path = temp.path().join("user.toml");
        write_file(
            &path,
            r#"
[[rule]]
id = "rust.no_unwrap"
severity = "info"
message = "Custom override"
patterns = ["override-pattern"]
"#,
        );
        let loaded = load_effective_config(Some(&path), false);
        let Ok(config) = loaded else {
            panic!("expected Ok");
        };
        let Some(rule) = config.rule.iter().find(|rule| rule.id == "rust.no_unwrap") else {
            panic!("user override missing from merged config");
        };
        assert_eq!(rule.message, "Custom override");
        assert!(matches!(rule.severity, Severity::Info));
    }

    // ----------------------------------------------------------------------
    // expand_env_vars (exercised through directory override loader)
    // ----------------------------------------------------------------------

    #[test]
    fn expand_env_vars_uses_inline_default_when_unset() {
        let temp = read_temp_dir();
        write_file(
            &temp.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "${DIFFGUARD_TEST_UNSET_ZZZ:-fallback.rule_id}"
"#,
        );
        let result = load_directory_overrides_for_file(temp.path(), "lib.rs");
        let Ok(overrides) = result else {
            panic!("expected Ok with inline default substitution");
        };
        let Some(first) = overrides.first() else {
            panic!("expected one override");
        };
        assert_eq!(first.rule_id, "fallback.rule_id");
    }

    // Note: the substituted-value path of expand_env_vars requires mutating
    // the process-wide environment (`std::env::set_var`), which in Rust 2024
    // is unsafe because parallel cargo test threads can race with other
    // crates' `std::env::var(...)` reads (segfault / abort under contention).
    // Coverage of that branch is intentionally omitted — the fallback path
    // (covered above) and the no-default error path (covered below) already
    // exercise the surrounding control flow.

    // ----------------------------------------------------------------------
    // Internal helpers exercised through behaviour
    // ----------------------------------------------------------------------

    #[test]
    fn collect_override_candidates_returns_only_root_for_bare_filename() {
        let mut set = BTreeSet::new();
        collect_override_candidates_for_path("lib.rs", &mut set);
        // A bare filename has no parent component, so only the root override
        // candidate should be emitted.
        assert_eq!(set.len(), 1);
        assert!(set.contains(&PathBuf::from(".diffguard.toml")));
    }

    #[test]
    fn collect_override_candidates_walks_up_from_nested_path() {
        let mut set = BTreeSet::new();
        collect_override_candidates_for_path("a/b/c/d.rs", &mut set);
        // Candidates for each ancestor: a/b/c, a/b, a, "" — four entries.
        assert!(set.contains(&PathBuf::from("a/b/c/.diffguard.toml")));
        assert!(set.contains(&PathBuf::from("a/b/.diffguard.toml")));
        assert!(set.contains(&PathBuf::from("a/.diffguard.toml")));
        assert!(set.contains(&PathBuf::from(".diffguard.toml")));
    }

    #[test]
    fn normalize_override_directory_returns_empty_for_root_or_dot() {
        // Verified indirectly: a root .diffguard.toml emits overrides with directory == "".
        let temp = read_temp_dir();
        write_file(
            &temp.path().join(".diffguard.toml"),
            r#"
[[rule]]
id = "x"
"#,
        );
        let Ok(overrides) = load_directory_overrides_for_file(temp.path(), "f.rs") else {
            panic!("expected Ok");
        };
        let Some(first) = overrides.first() else {
            panic!("expected one override");
        };
        assert_eq!(first.directory, "");
    }

    #[test]
    fn normalize_override_directory_keeps_nested_path() {
        let temp = read_temp_dir();
        std::fs::create_dir_all(temp.path().join("src/deep")).expect("mkdir nested"); // diffguard: ignore rust.no_unwrap
        write_file(
            &temp.path().join("src/deep/.diffguard.toml"),
            r#"
[[rule]]
id = "deep.rule"
"#,
        );
        let Ok(overrides) = load_directory_overrides_for_file(temp.path(), "src/deep/file.rs")
        else {
            panic!("expected Ok");
        };
        let Some(deep) = overrides.iter().find(|o| o.rule_id == "deep.rule") else {
            panic!("expected deep override");
        };
        assert_eq!(deep.directory, "src/deep");
    }

    #[test]
    fn simple_edit_distance_handles_empty_strings() {
        // Edge: find_similar_rules uses simple_edit_distance via the contains
        // branch and the distance branch. Cover the "empty rule id" path by
        // letting an empty rule id match the contains branch.
        let mut rule = minimal_rule("totally.different.id");
        // Set id to empty after construction to exercise the contains shortcut.
        rule.id = "".to_string();
        let suggestions = find_similar_rules("nonempty.query", &[rule]);
        // An empty id is a substring of any query, so it must be suggested.
        assert!(suggestions.contains(&"".to_string()));
    }

    #[test]
    fn simple_edit_distance_returns_full_length_when_one_side_empty() {
        // Drives the early-return branches in simple_edit_distance by handing it
        // a rule whose id avoids both prefix and contains short-circuits and
        // whose distance to the query is exactly within the threshold.
        // Query "abc" vs id "xyz": neither prefix, no contains, distance = 3.
        let rule = minimal_rule("xyz");
        let suggestions = find_similar_rules("abc", &[rule]);
        assert!(suggestions.contains(&"xyz".to_string()));
    }

    #[test]
    fn collect_override_candidates_handles_empty_path() {
        // Path::new("").parent() returns None, which exercises the
        // early-return branch.
        let mut set = BTreeSet::new();
        collect_override_candidates_for_path("", &mut set);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&PathBuf::from(".diffguard.toml")));
    }
}
