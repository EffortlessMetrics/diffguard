use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use diffguard_domain::DirectoryRuleOverride;
use diffguard_types::{ConfigFile, DirectoryOverrideConfig, MatchMode, RuleConfig, Severity};
use lsp_types::{Diagnostic, NumberOrString};
use regex::Regex;

const DIRECTORY_OVERRIDE_NAME: &str = ".diffguard.toml";
const MAX_INCLUDE_DEPTH: usize = 10;

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

pub fn paths_match(left: &Path, right: &Path) -> bool {
    let left_canonical = left.canonicalize().ok();
    let right_canonical = right.canonicalize().ok();
    if let (Some(left), Some(right)) = (left_canonical, right_canonical) {
        return left == right;
    }
    normalize_path(left) == normalize_path(right)
}

pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

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

pub fn find_rule<'a>(config: &'a ConfigFile, rule_id: &str) -> Option<&'a RuleConfig> {
    config.rule.iter().find(|rule| rule.id == rule_id)
}

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
            let cost = if left_chars[i - 1] == right_chars[j - 1] {
                0
            } else {
                1
            };
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
}
