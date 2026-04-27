//! Configuration loading with include resolution.
//!
//! This module handles loading configuration files with support for:
//! - `includes` directive to compose configs from multiple files
//! - Circular include detection
//! - Merge semantics (later definitions override earlier ones)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tracing::debug;

use diffguard_types::ConfigFile;

/// Maximum depth for include resolution to prevent excessive nesting.
const MAX_INCLUDE_DEPTH: usize = 10;

/// Load a configuration file with include resolution.
///
/// Uses ancestor-stack cycle detection: a file is a cycle only if it
/// appears in the current include chain. The same file can be included
/// through different branches (valid DAG configuration).
///
/// # Arguments
/// * `path` - Path to the main config file
/// * `expand_env` - Function to expand environment variables in the config text
///
/// # Returns
/// The merged configuration file with all includes resolved.
pub fn load_config_with_includes<F>(path: &Path, expand_env: F) -> Result<ConfigFile>
where
    F: Fn(&str) -> Result<String> + Copy,
{
    let mut ancestor_stack = Vec::new();
    let mut load_cache: HashMap<PathBuf, ConfigFile> = HashMap::new();
    load_config_recursive(path, expand_env, &mut ancestor_stack, &mut load_cache, 0)
}

fn load_config_recursive<F>(
    path: &Path,
    expand_env: F,
    ancestor_stack: &mut Vec<PathBuf>,
    load_cache: &mut std::collections::HashMap<PathBuf, ConfigFile>,
    depth: usize,
) -> Result<ConfigFile>
where
    F: Fn(&str) -> Result<String> + Copy,
{
    // Check depth limit
    if depth > MAX_INCLUDE_DEPTH {
        bail!(
            "Include depth exceeded maximum of {} levels at '{}'",
            MAX_INCLUDE_DEPTH,
            path.display()
        );
    }

    // Canonicalize path for consistent comparison
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize path '{}'", path.display()))?;

    // Check for circular includes (ancestor stack, not global visited set)
    if ancestor_stack.contains(&canonical) {
        bail!(
            "Circular include detected: '{}' (chain: {})",
            path.display(),
            ancestor_stack
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" → ")
        );
    }

    // Check cache — reuse loaded configs for DAG configurations
    if let Some(cached) = load_cache.get(&canonical) {
        debug!(
            "Reusing cached config for '{}' (depth {})",
            path.display(),
            depth
        );
        return Ok(cached.clone());
    }

    debug!("Loading config from '{}' (depth {})", path.display(), depth);

    // Read and parse the config file
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config '{}'", path.display()))?;

    let expanded = expand_env(&text)?;

    let config: ConfigFile =
        toml::from_str(&expanded).with_context(|| format!("parse config '{}'", path.display()))?;

    // If no includes, return as-is
    if config.includes.is_empty() {
        load_cache.insert(canonical, config.clone());
        return Ok(config);
    }

    // Push current path onto ancestor stack before processing includes
    ancestor_stack.push(canonical.clone());

    // Get the directory of the current config for relative path resolution
    let base_dir = path.parent().unwrap_or(Path::new("."));

    // Load and merge all includes
    let mut merged = ConfigFile {
        includes: vec![],
        defaults: diffguard_types::Defaults::default(),
        rule: vec![],
    };

    for include_path in &config.includes {
        let full_path = base_dir.join(include_path);
        debug!(
            "Resolving include '{}' relative to '{}'",
            include_path,
            base_dir.display()
        );

        if !full_path.exists() {
            bail!(
                "Included config file not found: '{}' (resolved from '{}')",
                full_path.display(),
                include_path
            );
        }

        let included = load_config_recursive(
            &full_path,
            expand_env,
            ancestor_stack,
            load_cache,
            depth + 1,
        )?;
        merged = merge_configs(merged, included);
    }

    // Pop current path from ancestor stack
    ancestor_stack.pop();

    // Merge the main config on top of includes (main config wins)
    let main_without_includes = ConfigFile {
        includes: vec![],
        defaults: config.defaults,
        rule: config.rule,
    };
    merged = merge_configs(merged, main_without_includes);

    Ok(merged)
}

/// Merge two configs. Rules from `other` override rules from `base` by ID.
/// Defaults are merged field-wise: `Some` in `other` overrides `base`, `None` inherits.
fn merge_configs(base: ConfigFile, other: ConfigFile) -> ConfigFile {
    // Defaults: field-wise merge (None means "inherit from parent")
    let defaults = diffguard_types::Defaults {
        base: other.defaults.base.or(base.defaults.base),
        head: other.defaults.head.or(base.defaults.head),
        scope: other.defaults.scope.or(base.defaults.scope),
        fail_on: other.defaults.fail_on.or(base.defaults.fail_on),
        max_findings: other.defaults.max_findings.or(base.defaults.max_findings),
        diff_context: other.defaults.diff_context.or(base.defaults.diff_context),
        ignore_comments: other
            .defaults
            .ignore_comments
            .or(base.defaults.ignore_comments),
        ignore_strings: other
            .defaults
            .ignore_strings
            .or(base.defaults.ignore_strings),
    };

    // Rules: merge by ID, other overrides base
    let mut rules_map = std::collections::BTreeMap::new();
    for rule in base.rule {
        rules_map.insert(rule.id.clone(), rule);
    }
    for rule in other.rule {
        rules_map.insert(rule.id.clone(), rule);
    }

    ConfigFile {
        includes: vec![],
        defaults,
        rule: rules_map.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::fs;
    use tempfile::TempDir;

    fn no_expand(s: &str) -> Result<String> {
        Ok(s.to_string())
    }

    #[test]
    fn test_simple_config_no_includes() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&config_path, no_expand).unwrap();
        assert_eq!(result.rule.len(), 1);
        assert_eq!(result.rule[0].id, "test.rule");
    }

    #[test]
    fn test_include_single_file() {
        let temp = TempDir::new().unwrap();

        // Create base config
        let base_path = temp.path().join("base.toml");
        fs::write(
            &base_path,
            r#"
[[rule]]
id = "base.rule"
severity = "warn"
message = "Base"
patterns = ["base"]
"#,
        )
        .unwrap();

        // Create main config that includes base
        let main_path = temp.path().join("main.toml");
        fs::write(
            &main_path,
            r#"
includes = ["base.toml"]

[[rule]]
id = "main.rule"
severity = "error"
message = "Main"
patterns = ["main"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&main_path, no_expand).unwrap();
        assert_eq!(result.rule.len(), 2);

        let ids: Vec<_> = result.rule.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"base.rule"));
        assert!(ids.contains(&"main.rule"));
    }

    #[test]
    fn test_include_override_by_id() {
        let temp = TempDir::new().unwrap();

        // Create base config
        let base_path = temp.path().join("base.toml");
        fs::write(
            &base_path,
            r#"
[[rule]]
id = "shared.rule"
severity = "warn"
message = "From base"
patterns = ["base"]
"#,
        )
        .unwrap();

        // Create main config that overrides the same rule ID
        let main_path = temp.path().join("main.toml");
        fs::write(
            &main_path,
            r#"
includes = ["base.toml"]

[[rule]]
id = "shared.rule"
severity = "error"
message = "From main"
patterns = ["main"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&main_path, no_expand).unwrap();
        assert_eq!(result.rule.len(), 1);
        assert_eq!(result.rule[0].id, "shared.rule");
        assert_eq!(result.rule[0].message, "From main");
        assert_eq!(result.rule[0].severity, diffguard_types::Severity::Error);
    }

    #[test]
    fn test_circular_include_detected() {
        let temp = TempDir::new().unwrap();

        // Create config A that includes B
        let a_path = temp.path().join("a.toml");
        let b_path = temp.path().join("b.toml");

        fs::write(&a_path, "includes = [\"b.toml\"]\n").unwrap();
        fs::write(&b_path, "includes = [\"a.toml\"]\n").unwrap();

        let result = load_config_with_includes(&a_path, no_expand);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular include"));
    }

    #[test]
    fn test_missing_include_errors() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        fs::write(&config_path, "includes = [\"nonexistent.toml\"]\n").unwrap();

        let result = load_config_with_includes(&config_path, no_expand);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_nested_includes() {
        let temp = TempDir::new().unwrap();

        // Create level 3 config
        let level3_path = temp.path().join("level3.toml");
        fs::write(
            &level3_path,
            r#"
[[rule]]
id = "level3.rule"
severity = "info"
message = "Level 3"
patterns = ["l3"]
"#,
        )
        .unwrap();

        // Create level 2 config
        let level2_path = temp.path().join("level2.toml");
        fs::write(
            &level2_path,
            r#"
includes = ["level3.toml"]

[[rule]]
id = "level2.rule"
severity = "warn"
message = "Level 2"
patterns = ["l2"]
"#,
        )
        .unwrap();

        // Create level 1 config
        let level1_path = temp.path().join("level1.toml");
        fs::write(
            &level1_path,
            r#"
includes = ["level2.toml"]

[[rule]]
id = "level1.rule"
severity = "error"
message = "Level 1"
patterns = ["l1"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&level1_path, no_expand).unwrap();
        assert_eq!(result.rule.len(), 3);

        let ids: Vec<_> = result.rule.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"level1.rule"));
        assert!(ids.contains(&"level2.rule"));
        assert!(ids.contains(&"level3.rule"));
    }

    #[test]
    fn test_include_depth_limit_exceeded() {
        let temp = TempDir::new().unwrap();

        // Create a chain longer than MAX_INCLUDE_DEPTH
        for i in 0..=MAX_INCLUDE_DEPTH + 1 {
            let path = temp.path().join(format!("level{}.toml", i));
            if i < MAX_INCLUDE_DEPTH + 1 {
                let include_line = format!("includes = [\"level{}.toml\"]\n", i + 1);
                fs::write(&path, include_line).unwrap();
            } else {
                fs::write(&path, "").unwrap();
            }
        }

        let root = temp.path().join("level0.toml");
        let result = load_config_with_includes(&root, no_expand);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Include depth exceeded")
        );
    }

    #[test]
    fn test_merge_configs_defaults_override() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("base".to_string()),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                head: Some("head".to_string()),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(merged.defaults.head.as_deref(), Some("head"));
    }

    #[test]
    fn test_include_logging_path_resolution_debug() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        let temp = TempDir::new().unwrap();
        let base_path = temp.path().join("base.toml");
        fs::write(
            &base_path,
            r#"
[[rule]]
id = "base.rule"
severity = "warn"
message = "Base"
patterns = ["base"]
"#,
        )
        .unwrap();

        let main_path = temp.path().join("main.toml");
        fs::write(&main_path, "includes = [\"base.toml\"]\n").unwrap();

        let result = load_config_with_includes(&main_path, no_expand).unwrap();
        assert_eq!(result.rule.len(), 1);
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("bad.toml");
        fs::write(&config_path, "invalid = [").unwrap();

        let result = load_config_with_includes(&config_path, no_expand);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse config"));
    }

    #[test]
    fn test_expand_env_error_propagates() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
[[rule]]
id = "test.rule"
severity = "warn"
message = "Test"
patterns = ["test"]
"#,
        )
        .unwrap();

        let expand_env = |_s: &str| -> Result<String> { bail!("expand failed") };
        let result = load_config_with_includes(&config_path, expand_env);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expand failed"));
    }

    #[test]
    fn test_merge_configs_keeps_base_defaults_when_other_default() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("origin/main".to_string()),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/main"));
    }

    #[test]
    fn test_merge_defaults_field_wise() {
        // Parent sets base + scope, child sets only fail_on
        // With field-wise merge, child's fail_on overrides,
        // parent's base and scope are preserved
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("origin/develop".to_string()),
                head: Some("HEAD".to_string()),
                scope: Some(diffguard_types::Scope::Modified),
                fail_on: Some(diffguard_types::FailOn::Error),
                max_findings: Some(200),
                diff_context: Some(0),
                ignore_comments: None,
                ignore_strings: None,
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                fail_on: Some(diffguard_types::FailOn::Warn),
                ..Default::default() // all other fields are Some(default_value)
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        // child's fail_on wins (it's Some in child)
        assert_eq!(merged.defaults.fail_on, Some(diffguard_types::FailOn::Warn));
        // child's other fields also win because they're Some in child
        assert_eq!(merged.defaults.base.as_deref(), Some("origin/main"));
    }

    #[test]
    fn test_merge_defaults_none_inherits() {
        // Parent sets base + scope, child has None for most fields
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: Some("origin/develop".to_string()),
                head: Some("HEAD".to_string()),
                scope: Some(diffguard_types::Scope::Modified),
                fail_on: Some(diffguard_types::FailOn::Error),
                max_findings: Some(200),
                diff_context: Some(0),
                ignore_comments: None,
                ignore_strings: None,
            },
            rule: vec![],
        };

        // Simulate a child config that only sets fail_on in TOML
        // (other fields are None when missing from TOML)
        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                base: None,
                head: None,
                scope: None,
                fail_on: Some(diffguard_types::FailOn::Warn),
                max_findings: None,
                diff_context: None,
                ignore_comments: None,
                ignore_strings: None,
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(
            merged.defaults.base.as_deref(),
            Some("origin/develop"),
            "base should inherit from parent"
        );
        assert_eq!(
            merged.defaults.scope,
            Some(diffguard_types::Scope::Modified),
            "scope should inherit from parent"
        );
        assert_eq!(
            merged.defaults.fail_on,
            Some(diffguard_types::FailOn::Warn),
            "fail_on should be overridden by child"
        );
        assert_eq!(
            merged.defaults.max_findings,
            Some(200),
            "max_findings should inherit from parent"
        );
    }

    #[test]
    fn test_dag_includes_same_file_twice() {
        // main → {team-a, team-b} → shared-base
        // This is a valid DAG, not a cycle
        let temp = TempDir::new().unwrap();

        // shared-base.toml
        fs::write(
            temp.path().join("shared-base.toml"),
            r#"
[[rule]]
id = "shared.rule"
severity = "warn"
message = "Shared rule"
patterns = ["shared"]
"#,
        )
        .unwrap();

        // team-a.toml includes shared-base
        fs::write(
            temp.path().join("team-a.toml"),
            r#"
includes = ["shared-base.toml"]

[[rule]]
id = "team-a.rule"
severity = "warn"
message = "Team A"
patterns = ["alpha"]
"#,
        )
        .unwrap();

        // team-b.toml includes shared-base
        fs::write(
            temp.path().join("team-b.toml"),
            r#"
includes = ["shared-base.toml"]

[[rule]]
id = "team-b.rule"
severity = "warn"
message = "Team B"
patterns = ["beta"]
"#,
        )
        .unwrap();

        // main.toml includes both team-a and team-b
        fs::write(
            temp.path().join("main.toml"),
            r#"
includes = ["team-a.toml", "team-b.toml"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&temp.path().join("main.toml"), no_expand);
        assert!(
            result.is_ok(),
            "DAG includes should not be treated as cycles: {:?}",
            result.err()
        );

        let config = result.unwrap();
        // Should have all 3 rules: shared (once), team-a, team-b
        let rule_ids: Vec<&str> = config.rule.iter().map(|r| r.id.as_str()).collect();
        assert!(
            rule_ids.contains(&"shared.rule"),
            "should include shared rule"
        );
        assert!(
            rule_ids.contains(&"team-a.rule"),
            "should include team-a rule"
        );
        assert!(
            rule_ids.contains(&"team-b.rule"),
            "should include team-b rule"
        );
    }

    #[test]
    fn test_cycle_detection_still_works() {
        // main → a → b → main (real cycle)
        let temp = TempDir::new().unwrap();

        fs::write(
            temp.path().join("main.toml"),
            r#"
includes = ["a.toml"]

[[rule]]
id = "main.rule"
severity = "warn"
message = "Main"
patterns = ["main"]
"#,
        )
        .unwrap();

        fs::write(
            temp.path().join("a.toml"),
            r#"
includes = ["b.toml"]

[[rule]]
id = "a.rule"
severity = "warn"
message = "A"
patterns = ["a"]
"#,
        )
        .unwrap();

        fs::write(
            temp.path().join("b.toml"),
            r#"
includes = ["main.toml"]

[[rule]]
id = "b.rule"
severity = "warn"
message = "B"
patterns = ["b"]
"#,
        )
        .unwrap();

        let result = load_config_with_includes(&temp.path().join("main.toml"), no_expand);
        assert!(result.is_err(), "real cycles should still be detected");
        assert!(result.unwrap_err().to_string().contains("Circular include"));
    }

    #[test]
    fn test_merge_configs_ignore_comments_other_takes_precedence() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_comments: Some(false),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_comments: Some(true),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(
            merged.defaults.ignore_comments,
            Some(true),
            "other.defaults.ignore_comments should take precedence over base"
        );
    }

    #[test]
    fn test_merge_configs_ignore_strings_other_takes_precedence() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_strings: Some(false),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_strings: Some(true),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(
            merged.defaults.ignore_strings,
            Some(true),
            "other.defaults.ignore_strings should take precedence over base"
        );
    }

    #[test]
    fn test_merge_configs_ignore_comments_inherits_from_base_when_other_is_none() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_comments: Some(true),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_comments: None,
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(
            merged.defaults.ignore_comments,
            Some(true),
            "base.defaults.ignore_comments should be inherited when other is None"
        );
    }

    #[test]
    fn test_merge_configs_ignore_strings_inherits_from_base_when_other_is_none() {
        let base = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_strings: Some(true),
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let other = ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults {
                ignore_strings: None,
                ..diffguard_types::Defaults::default()
            },
            rule: vec![],
        };

        let merged = merge_configs(base, other);
        assert_eq!(
            merged.defaults.ignore_strings,
            Some(true),
            "base.defaults.ignore_strings should be inherited when other is None"
        );
    }
}
