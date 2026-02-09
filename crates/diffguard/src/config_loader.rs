//! Configuration loading with include resolution.
//!
//! This module handles loading configuration files with support for:
//! - `includes` directive to compose configs from multiple files
//! - Circular include detection
//! - Merge semantics (later definitions override earlier ones)

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::debug;

use diffguard_types::ConfigFile;

/// Maximum depth for include resolution to prevent excessive nesting.
const MAX_INCLUDE_DEPTH: usize = 10;

/// Load a configuration file with include resolution.
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
    let mut visited = HashSet::new();
    load_config_recursive(path, expand_env, &mut visited, 0)
}

fn load_config_recursive<F>(
    path: &Path,
    expand_env: F,
    visited: &mut HashSet<PathBuf>,
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

    // Check for circular includes
    if !visited.insert(canonical.clone()) {
        bail!("Circular include detected: '{}'", path.display());
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
        return Ok(config);
    }

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

        let included = load_config_recursive(&full_path, expand_env, visited, depth + 1)?;
        merged = merge_configs(merged, included);
    }

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
fn merge_configs(base: ConfigFile, other: ConfigFile) -> ConfigFile {
    // Defaults: other overrides base
    let defaults = if other.defaults != diffguard_types::Defaults::default() {
        other.defaults
    } else {
        base.defaults
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Include depth exceeded"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("parse config"));
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
}
