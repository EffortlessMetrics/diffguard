use std::collections::BTreeMap;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use diffguard_types::Severity;

/// A per-directory rule override loaded from `.diffguard.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRuleOverride {
    /// Directory path (repo-relative). Empty string means repo root.
    pub directory: String,
    /// Rule identifier to override.
    pub rule_id: String,
    /// Optional enabled/disabled flag.
    pub enabled: Option<bool>,
    /// Optional severity override for files in scope.
    pub severity: Option<Severity>,
    /// Additional exclude globs scoped to this directory.
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OverrideCompileError {
    #[error("rule override '{rule_id}' in '{directory}' has invalid glob '{glob}': {source}")]
    InvalidGlob {
        rule_id: String,
        directory: String,
        glob: String,
        source: globset::Error,
    },
}

#[derive(Debug, Clone)]
struct CompiledDirectoryRuleOverride {
    directory: String,
    depth: usize,
    enabled: Option<bool>,
    severity: Option<Severity>,
    exclude: Option<GlobSet>,
}

/// Resolved effective override state for a single (path, rule) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRuleOverride {
    /// Whether this rule is enabled for the path.
    pub enabled: bool,
    /// Optional severity override.
    pub severity: Option<Severity>,
}

impl Default for ResolvedRuleOverride {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: None,
        }
    }
}

/// Matcher for per-directory overrides.
///
/// Overrides are applied from shallowest to deepest directory so child
/// directories can refine parent behavior.
#[derive(Debug, Clone, Default)]
pub struct RuleOverrideMatcher {
    by_rule: BTreeMap<String, Vec<CompiledDirectoryRuleOverride>>,
}

impl RuleOverrideMatcher {
    /// Compile raw directory overrides into a matcher.
    pub fn compile(specs: &[DirectoryRuleOverride]) -> Result<Self, OverrideCompileError> {
        let mut by_rule: BTreeMap<String, Vec<CompiledDirectoryRuleOverride>> = BTreeMap::new();

        for spec in specs {
            let directory = normalize_directory(&spec.directory);
            let exclude = compile_exclude_globs(&directory, &spec.rule_id, &spec.exclude_paths)?;

            by_rule
                .entry(spec.rule_id.clone())
                .or_default()
                .push(CompiledDirectoryRuleOverride {
                    depth: directory_depth(&directory),
                    directory,
                    enabled: spec.enabled,
                    severity: spec.severity,
                    exclude,
                });
        }

        for entries in by_rule.values_mut() {
            entries.sort_by(|a, b| {
                a.depth
                    .cmp(&b.depth)
                    .then_with(|| a.directory.cmp(&b.directory))
            });
        }

        Ok(Self { by_rule })
    }

    /// Resolve the effective override for a specific path and rule id.
    pub fn resolve(&self, path: &str, rule_id: &str) -> ResolvedRuleOverride {
        let Some(entries) = self.by_rule.get(rule_id) else {
            return ResolvedRuleOverride::default();
        };

        let mut resolved = ResolvedRuleOverride::default();
        let normalized_path = normalize_path(path);
        let path_ref = Path::new(&normalized_path);

        for entry in entries {
            if !path_in_directory(&normalized_path, &entry.directory) {
                continue;
            }

            if let Some(enabled) = entry.enabled {
                resolved.enabled = enabled;
            }

            if let Some(severity) = entry.severity {
                resolved.severity = Some(severity);
            }

            if entry
                .exclude
                .as_ref()
                .is_some_and(|exclude| exclude.is_match(path_ref))
            {
                resolved.enabled = false;
            }
        }

        resolved
    }
}

fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let without_dot = replaced.strip_prefix("./").unwrap_or(&replaced);
    without_dot.trim_start_matches('/').to_string()
}

fn normalize_directory(directory: &str) -> String {
    let normalized = normalize_path(directory);
    if normalized.is_empty() || normalized == "." {
        return String::new();
    }
    normalized.trim_end_matches('/').to_string()
}

fn directory_depth(directory: &str) -> usize {
    if directory.is_empty() {
        0
    } else {
        directory.split('/').filter(|s| !s.is_empty()).count()
    }
}

fn path_in_directory(path: &str, directory: &str) -> bool {
    if directory.is_empty() {
        return true;
    }
    if path == directory {
        return true;
    }
    path.starts_with(directory) && path.as_bytes().get(directory.len()) == Some(&b'/')
}

fn compile_exclude_globs(
    directory: &str,
    rule_id: &str,
    globs: &[String],
) -> Result<Option<GlobSet>, OverrideCompileError> {
    if globs.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for glob in globs {
        let scoped = scope_glob_to_directory(directory, glob);
        let parsed = Glob::new(&scoped).map_err(|source| OverrideCompileError::InvalidGlob {
            rule_id: rule_id.to_string(),
            directory: directory.to_string(),
            glob: scoped.clone(),
            source,
        })?;
        builder.add(parsed);
    }

    Ok(Some(builder.build().expect("globset build should succeed")))
}

fn scope_glob_to_directory(directory: &str, glob: &str) -> String {
    let replaced = glob.replace('\\', "/");
    let without_dot = replaced.strip_prefix("./").unwrap_or(&replaced);

    if directory.is_empty() || without_dot.starts_with('/') {
        without_dot.trim_start_matches('/').to_string()
    } else {
        format!("{}/{}", directory, without_dot.trim_start_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn override_spec(
        directory: &str,
        rule_id: &str,
        enabled: Option<bool>,
        severity: Option<Severity>,
        exclude_paths: Vec<&str>,
    ) -> DirectoryRuleOverride {
        DirectoryRuleOverride {
            directory: directory.to_string(),
            rule_id: rule_id.to_string(),
            enabled,
            severity,
            exclude_paths: exclude_paths.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parent_and_child_overrides_merge_in_depth_order() {
        let matcher = RuleOverrideMatcher::compile(&[
            override_spec("src", "rust.no_unwrap", Some(false), None, vec![]),
            override_spec(
                "src/legacy",
                "rust.no_unwrap",
                Some(true),
                Some(Severity::Warn),
                vec![],
            ),
        ])
        .expect("compile overrides");

        let parent_only = matcher.resolve("src/new/mod.rs", "rust.no_unwrap");
        assert!(!parent_only.enabled);
        assert_eq!(parent_only.severity, None);

        let child = matcher.resolve("src/legacy/mod.rs", "rust.no_unwrap");
        assert!(child.enabled);
        assert_eq!(child.severity, Some(Severity::Warn));
    }

    #[test]
    fn exclude_paths_are_scoped_to_override_directory() {
        let matcher = RuleOverrideMatcher::compile(&[override_spec(
            "src",
            "rust.no_unwrap",
            None,
            None,
            vec!["**/generated/**"],
        )])
        .expect("compile overrides");

        assert!(
            !matcher
                .resolve("src/generated/file.rs", "rust.no_unwrap")
                .enabled
        );
        assert!(
            matcher
                .resolve("generated/file.rs", "rust.no_unwrap")
                .enabled
        );
    }

    #[test]
    fn root_directory_override_applies_everywhere() {
        let matcher = RuleOverrideMatcher::compile(&[override_spec(
            "",
            "rust.no_unwrap",
            Some(false),
            None,
            vec![],
        )])
        .expect("compile overrides");

        assert!(!matcher.resolve("src/lib.rs", "rust.no_unwrap").enabled);
        assert!(!matcher.resolve("main.rs", "rust.no_unwrap").enabled);
    }

    #[test]
    fn invalid_override_glob_returns_error() {
        let err = RuleOverrideMatcher::compile(&[override_spec(
            "src",
            "rust.no_unwrap",
            None,
            None,
            vec!["["],
        )])
        .expect_err("invalid glob should fail");

        match err {
            OverrideCompileError::InvalidGlob { glob, .. } => {
                assert_eq!(glob, "src/[");
            }
        }
    }
}
