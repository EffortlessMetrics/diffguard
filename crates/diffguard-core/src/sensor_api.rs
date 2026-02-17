//! R2 Library Contract: `run_sensor()` entry point for Cockpit/BusyBox integration.
//!
//! This module provides the `Settings` + `Substrate` → `SensorReport` contract
//! required by the Governance OS "Fleet Crate Tiering" specification.

use std::collections::HashMap;

use diffguard_types::{ConfigFile, SensorReport};

use crate::check::{CheckPlan, run_check};
use crate::sensor::{RuleMetadata, SensorReportContext, render_sensor_report};

/// Consolidated input for the diffguard sensor engine.
///
/// This is the R2 Library Contract entry point.
pub struct Settings {
    /// Parsed configuration (rules, defaults).
    pub config: ConfigFile,
    /// Check execution plan (refs, scope, fail_on, etc.).
    pub plan: CheckPlan,
    /// Raw unified diff text.
    pub diff_text: String,
    /// Sensor envelope context (timing, capabilities).
    pub context: SensorReportContext,
}

/// Optional shared substrate from the Cockpit runtime.
///
/// Provides pre-computed inventory to avoid redundant scans.
/// No sensor may *require* a `Substrate` to function.
pub trait Substrate {
    /// Pre-computed list of changed file paths (forward-slash normalized).
    fn changed_files(&self) -> Option<&[String]> {
        None
    }
    /// Repository root path.
    fn repo_root(&self) -> Option<&std::path::Path> {
        None
    }
    /// Arbitrary metadata from the substrate provider.
    fn metadata(&self) -> Option<&serde_json::Value> {
        None
    }
}

/// R2 Library Contract: run the diffguard sensor and return a `SensorReport`.
///
/// This is the entry point for BusyBox/integrated cockpit usage.
/// For standalone CLI usage, use `run_check()` directly.
pub fn run_sensor(
    settings: &Settings,
    substrate: Option<&dyn Substrate>,
) -> Result<SensorReport, anyhow::Error> {
    // 1. Run the check (substrate currently unused; reserved for future optimization)
    let _ = substrate;
    let check_run = run_check(&settings.plan, &settings.config, &settings.diff_text)?;

    // 2. Build rule metadata from config and merge check stats into context
    let rule_metadata = extract_rule_metadata(&settings.config);
    let ctx = SensorReportContext {
        rule_metadata,
        truncated_count: check_run.truncated_findings,
        rules_total: check_run.rules_evaluated,
        ..settings.context.clone()
    };

    // 3. Convert to sensor report
    Ok(render_sensor_report(&check_run.receipt, &ctx))
}

/// Extracts rule metadata (help text, URL, and tags) from a config file.
fn extract_rule_metadata(config: &ConfigFile) -> HashMap<String, RuleMetadata> {
    config
        .rule
        .iter()
        .map(|r| {
            (
                r.id.clone(),
                RuleMetadata {
                    help: r.help.clone(),
                    url: r.url.clone(),
                    tags: r.tags.clone(),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CAP_GIT, CAP_STATUS_AVAILABLE, CapabilityStatus, FailOn, RuleConfig,
        SENSOR_REPORT_SCHEMA_V1, Scope, Severity,
    };
    use std::collections::HashMap;

    fn test_config() -> ConfigFile {
        ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![RuleConfig {
                id: "test.rule".to_string(),
                severity: Severity::Warn,
                message: "Test match".to_string(),
                languages: vec![],
                patterns: vec!["test_pattern".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                help: Some("Fix the test pattern".to_string()),
                url: Some("https://example.com/help".to_string()),
                tags: vec![],
                test_cases: vec![],
            }],
        }
    }

    fn test_plan() -> CheckPlan {
        CheckPlan {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            scope: Scope::Added,
            diff_context: 0,
            fail_on: FailOn::Error,
            max_findings: 100,
            path_filters: vec![],
            only_tags: vec![],
            enable_tags: vec![],
            disable_tags: vec![],
            directory_overrides: vec![],
        }
    }

    fn test_context() -> SensorReportContext {
        let mut capabilities = HashMap::new();
        capabilities.insert(
            CAP_GIT.to_string(),
            CapabilityStatus {
                status: CAP_STATUS_AVAILABLE.to_string(),
                reason: None,
                detail: None,
            },
        );
        SensorReportContext {
            started_at: "2024-01-15T10:30:00Z".to_string(),
            ended_at: "2024-01-15T10:30:01Z".to_string(),
            duration_ms: 1000,
            capabilities,
            artifacts: vec![],
            rule_metadata: HashMap::new(),
            truncated_count: 0,
            rules_total: 0,
        }
    }

    fn make_diff_with_finding() -> String {
        "--- a/test.rs\n+++ b/test.rs\n@@ -0,0 +1 @@\n+let x = test_pattern();\n".to_string()
    }

    #[test]
    fn run_sensor_returns_sensor_report() {
        let settings = Settings {
            config: test_config(),
            plan: test_plan(),
            diff_text: make_diff_with_finding(),
            context: test_context(),
        };

        let report = run_sensor(&settings, None).unwrap();
        assert_eq!(report.schema, SENSOR_REPORT_SCHEMA_V1);
        assert_eq!(report.tool.name, "diffguard");
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn run_sensor_with_no_substrate() {
        let settings = Settings {
            config: test_config(),
            plan: test_plan(),
            diff_text: String::new(),
            context: test_context(),
        };

        let report = run_sensor(&settings, None).unwrap();
        assert_eq!(report.schema, SENSOR_REPORT_SCHEMA_V1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn run_sensor_populates_rule_metadata() {
        let settings = Settings {
            config: test_config(),
            plan: test_plan(),
            diff_text: make_diff_with_finding(),
            context: test_context(),
        };

        let report = run_sensor(&settings, None).unwrap();
        let finding = &report.findings[0];
        assert_eq!(finding.help.as_deref(), Some("Fix the test pattern"));
        assert_eq!(finding.url.as_deref(), Some("https://example.com/help"));
    }

    #[test]
    fn substrate_defaults_return_none() {
        struct Dummy;
        impl Substrate for Dummy {}

        let dummy = Dummy;
        assert!(dummy.changed_files().is_none());
        assert!(dummy.repo_root().is_none());
        assert!(dummy.metadata().is_none());
    }

    #[test]
    fn run_sensor_preserves_timing_from_context() {
        let settings = Settings {
            config: test_config(),
            plan: test_plan(),
            diff_text: String::new(),
            context: test_context(),
        };

        let report = run_sensor(&settings, None).unwrap();
        assert_eq!(report.run.started_at, "2024-01-15T10:30:00Z");
        assert_eq!(report.run.ended_at, "2024-01-15T10:30:01Z");
        assert_eq!(report.run.duration_ms, 1000);
    }

    #[test]
    fn run_sensor_propagates_check_error() {
        let mut plan = test_plan();
        plan.fail_on = FailOn::Error;

        let settings = Settings {
            config: ConfigFile {
                includes: vec![],
                defaults: diffguard_types::Defaults::default(),
                rule: vec![RuleConfig {
                    id: "bad.rule".to_string(),
                    severity: Severity::Error,
                    message: "Bad pattern".to_string(),
                    languages: vec![],
                    // Invalid regex pattern
                    patterns: vec!["[invalid".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: None,
                    url: None,
                    tags: vec![],
                    test_cases: vec![],
                }],
            },
            plan,
            diff_text: make_diff_with_finding(),
            context: test_context(),
        };

        let result = run_sensor(&settings, None);
        assert!(result.is_err());
    }

    #[test]
    fn extract_rule_metadata_maps_config_rules() {
        let config = test_config();
        let meta = extract_rule_metadata(&config);
        assert!(meta.contains_key("test.rule"));
        let entry = &meta["test.rule"];
        assert_eq!(entry.help.as_deref(), Some("Fix the test pattern"));
        assert_eq!(entry.url.as_deref(), Some("https://example.com/help"));
    }
}
