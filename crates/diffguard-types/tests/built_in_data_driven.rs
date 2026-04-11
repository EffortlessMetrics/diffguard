// Red tests for data-driven ConfigFile::built_in() via JSON + include_str!
//
// These tests define the TARGET behavior: ConfigFile::built_in() should load
// its rules from a JSON file embedded via include_str!, NOT from hardcoded
// Rust struct literals.
//
// Current (broken) implementation: hardcoded vec![RuleConfig { ... }, ...]
// Target (fixed) implementation:  serde_json::from_str(include_str!("built_in_rules.json"))
//
// When the refactoring is complete, all these tests should pass.

use diffguard_types::{ConfigFile, RuleConfig, Severity};
use std::collections::HashSet;

#[test]
fn built_in_has_exactly_36_rules() {
    // The built-in config should contain exactly 36 rules
    let cfg = ConfigFile::built_in();
    assert_eq!(
        cfg.rule.len(),
        36,
        "built_in() should return exactly 36 rules, got {}",
        cfg.rule.len()
    );
}

#[test]
fn built_in_all_rule_ids_are_unique() {
    // All rule IDs in built_in() must be unique (no duplicates)
    let cfg = ConfigFile::built_in();
    let ids: HashSet<&str> = cfg.rule.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids.len(),
        cfg.rule.len(),
        "built-in rule IDs should be unique, but found {} duplicates",
        cfg.rule.len() - ids.len()
    );
}

#[test]
fn built_in_contains_expected_rules() {
    // These specific rules must be present in the built-in config
    let cfg = ConfigFile::built_in();
    let ids: HashSet<&str> = cfg.rule.iter().map(|r| r.id.as_str()).collect();

    let expected_rules = [
        "rust.no_unwrap",
        "rust.no_dbg",
        "rust.no_todo",
        "python.no_print",
        "python.no_pdb",
        "python.no_breakpoint",
        "js.no_console",
        "js.no_debugger",
        "ruby.no_binding_pry",
        "security.hardcoded_ipv4",
        "security.http_url",
        "security.sql_concat",
        "secrets.aws_access_key",
        "secrets.github_token",
    ];

    for expected in expected_rules {
        assert!(
            ids.contains(expected),
            "expected built-in rule '{}' not found",
            expected
        );
    }
}

#[test]
fn built_in_rules_have_valid_severity() {
    // Every rule in built_in() must have a valid Severity (Info, Warn, or Error)
    let cfg = ConfigFile::built_in();
    for rule in &cfg.rule {
        assert!(
            matches!(rule.severity, Severity::Info | Severity::Warn | Severity::Error),
            "rule '{}' has invalid severity: {:?}",
            rule.id,
            rule.severity
        );
    }
}

#[test]
fn built_in_rules_have_non_empty_id() {
    // Every rule must have a non-empty ID
    let cfg = ConfigFile::built_in();
    for rule in &cfg.rule {
        assert!(
            !rule.id.is_empty(),
            "found rule with empty id: {:?}",
            rule
        );
    }
}

#[test]
fn built_in_rules_have_at_least_one_pattern() {
    // Every rule must have at least one pattern defined
    let cfg = ConfigFile::built_in();
    for rule in &cfg.rule {
        assert!(
            !rule.patterns.is_empty(),
            "rule '{}' has no patterns defined",
            rule.id
        );
    }
}

#[test]
fn built_in_rules_are_valid_rule_config_objects() {
    // Rules must be valid RuleConfig objects that can be serialized and deserialized
    let cfg = ConfigFile::built_in();
    for rule in &cfg.rule {
        // Should serialize without error
        let json = serde_json::to_string(rule)
            .unwrap_or_else(|e| panic!("rule '{}' failed to serialize: {}", rule.id, e));

        // Should deserialize back to equivalent RuleConfig
        let deserialized: RuleConfig = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("rule '{}' failed to deserialize: {}", rule.id, e));

        assert_eq!(
            deserialized.id, rule.id,
            "rule '{}' deserialized to different id",
            rule.id
        );
        assert_eq!(
            deserialized.severity, rule.severity,
            "rule '{}' deserialized to different severity",
            rule.id
        );
    }
}

#[test]
fn built_in_config_serializes_to_valid_json() {
    // The entire ConfigFile should serialize to valid JSON
    let cfg = ConfigFile::built_in();
    let json = serde_json::to_string_pretty(&cfg)
        .expect("ConfigFile::built_in() should serialize to valid JSON");

    // Should be able to deserialize it back
    let deserialized: ConfigFile = serde_json::from_str(&json)
        .expect("ConfigFile JSON should be valid and deserializable");

    assert_eq!(
        deserialized.rule.len(),
        cfg.rule.len(),
        "deserialized config should have same number of rules"
    );
}

#[test]
fn built_in_defaults_are_default() {
    // The defaults field should be Defaults::default()
    let cfg = ConfigFile::built_in();
    assert_eq!(
        cfg.defaults,
        diffguard_types::Defaults::default(),
        "built_in() defaults should be Defaults::default()"
    );
}

#[test]
fn built_in_includes_are_empty() {
    // The includes field should be empty
    let cfg = ConfigFile::built_in();
    assert!(
        cfg.includes.is_empty(),
        "built_in() includes should be empty, got {:?}",
        cfg.includes
    );
}

#[test]
fn built_in_rules_have_valid_regex_patterns() {
    // All patterns should be valid regex patterns (can be compiled)
    let cfg = ConfigFile::built_in();
    for rule in &cfg.rule {
        for pattern in &rule.patterns {
            regex::Regex::new(pattern)
                .unwrap_or_else(|e| panic!("rule '{}' has invalid regex '{}': {}", rule.id, pattern, e));
        }
        for pattern in &rule.context_patterns {
            regex::Regex::new(pattern)
                .unwrap_or_else(|e| panic!("rule '{}' has invalid context regex '{}': {}", rule.id, pattern, e));
        }
        for pattern in &rule.escalate_patterns {
            regex::Regex::new(pattern)
                .unwrap_or_else(|e| panic!("rule '{}' has invalid escalate regex '{}': {}", rule.id, pattern, e));
        }
    }
}
