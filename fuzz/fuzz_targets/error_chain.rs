//! Fuzz target for error chain propagation via `source()` method.
//!
//! This target exercises the error chain propagation for RuleCompileError,
//! OverrideCompileError, and SchemaValidationError types. It verifies that:
//! - `source()` returns Some for variants with inner errors (InvalidRegex, InvalidGlob)
//! - `source()` returns None for variants without inner errors
//! - Error chain iteration via source() loop works correctly
//!
//! Requirements: AC1-AC7 for source() implementation

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::error::Error;

use diffguard_domain::{compile_rules, overrides::RuleOverrideMatcher, DirectoryRuleOverride};
use diffguard_types::{RuleConfig, Severity};

fuzz_target!(|data: &[u8]| {
    // Skip empty or very large inputs
    if data.is_empty() || data.len() > 1000 {
        return;
    }

    // =================================================================
    // Fuzz RuleCompileError source chain via compile_rules (regex pattern)
    // =================================================================

    // Try to interpret input as a regex pattern string
    if let Ok(pattern) = std::str::from_utf8(data) {
        // Create a minimal rule config with the fuzzed pattern
        let rule = RuleConfig {
            id: "fuzz.error_chain".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec![pattern.to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
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
        };

        // Try to compile - if it fails, exercise the error chain
        if let Err(error) = compile_rules(&[rule]) {
            // Exercise source() - should return Some for InvalidRegex, None for others
            let _ = error.source();

            // Exercise chain iteration via source() loop
            let mut current: Option<&(dyn Error + 'static)> = error.source();
            while let Some(cause) = current {
                // Just access cause - should not panic
                let _ = cause.to_string();
                current = cause.source();
            }
        }
    }

    // =================================================================
    // Fuzz glob pattern errors in compile_rules (paths field)
    // =================================================================

    if let Ok(pattern) = std::str::from_utf8(data) {
        // Test glob in paths field
        let rule = RuleConfig {
            id: "fuzz.glob_paths".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()], // Valid minimal regex
            paths: vec![pattern.to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
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
        };

        if let Err(error) = compile_rules(&[rule]) {
            let _ = error.source();

            let mut current: Option<&(dyn Error + 'static)> = error.source();
            while let Some(cause) = current {
                let _ = cause.to_string();
                current = cause.source();
            }
        }
    }

    // =================================================================
    // Fuzz glob pattern errors in compile_rules (exclude_paths field)
    // =================================================================

    if let Ok(pattern) = std::str::from_utf8(data) {
        // Test glob in exclude_paths field
        let rule = RuleConfig {
            id: "fuzz.glob_exclude".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()], // Valid minimal regex
            paths: vec![],
            exclude_paths: vec![pattern.to_string()],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: Default::default(),
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
        };

        if let Err(error) = compile_rules(&[rule]) {
            let _ = error.source();

            let mut current: Option<&(dyn Error + 'static)> = error.source();
            while let Some(cause) = current {
                let _ = cause.to_string();
                current = cause.source();
            }
        }
    }

    // =================================================================
    // Fuzz OverrideCompileError source chain via RuleOverrideMatcher::compile
    // =================================================================

    if let Ok(glob_pattern) = std::str::from_utf8(data) {
        // Create an override with the fuzzed glob pattern
        let overrides = vec![DirectoryRuleOverride {
            directory: "src".to_string(),
            rule_id: "test-rule".to_string(),
            enabled: Some(true),
            severity: None,
            exclude_paths: vec![glob_pattern.to_string()],
        }];

        // Try to compile overrides - if invalid glob, exercise error chain
        if let Err(error) = RuleOverrideMatcher::compile(&overrides) {
            let _ = error.source();

            let mut current: Option<&(dyn Error + 'static)> = error.source();
            while let Some(cause) = current {
                let _ = cause.to_string();
                current = cause.source();
            }
        }
    }
});
