//! Fuzz target for glob pattern compilation.
//!
//! This target exercises glob pattern compilation to discover edge cases
//! that might cause panics or excessive resource usage.
//!
//! Requirements: 8.1-8.4

#![no_main]

use libfuzzer_sys::fuzz_target;

use diffguard_domain::compile_rules;
use diffguard_types::{RuleConfig, Severity};

fuzz_target!(|data: &[u8]| {
    // Try to interpret input as a glob pattern string
    if let Ok(pattern) = std::str::from_utf8(data) {
        // Skip excessively long patterns to avoid timeout
        if pattern.len() > 500 {
            return;
        }

        // Create a minimal rule config with the fuzzed glob in paths
        let rule_with_include = RuleConfig {
            id: "fuzz.glob.include".to_string(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()], // Valid minimal regex
            paths: vec![pattern.to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        // Try to compile the rule with include glob - should return error for invalid glob, never panic
        let _ = compile_rules(&[rule_with_include]);

        // Also test as exclude_paths glob
        let rule_with_exclude = RuleConfig {
            id: "fuzz.glob.exclude".to_string(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()], // Valid minimal regex
            paths: vec![],
            exclude_paths: vec![pattern.to_string()],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        // Try to compile the rule with exclude glob - should return error for invalid glob, never panic
        let _ = compile_rules(&[rule_with_exclude]);
    }
});
