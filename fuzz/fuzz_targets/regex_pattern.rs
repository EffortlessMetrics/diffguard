//! Fuzz target for regex pattern compilation.
//!
//! This target exercises regex pattern compilation to discover edge cases
//! that might cause panics or excessive resource usage.
//!
//! Requirements: 8.1-8.4

#![no_main]

use libfuzzer_sys::fuzz_target;

use diffguard_domain::compile_rules;
use diffguard_types::{RuleConfig, Severity};

fuzz_target!(|data: &[u8]| {
    // Try to interpret input as a regex pattern string
    if let Ok(pattern) = std::str::from_utf8(data) {
        // Skip excessively long patterns to avoid timeout
        if pattern.len() > 1000 {
            return;
        }

        // Create a minimal rule config with the fuzzed pattern
        let rule = RuleConfig {
            id: "fuzz.regex".to_string(),
            severity: Severity::Warn,
            message: "fuzz test".to_string(),
            languages: vec![],
            patterns: vec![pattern.to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        // Try to compile the rule - should return error for invalid regex, never panic
        let _ = compile_rules(&[rule]);
    }
});
