//! Proptest strategies for generating valid test inputs.
//!
//! This module provides constructive strategies that generate valid inputs
//! without relying on filtering. All patterns and globs are guaranteed to
//! be syntactically valid.
//!
//! # Bounds
//!
//! To keep tests fast, the following bounds are enforced:
//! - Max files per diff: 5
//! - Max hunks per file: 5
//! - Max lines per hunk: 20
//! - Max line length: 200 bytes
//! - Max patterns per rule: 5
//! - Max paths per rule: 5

use diffguard_types::{
    ConfigFile, Defaults, FailOn, Finding, RuleConfig, Scope, Severity, VerdictCounts,
    VerdictStatus,
};
use proptest::prelude::*;

// =============================================================================
// Constants for bounding generated data
// =============================================================================

/// Maximum number of files in a generated diff
pub const MAX_FILES: usize = 5;

/// Maximum number of hunks per file
pub const MAX_HUNKS_PER_FILE: usize = 5;

/// Maximum number of lines per hunk
pub const MAX_LINES_PER_HUNK: usize = 20;

/// Maximum line length in bytes
pub const MAX_LINE_LENGTH: usize = 200;

/// Maximum number of patterns per rule
pub const MAX_PATTERNS_PER_RULE: usize = 5;

/// Maximum number of path globs per rule
pub const MAX_PATHS_PER_RULE: usize = 5;

// =============================================================================
// Enum Strategies
// =============================================================================

/// Strategy for generating Severity values.
pub fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating Scope values.
pub fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Added),
        Just(Scope::Changed),
        Just(Scope::Modified),
        Just(Scope::Deleted),
    ]
}

/// Strategy for generating FailOn values.
pub fn arb_fail_on() -> impl Strategy<Value = FailOn> {
    prop_oneof![Just(FailOn::Error), Just(FailOn::Warn), Just(FailOn::Never),]
}

/// Strategy for generating VerdictStatus values.
pub fn arb_verdict_status() -> impl Strategy<Value = VerdictStatus> {
    prop_oneof![
        Just(VerdictStatus::Pass),
        Just(VerdictStatus::Warn),
        Just(VerdictStatus::Fail),
    ]
}

// =============================================================================
// Constructive Regex Pattern Strategies
// =============================================================================

/// Strategy for generating valid regex patterns constructively.
///
/// Instead of filtering random strings, this builds regexes from known-valid
/// components. The patterns cover common use cases:
/// - Literal word matches (e.g., "unwrap", "console")
/// - Word boundary patterns (e.g., r"\bprint\b")
/// - Method call patterns (e.g., r"\.unwrap\(")
/// - Simple character classes (e.g., "[a-z]+")
pub fn arb_regex_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        // Literal word (alphanumeric, safe characters)
        arb_identifier().prop_map(|s| s),
        // Word with word boundary
        arb_identifier().prop_map(|s| format!(r"\b{}\b", s)),
        // Method call pattern: .method(
        arb_identifier().prop_map(|s| format!(r"\.{}\(", s)),
        // Simple character class patterns
        Just("[a-z]+".to_string()),
        Just("[A-Z][a-z]+".to_string()),
        Just("[0-9]+".to_string()),
        Just("[a-zA-Z_][a-zA-Z0-9_]*".to_string()),
        // Common debug patterns
        Just(r"\bdbg!\(".to_string()),
        Just(r"\bprintln!\(".to_string()),
        Just(r"\bconsole\.(log|debug|info)\s*\(".to_string()),
        Just(r"\bprint\s*\(".to_string()),
        Just(r"\bfmt\.(Print|Println|Printf)\s*\(".to_string()),
        // Common error patterns
        Just(r"\.unwrap\(".to_string()),
        Just(r"\.expect\(".to_string()),
        Just(r"\bpanic!\(".to_string()),
        Just(r"\btodo!\(".to_string()),
        Just(r"\bunimplemented!\(".to_string()),
        // Quantifiers with simple patterns
        arb_identifier().prop_map(|s| format!("{}+", s)),
        arb_identifier().prop_map(|s| format!("{}*", s)),
        arb_identifier().prop_map(|s| format!("{}?", s)),
        // Alternation
        (arb_identifier(), arb_identifier()).prop_map(|(a, b)| format!("({}|{})", a, b)),
    ]
}

/// Strategy for generating valid, simple regex patterns (no special chars).
pub fn arb_simple_regex() -> impl Strategy<Value = String> {
    arb_identifier()
}

// =============================================================================
// Constructive Glob Pattern Strategies
// =============================================================================

/// Strategy for generating valid glob patterns constructively.
///
/// Builds globs from known-valid components:
/// - File extension matches (e.g., "*.rs", "*.py")
/// - Directory patterns (e.g., "src/**/*.rs")
/// - Specific file patterns (e.g., "**/Cargo.toml")
pub fn arb_glob_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple extension match: *.ext
        arb_file_extension().prop_map(|ext| format!("*.{}", ext)),
        // Recursive extension match: **/*.ext
        arb_file_extension().prop_map(|ext| format!("**/*.{}", ext)),
        // Directory with recursive extension: dir/**/*.ext
        (arb_dir_name(), arb_file_extension())
            .prop_map(|(dir, ext)| format!("{}/**/*.{}", dir, ext)),
        // Nested directory pattern
        (arb_dir_name(), arb_dir_name(), arb_file_extension())
            .prop_map(|(d1, d2, ext)| format!("{}/**/{}/**/*.{}", d1, d2, ext)),
        // Common exclude patterns
        Just("**/tests/**".to_string()),
        Just("**/test/**".to_string()),
        Just("**/*.test.*".to_string()),
        Just("**/*.spec.*".to_string()),
        Just("**/node_modules/**".to_string()),
        Just("**/target/**".to_string()),
        Just("**/vendor/**".to_string()),
        Just("**/benches/**".to_string()),
        Just("**/examples/**".to_string()),
        // Specific file patterns
        Just("**/Cargo.toml".to_string()),
        Just("**/package.json".to_string()),
        Just("**/go.mod".to_string()),
    ]
}

/// Strategy for generating include path globs (typically more permissive).
pub fn arb_include_glob() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_file_extension().prop_map(|ext| format!("**/*.{}", ext)),
        (arb_dir_name(), arb_file_extension())
            .prop_map(|(dir, ext)| format!("{}/**/*.{}", dir, ext)),
    ]
}

/// Strategy for generating exclude path globs.
pub fn arb_exclude_glob() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("**/tests/**".to_string()),
        Just("**/test/**".to_string()),
        Just("**/*.test.*".to_string()),
        Just("**/*.spec.*".to_string()),
        Just("**/node_modules/**".to_string()),
        Just("**/target/**".to_string()),
        Just("**/vendor/**".to_string()),
        Just("**/benches/**".to_string()),
        Just("**/examples/**".to_string()),
        (arb_dir_name()).prop_map(|d| format!("**/{}/**", d)),
    ]
}

// =============================================================================
// Helper Strategies
// =============================================================================

/// Strategy for generating valid identifiers (for pattern components).
fn arb_identifier() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{0,15}")
        .expect("valid regex for identifier")
        .prop_filter("identifier must not be empty", |s| !s.is_empty())
}

/// Strategy for generating file extensions.
fn arb_file_extension() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "kt", "rb", "c", "cpp", "h", "hpp",
        "cs", "txt", "md", "json", "yaml", "toml",
    ])
    .prop_map(|s| s.to_string())
}

/// Strategy for generating directory names.
fn arb_dir_name() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "src", "lib", "bin", "tests", "test", "examples", "benches", "docs", "scripts", "utils",
        "core", "api", "internal", "pkg", "cmd", "app",
    ])
    .prop_map(|s| s.to_string())
}

/// Strategy for generating non-empty strings suitable for IDs and messages.
pub fn arb_non_empty_string() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_.\\-]{0,49}")
        .expect("valid regex for non-empty string")
        .prop_filter("string must not be empty", |s| !s.is_empty())
}

/// Strategy for generating optional strings.
pub fn arb_optional_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), arb_non_empty_string().prop_map(Some),]
}

/// Strategy for generating language identifiers.
pub fn arb_language() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "rust",
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "kotlin",
        "ruby",
        "c",
        "cpp",
        "csharp",
    ])
    .prop_map(|s| s.to_string())
}

// =============================================================================
// RuleConfig Strategy
// =============================================================================

/// Strategy for generating valid RuleConfig instances.
///
/// All generated configs have:
/// - Non-empty ID
/// - At least one valid regex pattern
/// - Valid glob patterns for paths
pub fn arb_rule_config() -> impl Strategy<Value = RuleConfig> {
    (
        arb_non_empty_string(),                                               // id
        arb_severity(),                                                       // severity
        arb_non_empty_string(),                                               // message
        prop::collection::vec(arb_language(), 0..3),                          // languages
        prop::collection::vec(arb_regex_pattern(), 1..MAX_PATTERNS_PER_RULE), // patterns
        prop::collection::vec(arb_include_glob(), 0..MAX_PATHS_PER_RULE),     // paths
        prop::collection::vec(arb_exclude_glob(), 0..MAX_PATHS_PER_RULE),     // exclude_paths
        any::<bool>(),                                                        // ignore_comments
        any::<bool>(),                                                        // ignore_strings
        prop::collection::vec(arb_non_empty_string(), 0..3),                  // tags
    )
        .prop_map(
            |(
                id,
                severity,
                message,
                languages,
                patterns,
                paths,
                exclude_paths,
                ignore_comments,
                ignore_strings,
                tags,
            )| {
                RuleConfig {
                    id,
                    severity,
                    message,
                    languages,
                    patterns,
                    paths,
                    exclude_paths,
                    ignore_comments,
                    ignore_strings,
                    help: None,
                    url: None,
                    tags,
                    test_cases: vec![],
                }
            },
        )
}

/// Strategy for generating a minimal valid RuleConfig.
pub fn arb_minimal_rule_config() -> impl Strategy<Value = RuleConfig> {
    (arb_non_empty_string(), arb_severity(), arb_simple_regex()).prop_map(
        |(id, severity, pattern)| RuleConfig {
            id,
            severity,
            message: "Test rule".to_string(),
            languages: vec![],
            patterns: vec![pattern],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        },
    )
}

// =============================================================================
// ConfigFile Strategy
// =============================================================================

/// Strategy for generating valid Defaults.
pub fn arb_defaults() -> impl Strategy<Value = Defaults> {
    (
        arb_optional_string(),
        arb_optional_string(),
        prop::option::of(arb_scope()),
        prop::option::of(arb_fail_on()),
        prop::option::of(0u32..1000),
        prop::option::of(0u32..10),
    )
        .prop_map(
            |(base, head, scope, fail_on, max_findings, diff_context)| Defaults {
                base,
                head,
                scope,
                fail_on,
                max_findings,
                diff_context,
            },
        )
}

/// Strategy for generating valid ConfigFile instances.
pub fn arb_config_file() -> impl Strategy<Value = ConfigFile> {
    (
        arb_defaults(),
        prop::collection::vec(arb_rule_config(), 0..MAX_FILES),
    )
        .prop_map(|(defaults, rule)| ConfigFile {
            includes: vec![],
            defaults,
            rule,
        })
}

// =============================================================================
// Finding Strategy
// =============================================================================

/// Strategy for generating valid Finding instances.
pub fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_non_empty_string(),      // rule_id
        arb_severity(),              // severity
        arb_non_empty_string(),      // message
        arb_file_path(),             // path
        1u32..10000,                 // line
        prop::option::of(1u32..500), // column
        arb_non_empty_string(),      // match_text
        arb_line_content(),          // snippet
    )
        .prop_map(
            |(rule_id, severity, message, path, line, column, match_text, snippet)| Finding {
                rule_id,
                severity,
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating VerdictCounts.
pub fn arb_verdict_counts() -> impl Strategy<Value = VerdictCounts> {
    (0u32..100, 0u32..100, 0u32..100, 0u32..50).prop_map(|(info, warn, error, suppressed)| {
        VerdictCounts {
            info,
            warn,
            error,
            suppressed,
        }
    })
}

// =============================================================================
// Diff Content Strategies
// =============================================================================

/// Strategy for generating valid file paths.
pub fn arb_file_path() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(arb_dir_name(), 1..4),
        arb_identifier(),
        arb_file_extension(),
    )
        .prop_map(|(dirs, name, ext)| format!("{}/{}.{}", dirs.join("/"), name, ext))
}

/// Strategy for generating line content (no diff markers at start).
pub fn arb_line_content() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_(){}\\[\\];:,.<>=+\\-*/& ]{1,200}")
        .expect("valid regex for line content")
        .prop_filter("must not start with diff markers", |s| {
            !s.starts_with('+')
                && !s.starts_with('-')
                && !s.starts_with('@')
                && !s.starts_with(' ')
                && !s.starts_with('\\')
        })
}

/// Strategy for generating line content that is safe for diffs.
pub fn arb_safe_line_content() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_(){}\\[\\];:,.<>=*/& ]{0,199}")
        .expect("valid regex for safe line content")
}

/// Strategy for generating a vector of line contents.
pub fn arb_lines(max_lines: usize) -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_safe_line_content(), 1..=max_lines)
        .prop_filter("must have at least one non-empty line", |lines| {
            lines.iter().any(|l| !l.is_empty())
        })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[test]
    fn arb_regex_pattern_produces_valid_regex() {
        let mut runner = TestRunner::default();
        let strategy = arb_regex_pattern();

        for _ in 0..100 {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            assert!(
                regex::Regex::new(&value).is_ok(),
                "Generated pattern '{}' should be valid regex",
                value
            );
        }
    }

    #[test]
    fn arb_glob_pattern_produces_valid_glob() {
        let mut runner = TestRunner::default();
        let strategy = arb_glob_pattern();

        for _ in 0..100 {
            let value = strategy.new_tree(&mut runner).unwrap().current();
            assert!(
                globset::Glob::new(&value).is_ok(),
                "Generated pattern '{}' should be valid glob",
                value
            );
        }
    }

    #[test]
    fn arb_rule_config_produces_valid_config() {
        let mut runner = TestRunner::default();
        let strategy = arb_rule_config();

        for _ in 0..20 {
            let config = strategy.new_tree(&mut runner).unwrap().current();
            assert!(!config.id.is_empty(), "ID should not be empty");
            assert!(!config.patterns.is_empty(), "Patterns should not be empty");

            // Verify all patterns are valid regexes
            for pattern in &config.patterns {
                assert!(
                    regex::Regex::new(pattern).is_ok(),
                    "Pattern '{}' should be valid regex",
                    pattern
                );
            }

            // Verify all paths are valid globs
            for path in &config.paths {
                assert!(
                    globset::Glob::new(path).is_ok(),
                    "Path '{}' should be valid glob",
                    path
                );
            }

            for path in &config.exclude_paths {
                assert!(
                    globset::Glob::new(path).is_ok(),
                    "Exclude path '{}' should be valid glob",
                    path
                );
            }
        }
    }

    #[test]
    fn arb_file_path_produces_valid_paths() {
        let mut runner = TestRunner::default();
        let strategy = arb_file_path();

        for _ in 0..50 {
            let path = strategy.new_tree(&mut runner).unwrap().current();
            assert!(!path.is_empty(), "Path should not be empty");
            assert!(
                path.contains('/'),
                "Path should contain directory separator"
            );
            assert!(
                path.contains('.'),
                "Path should contain extension separator"
            );
        }
    }

    proptest! {
        #[test]
        fn severity_roundtrip(sev in arb_severity()) {
            let json = serde_json::to_string(&sev).unwrap();
            let parsed: Severity = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(sev, parsed);
        }

        #[test]
        fn scope_roundtrip(scope in arb_scope()) {
            let json = serde_json::to_string(&scope).unwrap();
            let parsed: Scope = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(scope, parsed);
        }

        #[test]
        fn fail_on_roundtrip(fail_on in arb_fail_on()) {
            let json = serde_json::to_string(&fail_on).unwrap();
            let parsed: FailOn = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(fail_on, parsed);
        }
    }

    #[test]
    fn arb_strategies_smoke() {
        let mut runner = TestRunner::default();

        let _ = arb_verdict_status()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _ = arb_simple_regex().new_tree(&mut runner).unwrap().current();
        let _ = arb_optional_string()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _ = arb_minimal_rule_config()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _ = arb_defaults().new_tree(&mut runner).unwrap().current();
        let _ = arb_config_file().new_tree(&mut runner).unwrap().current();
        let _ = arb_finding().new_tree(&mut runner).unwrap().current();
        let _ = arb_verdict_counts()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _ = arb_line_content().new_tree(&mut runner).unwrap().current();
        let _ = arb_safe_line_content()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let _ = arb_lines(3).new_tree(&mut runner).unwrap().current();
        let _ = arb_language().new_tree(&mut runner).unwrap().current();
        let _ = arb_include_glob().new_tree(&mut runner).unwrap().current();
        let _ = arb_exclude_glob().new_tree(&mut runner).unwrap().current();
    }
}
