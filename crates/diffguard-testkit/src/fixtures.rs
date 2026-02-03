//! Common test fixtures for diffguard.
//!
//! This module provides sample configs, diffs, and expected outputs
//! for use in tests across the workspace.

use diffguard_types::{
    CheckReceipt, ConfigFile, Defaults, DiffMeta, FailOn, Finding, RuleConfig, Scope, Severity,
    ToolMeta, Verdict, VerdictCounts, VerdictStatus, CHECK_SCHEMA_V1,
};

// =============================================================================
// Sample Configs
// =============================================================================

/// Collection of sample configuration files for testing.
pub mod sample_configs {
    use super::*;

    /// An empty configuration with default values.
    pub fn empty() -> ConfigFile {
        ConfigFile {
            defaults: Defaults::default(),
            rule: vec![],
        }
    }

    /// The built-in configuration from diffguard-types.
    pub fn built_in() -> ConfigFile {
        ConfigFile::built_in()
    }

    /// A minimal configuration with one rule.
    pub fn minimal() -> ConfigFile {
        ConfigFile {
            defaults: Defaults::default(),
            rule: vec![RuleConfig {
                id: "test.rule".to_string(),
                severity: Severity::Warn,
                message: "Test rule matched".to_string(),
                languages: vec![],
                patterns: vec!["test".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                help: None,
                url: None,
            }],
        }
    }

    /// A Rust-focused configuration.
    pub fn rust_focused() -> ConfigFile {
        ConfigFile {
            defaults: Defaults {
                base: Some("origin/main".to_string()),
                head: Some("HEAD".to_string()),
                scope: Some(Scope::Added),
                fail_on: Some(FailOn::Error),
                max_findings: Some(100),
                diff_context: Some(0),
            },
            rule: vec![
                RuleConfig {
                    id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap in production code".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec![r"\.unwrap\(".to_string(), r"\.expect\(".to_string()],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec!["**/tests/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
                RuleConfig {
                    id: "rust.no_dbg".to_string(),
                    severity: Severity::Warn,
                    message: "Remove debug macros before merging".to_string(),
                    languages: vec!["rust".to_string()],
                    patterns: vec![r"\bdbg!\(".to_string(), r"\bprintln!\(".to_string()],
                    paths: vec!["**/*.rs".to_string()],
                    exclude_paths: vec!["**/tests/**".to_string(), "**/examples/**".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
            ],
        }
    }

    /// A JavaScript/TypeScript-focused configuration.
    pub fn javascript_focused() -> ConfigFile {
        ConfigFile {
            defaults: Defaults::default(),
            rule: vec![
                RuleConfig {
                    id: "js.no_console".to_string(),
                    severity: Severity::Warn,
                    message: "Remove console.log before merging".to_string(),
                    languages: vec!["javascript".to_string(), "typescript".to_string()],
                    patterns: vec![r"\bconsole\.(log|debug|info)\s*\(".to_string()],
                    paths: vec![
                        "**/*.js".to_string(),
                        "**/*.ts".to_string(),
                        "**/*.jsx".to_string(),
                        "**/*.tsx".to_string(),
                    ],
                    exclude_paths: vec![
                        "**/tests/**".to_string(),
                        "**/*.test.*".to_string(),
                        "**/*.spec.*".to_string(),
                    ],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
                RuleConfig {
                    id: "js.no_debugger".to_string(),
                    severity: Severity::Error,
                    message: "Remove debugger statements".to_string(),
                    languages: vec!["javascript".to_string(), "typescript".to_string()],
                    patterns: vec![r"\bdebugger\b".to_string()],
                    paths: vec!["**/*.js".to_string(), "**/*.ts".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
            ],
        }
    }

    /// A Python-focused configuration.
    pub fn python_focused() -> ConfigFile {
        ConfigFile {
            defaults: Defaults::default(),
            rule: vec![
                RuleConfig {
                    id: "python.no_print".to_string(),
                    severity: Severity::Warn,
                    message: "Remove print statements before merging".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![r"\bprint\s*\(".to_string()],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec!["**/tests/**".to_string(), "**/test_*.py".to_string()],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
                RuleConfig {
                    id: "python.no_pdb".to_string(),
                    severity: Severity::Error,
                    message: "Remove debugger statements".to_string(),
                    languages: vec!["python".to_string()],
                    patterns: vec![
                        r"\bimport\s+pdb\b".to_string(),
                        r"\bpdb\.set_trace\s*\(".to_string(),
                        r"\bbreakpoint\s*\(".to_string(),
                    ],
                    paths: vec!["**/*.py".to_string()],
                    exclude_paths: vec![],
                    ignore_comments: true,
                    ignore_strings: true,
                    help: None,
                    url: None,
                },
            ],
        }
    }

    /// A multi-language configuration.
    pub fn multi_language() -> ConfigFile {
        let mut rules = Vec::new();
        rules.extend(rust_focused().rule);
        rules.extend(javascript_focused().rule);
        rules.extend(python_focused().rule);

        ConfigFile {
            defaults: Defaults::default(),
            rule: rules,
        }
    }

    /// A configuration with all severity levels.
    pub fn all_severities() -> ConfigFile {
        ConfigFile {
            defaults: Defaults::default(),
            rule: vec![
                RuleConfig {
                    id: "test.info".to_string(),
                    severity: Severity::Info,
                    message: "Info level finding".to_string(),
                    languages: vec![],
                    patterns: vec!["INFO_PATTERN".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: None,
                    url: None,
                },
                RuleConfig {
                    id: "test.warn".to_string(),
                    severity: Severity::Warn,
                    message: "Warning level finding".to_string(),
                    languages: vec![],
                    patterns: vec!["WARN_PATTERN".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: None,
                    url: None,
                },
                RuleConfig {
                    id: "test.error".to_string(),
                    severity: Severity::Error,
                    message: "Error level finding".to_string(),
                    languages: vec![],
                    patterns: vec!["ERROR_PATTERN".to_string()],
                    paths: vec![],
                    exclude_paths: vec![],
                    ignore_comments: false,
                    ignore_strings: false,
                    help: None,
                    url: None,
                },
            ],
        }
    }
}

// =============================================================================
// Sample Diffs
// =============================================================================

/// Collection of sample unified diffs for testing.
pub mod sample_diffs {
    /// A simple diff with one added line.
    pub fn simple_addition() -> &'static str {
        r#"diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn new_function() {}
"#
    }

    /// A diff with a changed line (removal + addition).
    pub fn simple_change() -> &'static str {
        r#"diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,1 @@
-fn old_function() {}
+fn new_function() {}
"#
    }

    /// A diff with multiple files.
    pub fn multiple_files() -> &'static str {
        r#"diff --git a/src/a.rs b/src/a.rs
index 0000000..1111111 100644
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn a_new() {}
diff --git a/src/b.rs b/src/b.rs
index 0000000..1111111 100644
--- a/src/b.rs
+++ b/src/b.rs
@@ -1,1 +1,2 @@
 fn b() {}
+fn b_new() {}
"#
    }

    /// A diff with multiple hunks in one file.
    pub fn multiple_hunks() -> &'static str {
        r#"diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,3 @@
 fn first() {}
+fn after_first() {}
 fn second() {}
@@ -10,2 +11,3 @@
 fn tenth() {}
+fn after_tenth() {}
 fn eleventh() {}
"#
    }

    /// A diff with a binary file (should be skipped).
    pub fn binary_file() -> &'static str {
        r#"diff --git a/image.png b/image.png
index 0000000..1111111 100644
Binary files a/image.png and b/image.png differ
diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn new_function() {}
"#
    }

    /// A diff with a deleted file (should be skipped).
    pub fn deleted_file() -> &'static str {
        r#"diff --git a/old.rs b/old.rs
deleted file mode 100644
index 1111111..0000000
--- a/old.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-fn old() {}
-fn deprecated() {}
diff --git a/new.rs b/new.rs
new file mode 100644
index 0000000..1111111 100644
--- /dev/null
+++ b/new.rs
@@ -0,0 +1,1 @@
+fn new() {}
"#
    }

    /// A diff with a renamed file.
    pub fn renamed_file() -> &'static str {
        r#"diff --git a/old/path.rs b/new/path.rs
similarity index 90%
rename from old/path.rs
rename to new/path.rs
index 0000000..1111111 100644
--- a/old/path.rs
+++ b/new/path.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn added_after_rename() {}
"#
    }

    /// A diff with a mode-only change (should be skipped).
    pub fn mode_change() -> &'static str {
        r#"diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
diff --git a/src/lib.rs b/src/lib.rs
index 0000000..1111111 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn existing() {}
+fn new_function() {}
"#
    }

    /// A diff with a submodule change (should be skipped).
    pub fn submodule_change() -> &'static str {
        r#"diff --git a/vendor/lib b/vendor/lib
index abc1234..def5678 160000
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit abc1234567890abcdef1234567890abcdef123456
+Subproject commit def5678901234567890abcdef1234567890abcdef
diff --git a/src/main.rs b/src/main.rs
index 0000000..1111111 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,1 +1,2 @@
 fn main() {}
+fn helper() {}
"#
    }

    /// A diff with a malformed hunk header (should recover).
    pub fn malformed_hunk() -> &'static str {
        r#"diff --git a/bad.rs b/bad.rs
index 0000000..1111111 100644
--- a/bad.rs
+++ b/bad.rs
@@ malformed hunk header
+this line should be skipped
diff --git a/good.rs b/good.rs
index 0000000..1111111 100644
--- a/good.rs
+++ b/good.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#
    }

    /// A diff with Unicode content.
    pub fn unicode_content() -> &'static str {
        r#"diff --git a/src/i18n.rs b/src/i18n.rs
index 0000000..1111111 100644
--- a/src/i18n.rs
+++ b/src/i18n.rs
@@ -1,1 +1,4 @@
 fn greet() {}
+let hello_jp = "こんにちは";
+let hello_cn = "你好";
+let hello_kr = "안녕하세요";
"#
    }

    /// A diff that should trigger unwrap detection.
    pub fn with_unwrap() -> &'static str {
        r#"diff --git a/src/main.rs b/src/main.rs
index 0000000..1111111 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,1 +1,2 @@
 fn main() {}
+let x = some_option.unwrap();
"#
    }

    /// A diff with unwrap in a comment (should be ignored with ignore_comments).
    pub fn with_unwrap_in_comment() -> &'static str {
        r#"diff --git a/src/main.rs b/src/main.rs
index 0000000..1111111 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,1 +1,2 @@
 fn main() {}
+// TODO: should we use .unwrap() here?
"#
    }

    /// A diff with console.log for JavaScript testing.
    pub fn javascript_console_log() -> &'static str {
        r#"diff --git a/src/app.js b/src/app.js
index 0000000..1111111 100644
--- a/src/app.js
+++ b/src/app.js
@@ -1,1 +1,2 @@
 function init() {}
+console.log("debug message");
"#
    }

    /// A diff with print statement for Python testing.
    pub fn python_print() -> &'static str {
        r#"diff --git a/src/main.py b/src/main.py
index 0000000..1111111 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1,1 +1,2 @@
 def main():
+    print("debug")
"#
    }

    /// An empty diff (no changes).
    pub fn empty() -> &'static str {
        ""
    }
}

// =============================================================================
// Sample Check Receipts
// =============================================================================

/// Collection of sample check receipts for testing.
pub mod sample_receipts {
    use super::*;

    /// A passing check receipt with no findings.
    pub fn pass() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 5,
                lines_scanned: 100,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
        }
    }

    /// A check receipt with warnings only.
    pub fn with_warnings() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 3,
                lines_scanned: 50,
            },
            findings: vec![Finding {
                rule_id: "rust.no_dbg".to_string(),
                severity: Severity::Warn,
                message: "Remove debug macros".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                column: Some(5),
                match_text: "dbg!(".to_string(),
                snippet: "    dbg!(value);".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec!["1 warning-level finding".to_string()],
            },
        }
    }

    /// A failing check receipt with errors.
    pub fn fail() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 2,
                lines_scanned: 25,
            },
            findings: vec![Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "Avoid unwrap in production".to_string(),
                path: "src/main.rs".to_string(),
                line: 42,
                column: Some(15),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = opt.unwrap();".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec!["1 error-level finding".to_string()],
            },
        }
    }

    /// A check receipt with mixed severities.
    pub fn mixed_severities() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 3,
                scope: Scope::Changed,
                files_scanned: 10,
                lines_scanned: 200,
            },
            findings: vec![
                Finding {
                    rule_id: "test.info".to_string(),
                    severity: Severity::Info,
                    message: "Info finding".to_string(),
                    path: "src/a.rs".to_string(),
                    line: 1,
                    column: None,
                    match_text: "info".to_string(),
                    snippet: "info".to_string(),
                },
                Finding {
                    rule_id: "test.warn".to_string(),
                    severity: Severity::Warn,
                    message: "Warn finding".to_string(),
                    path: "src/b.rs".to_string(),
                    line: 2,
                    column: None,
                    match_text: "warn".to_string(),
                    snippet: "warn".to_string(),
                },
                Finding {
                    rule_id: "test.error".to_string(),
                    severity: Severity::Error,
                    message: "Error finding".to_string(),
                    path: "src/c.rs".to_string(),
                    line: 3,
                    column: None,
                    match_text: "error".to_string(),
                    snippet: "error".to_string(),
                },
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 1,
                    warn: 1,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec![
                    "1 error-level finding".to_string(),
                    "1 warning-level finding".to_string(),
                ],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{validate_check_receipt, validate_config_file};

    #[test]
    fn all_sample_configs_are_valid() {
        assert!(validate_config_file(&sample_configs::empty()).is_ok());
        assert!(validate_config_file(&sample_configs::built_in()).is_ok());
        assert!(validate_config_file(&sample_configs::minimal()).is_ok());
        assert!(validate_config_file(&sample_configs::rust_focused()).is_ok());
        assert!(validate_config_file(&sample_configs::javascript_focused()).is_ok());
        assert!(validate_config_file(&sample_configs::python_focused()).is_ok());
        assert!(validate_config_file(&sample_configs::multi_language()).is_ok());
        assert!(validate_config_file(&sample_configs::all_severities()).is_ok());
    }

    #[test]
    fn all_sample_receipts_are_valid() {
        assert!(validate_check_receipt(&sample_receipts::pass()).is_ok());
        assert!(validate_check_receipt(&sample_receipts::with_warnings()).is_ok());
        assert!(validate_check_receipt(&sample_receipts::fail()).is_ok());
        assert!(validate_check_receipt(&sample_receipts::mixed_severities()).is_ok());
    }

    #[test]
    fn sample_diffs_are_not_empty() {
        // Most diffs should have content
        assert!(!sample_diffs::simple_addition().is_empty());
        assert!(!sample_diffs::simple_change().is_empty());
        assert!(!sample_diffs::multiple_files().is_empty());
        assert!(!sample_diffs::multiple_hunks().is_empty());
        assert!(!sample_diffs::binary_file().is_empty());
        assert!(!sample_diffs::deleted_file().is_empty());
        assert!(!sample_diffs::renamed_file().is_empty());
        assert!(!sample_diffs::mode_change().is_empty());
        assert!(!sample_diffs::submodule_change().is_empty());
        assert!(!sample_diffs::unicode_content().is_empty());
        assert!(!sample_diffs::with_unwrap().is_empty());

        // Empty diff should be empty
        assert!(sample_diffs::empty().is_empty());
    }

    #[test]
    fn sample_diffs_parse_correctly() {
        use diffguard_diff::parse_unified_diff;
        use diffguard_types::Scope;

        // Simple addition should have 1 line
        let (lines, stats) =
            parse_unified_diff(sample_diffs::simple_addition(), Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(lines.len(), 1);

        // Multiple files should have 2 files
        let (lines, stats) =
            parse_unified_diff(sample_diffs::multiple_files(), Scope::Added).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(lines.len(), 2);

        // Binary file should skip binary, parse the text file
        let (lines, stats) = parse_unified_diff(sample_diffs::binary_file(), Scope::Added).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].path, "src/lib.rs");

        // Renamed file should use new path
        let (lines, _) = parse_unified_diff(sample_diffs::renamed_file(), Scope::Added).unwrap();
        assert!(lines.iter().all(|l| l.path == "new/path.rs"));
    }
}
