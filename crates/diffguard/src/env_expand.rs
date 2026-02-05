//! Environment variable expansion for configuration files.
//!
//! This module provides functionality to expand environment variable references
//! in configuration file content before parsing. It supports:
//!
//! - Basic expansion: `${VAR}` - replaced with the value of VAR
//! - Default values: `${VAR:-default}` - uses "default" if VAR is unset or empty
//!
//! # Examples
//!
//! ```ignore
//! use diffguard::env_expand::expand_env_vars;
//!
//! // Basic expansion
//! std::env::set_var("PROJECT_ROOT", "/home/user/project");
//! let result = expand_env_vars("paths = [\"${PROJECT_ROOT}/src/**/*.rs\"]")?;
//! assert_eq!(result, "paths = [\"/home/user/project/src/**/*.rs\"]");
//!
//! // With default value
//! let result = expand_env_vars("name = \"${UNSET_VAR:-fallback}\"")?;
//! assert_eq!(result, "name = \"fallback\"");
//! ```

use std::borrow::Cow;

use anyhow::{bail, Result};

/// Expand environment variable references in the given text.
///
/// Supports two forms:
/// - `${VAR}` - Expands to the value of VAR, errors if unset
/// - `${VAR:-default}` - Expands to the value of VAR, or "default" if unset/empty
///
/// # Errors
///
/// Returns an error if a required variable (one without a default) is not set.
///
/// # Examples
///
/// ```ignore
/// std::env::set_var("HOME", "/home/user");
/// let result = expand_env_vars("path = \"${HOME}/config\"")?;
/// assert_eq!(result, "path = \"/home/user/config\"");
/// ```
pub fn expand_env_vars(text: &str) -> Result<Cow<'_, str>> {
    // Quick check: if no `${` pattern exists, return the original text
    if !text.contains("${") {
        return Ok(Cow::Borrowed(text));
    }

    let mut result = String::with_capacity(text.len());
    let mut chars = text.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if c == '$' {
            // Check if next char is '{'
            if let Some(&(_, '{')) = chars.peek() {
                chars.next(); // consume '{'

                // Find the closing '}'
                let start = i;
                let mut var_content = String::new();
                let mut found_close = false;
                let mut depth = 1;

                while let Some((_, ch)) = chars.next() {
                    if ch == '{' {
                        depth += 1;
                        var_content.push(ch);
                    } else if ch == '}' {
                        depth -= 1;
                        if depth == 0 {
                            found_close = true;
                            break;
                        }
                        var_content.push(ch);
                    } else {
                        var_content.push(ch);
                    }
                }

                if !found_close {
                    bail!(
                        "Unclosed environment variable reference starting at position {}: ${{{}...",
                        start,
                        &var_content[..var_content.len().min(20)]
                    );
                }

                // Parse the variable content: VAR or VAR:-default
                let expanded = expand_single_var(&var_content)?;
                result.push_str(&expanded);
            } else {
                // Not followed by '{', just a regular '$'
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    Ok(Cow::Owned(result))
}

/// Expand a single variable reference (the content between `${` and `}`).
///
/// Handles:
/// - `VAR` - simple variable, errors if unset
/// - `VAR:-default` - variable with default value
fn expand_single_var(content: &str) -> Result<String> {
    // Check for default value syntax: VAR:-default
    if let Some(pos) = content.find(":-") {
        let var_name = &content[..pos];
        let default_value = &content[pos + 2..];

        validate_var_name(var_name)?;

        match std::env::var(var_name) {
            Ok(val) if !val.is_empty() => Ok(val),
            _ => Ok(default_value.to_string()),
        }
    } else {
        // Simple variable reference
        validate_var_name(content)?;

        match std::env::var(content) {
            Ok(val) => Ok(val),
            Err(_) => bail!(
                "Environment variable '{}' is not set. \
                 Use ${{{}:-default}} syntax to provide a default value.",
                content,
                content
            ),
        }
    }
}

/// Validate that a variable name is valid (non-empty, valid chars).
fn validate_var_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Empty environment variable name in ${{}}");
    }

    // Check for valid variable name characters
    // Environment variable names typically consist of uppercase letters, digits, and underscores
    // But we'll be lenient and allow lowercase too
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        bail!(
            "Invalid environment variable name '{}': must start with a letter or underscore",
            name
        );
    }

    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            bail!(
                "Invalid environment variable name '{}': contains invalid character '{}'",
                name,
                c
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to run tests with controlled environment.
    fn with_env<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Set variables
        for (key, value) in vars {
            std::env::set_var(key, value);
        }

        let result = f();

        // Clean up
        for (key, _) in vars {
            std::env::remove_var(key);
        }

        result
    }

    /// Helper to ensure a variable is unset
    fn without_env<F, R>(vars: &[&str], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        for var in vars {
            std::env::remove_var(var);
        }
        f()
    }

    #[test]
    fn test_no_expansion_needed() {
        let input = "paths = [\"**/*.rs\"]";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, input);
        // Should be borrowed (no allocation)
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_basic_expansion() {
        with_env(&[("TEST_HOME", "/home/user")], || {
            let input = "path = \"${TEST_HOME}/config\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "path = \"/home/user/config\"");
        });
    }

    #[test]
    fn test_multiple_expansions() {
        with_env(
            &[
                ("TEST_PROJECT_ROOT", "/project"),
                ("TEST_PROJECT_NAME", "myapp"),
            ],
            || {
                let input =
                    "paths = [\"${TEST_PROJECT_ROOT}/src\"], name = \"${TEST_PROJECT_NAME}\"";
                let result = expand_env_vars(input).unwrap();
                assert_eq!(result, "paths = [\"/project/src\"], name = \"myapp\"");
            },
        );
    }

    #[test]
    fn test_default_value_when_unset() {
        without_env(&["TEST_UNSET_VAR"], || {
            let input = "value = \"${TEST_UNSET_VAR:-fallback}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"fallback\"");
        });
    }

    #[test]
    fn test_default_value_when_empty() {
        with_env(&[("TEST_EMPTY_VAR", "")], || {
            let input = "value = \"${TEST_EMPTY_VAR:-fallback}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"fallback\"");
        });
    }

    #[test]
    fn test_default_value_not_used_when_set() {
        with_env(&[("TEST_SET_VAR", "actual_value")], || {
            let input = "value = \"${TEST_SET_VAR:-fallback}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"actual_value\"");
        });
    }

    #[test]
    fn test_empty_default_value() {
        without_env(&["TEST_UNSET_VAR2"], || {
            let input = "value = \"${TEST_UNSET_VAR2:-}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"\"");
        });
    }

    #[test]
    fn test_default_with_special_chars() {
        without_env(&["TEST_UNSET_VAR3"], || {
            let input = "value = \"${TEST_UNSET_VAR3:-/path/to/file.txt}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"/path/to/file.txt\"");
        });
    }

    #[test]
    fn test_missing_required_var_error() {
        without_env(&["TEST_REQUIRED_VAR"], || {
            let input = "value = \"${TEST_REQUIRED_VAR}\"";
            let result = expand_env_vars(input);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("TEST_REQUIRED_VAR"));
            assert!(err.contains("not set"));
        });
    }

    #[test]
    fn test_unclosed_brace_error() {
        let input = "value = \"${UNCLOSED";
        let result = expand_env_vars(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unclosed"));
    }

    #[test]
    fn test_empty_var_name_error() {
        let input = "value = \"${}\"";
        let result = expand_env_vars(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Empty"));
    }

    #[test]
    fn test_invalid_var_name_start_digit() {
        let input = "value = \"${123VAR}\"";
        let result = expand_env_vars(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid"));
    }

    #[test]
    fn test_invalid_var_name_special_char() {
        let input = "value = \"${VAR-NAME}\"";
        let result = expand_env_vars(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid"));
    }

    #[test]
    fn test_dollar_without_brace_preserved() {
        let input = "regex = \"$pattern\"";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "regex = \"$pattern\"");
    }

    #[test]
    fn test_double_dollar_preserved() {
        let input = "text = \"$$money\"";
        let result = expand_env_vars(input).unwrap();
        assert_eq!(result, "text = \"$$money\"");
    }

    #[test]
    fn test_expansion_in_array() {
        with_env(&[("TEST_ROOT", "/root")], || {
            let input = r#"paths = ["${TEST_ROOT}/src/**/*.rs", "${TEST_ROOT}/lib/**/*.rs"]"#;
            let result = expand_env_vars(input).unwrap();
            assert_eq!(
                result,
                r#"paths = ["/root/src/**/*.rs", "/root/lib/**/*.rs"]"#
            );
        });
    }

    #[test]
    fn test_expansion_in_toml_config() {
        with_env(
            &[
                ("TEST_PROJECT_ROOT", "/home/user/project"),
                ("TEST_PROJECT_NAME", "diffguard"),
            ],
            || {
                let input = r#"
[defaults]
base = "origin/main"

[[rule]]
id = "custom.check"
paths = ["${TEST_PROJECT_ROOT}/src/**/*.rs"]
exclude_paths = ["${TEST_PROJECT_ROOT}/target/**"]
message = "Custom check for ${TEST_PROJECT_NAME}"
"#;
                let result = expand_env_vars(input).unwrap();

                assert!(result.contains("paths = [\"/home/user/project/src/**/*.rs\"]"));
                assert!(result.contains("exclude_paths = [\"/home/user/project/target/**\"]"));
                assert!(result.contains("message = \"Custom check for diffguard\""));
            },
        );
    }

    #[test]
    fn test_underscore_var_name() {
        with_env(&[("_PRIVATE_VAR", "secret")], || {
            let input = "value = \"${_PRIVATE_VAR}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"secret\"");
        });
    }

    #[test]
    fn test_var_with_numbers() {
        with_env(&[("VAR_123", "value123")], || {
            let input = "value = \"${VAR_123}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"value123\"");
        });
    }

    #[test]
    fn test_consecutive_vars() {
        with_env(&[("TEST_A", "alpha"), ("TEST_B", "beta")], || {
            let input = "value = \"${TEST_A}${TEST_B}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "value = \"alphabeta\"");
        });
    }

    #[test]
    fn test_mixed_defaults_and_required() {
        with_env(&[("TEST_REQUIRED", "present")], || {
            without_env(&["TEST_OPTIONAL"], || {
                let input = "a = \"${TEST_REQUIRED}\", b = \"${TEST_OPTIONAL:-default}\"";
                let result = expand_env_vars(input).unwrap();
                assert_eq!(result, "a = \"present\", b = \"default\"");
            });
        });
    }

    #[test]
    fn test_default_with_colon() {
        without_env(&["TEST_URL_VAR"], || {
            let input = "url = \"${TEST_URL_VAR:-http://localhost:8080}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "url = \"http://localhost:8080\"");
        });
    }

    #[test]
    fn test_windows_path_in_value() {
        with_env(&[("TEST_WIN_PATH", r"C:\Users\test")], || {
            let input = "path = \"${TEST_WIN_PATH}\"";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, "path = \"C:\\Users\\test\"");
        });
    }

    #[test]
    fn test_windows_path_in_default() {
        without_env(&["TEST_WIN_PATH2"], || {
            let input = r"path = '${TEST_WIN_PATH2:-C:\default\path}'";
            let result = expand_env_vars(input).unwrap();
            assert_eq!(result, r"path = 'C:\default\path'");
        });
    }
}
