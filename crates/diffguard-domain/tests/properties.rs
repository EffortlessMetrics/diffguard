//! Property-based tests for diffguard-domain
//!
//! Feature: diffguard-completion

use proptest::prelude::*;
use std::path::Path;

use diffguard_domain::{detect_language, Language, PreprocessOptions, Preprocessor};

// Known extensions and their expected language mappings
// Based on Requirements 1.1-1.12 and actual detect_language implementation
const KNOWN_EXTENSIONS: &[(&str, &str)] = &[
    // Rust (not in task list but in implementation)
    ("rs", "rust"),
    // Python - Requirement 1.1
    ("py", "python"),
    ("pyw", "python"),
    // JavaScript - Requirements 1.2, 1.5
    ("js", "javascript"),
    ("jsx", "javascript"),
    ("mjs", "javascript"),
    ("cjs", "javascript"),
    // TypeScript - Requirements 1.3, 1.4
    ("ts", "typescript"),
    ("tsx", "typescript"),
    ("mts", "typescript"),
    ("cts", "typescript"),
    // Go - Requirement 1.6
    ("go", "go"),
    // Java - Requirement 1.7
    ("java", "java"),
    // Kotlin - Requirement 1.8
    ("kt", "kotlin"),
    ("kts", "kotlin"),
    // Ruby - Requirement 1.9
    ("rb", "ruby"),
    ("rake", "ruby"),
    // C - Requirement 1.10
    ("c", "c"),
    ("h", "c"),
    // C++ - Requirement 1.11
    ("cpp", "cpp"),
    ("cc", "cpp"),
    ("cxx", "cpp"),
    ("hpp", "cpp"),
    ("hxx", "cpp"),
    ("hh", "cpp"),
    // C# - Requirement 1.12
    ("cs", "csharp"),
];

/// Strategy to generate valid file names (alphanumeric with underscores)
fn filename_strategy() -> impl Strategy<Value = String> {
    // Generate a filename without extension (1-20 alphanumeric chars)
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{0,19}").expect("valid regex")
}

/// Strategy to generate a known extension from the list
fn known_extension_strategy() -> impl Strategy<Value = (&'static str, &'static str)> {
    prop::sample::select(KNOWN_EXTENSIONS)
}

/// Strategy to generate unknown extensions
/// These are extensions NOT in the known set
fn unknown_extension_strategy() -> impl Strategy<Value = String> {
    // Generate extensions that are definitely not in our known set
    prop::string::string_regex("[a-z]{1,5}")
        .expect("valid regex")
        .prop_filter("must not be a known extension", |ext| {
            !KNOWN_EXTENSIONS.iter().any(|(known, _)| known == ext)
        })
}

/// Strategy to generate directory paths
fn directory_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{0,9}").expect("valid regex"),
        0..4,
    )
    .prop_map(|parts| {
        if parts.is_empty() {
            String::new()
        } else {
            parts.join("/") + "/"
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: diffguard-completion, Property 1: Language Detection Correctness
    // For any file path with a known extension (rs, py, js, ts, tsx, jsx, go, java, kt, rb, c, h, cpp, cc, cxx, hpp, cs),
    // the `detect_language` function SHALL return the correct language identifier string.
    // **Validates: Requirements 1.1-1.12**
    #[test]
    fn property_language_detection_correctness(
        dir in directory_strategy(),
        filename in filename_strategy(),
        (ext, expected_lang) in known_extension_strategy(),
    ) {
        let path_str = format!("{}{}.{}", dir, filename, ext);
        let path = Path::new(&path_str);

        let detected = detect_language(path);

        prop_assert_eq!(
            detected,
            Some(expected_lang),
            "Expected language '{}' for extension '{}' in path '{}'",
            expected_lang,
            ext,
            path_str
        );
    }

    // Feature: diffguard-completion, Property 1: Language Detection Correctness (case insensitive)
    // Extensions should be detected case-insensitively
    // **Validates: Requirements 1.1-1.12**
    #[test]
    fn property_language_detection_case_insensitive(
        dir in directory_strategy(),
        filename in filename_strategy(),
        (ext, expected_lang) in known_extension_strategy(),
        use_uppercase in prop::bool::ANY,
    ) {
        let ext_case = if use_uppercase {
            ext.to_uppercase()
        } else {
            ext.to_lowercase()
        };
        let path_str = format!("{}{}.{}", dir, filename, ext_case);
        let path = Path::new(&path_str);

        let detected = detect_language(path);

        prop_assert_eq!(
            detected,
            Some(expected_lang),
            "Expected language '{}' for extension '{}' (case: {}) in path '{}'",
            expected_lang,
            ext_case,
            if use_uppercase { "upper" } else { "lower" },
            path_str
        );
    }

    // Feature: diffguard-completion, Property 2: Unknown Extension Fallback
    // For any file path with an extension not in the known set,
    // the `detect_language` function SHALL return None.
    // **Validates: Requirements 1.13**
    #[test]
    fn property_unknown_extension_fallback(
        dir in directory_strategy(),
        filename in filename_strategy(),
        ext in unknown_extension_strategy(),
    ) {
        let path_str = format!("{}{}.{}", dir, filename, ext);
        let path = Path::new(&path_str);

        let detected = detect_language(path);

        prop_assert_eq!(
            detected,
            None,
            "Expected None for unknown extension '{}' in path '{}', but got {:?}",
            ext,
            path_str,
            detected
        );
    }

    // Feature: diffguard-completion, Property 2: Unknown Extension Fallback (no extension)
    // Files without extensions should return None
    // **Validates: Requirements 1.13**
    #[test]
    fn property_no_extension_returns_none(
        dir in directory_strategy(),
        filename in filename_strategy(),
    ) {
        let path_str = format!("{}{}", dir, filename);
        let path = Path::new(&path_str);

        let detected = detect_language(path);

        prop_assert_eq!(
            detected,
            None,
            "Expected None for file without extension '{}', but got {:?}",
            path_str,
            detected
        );
    }
}

// ==================== Property 3 & 4: Language-Aware Preprocessing ====================

/// Strategy to generate code content that doesn't contain comment starters
/// (excludes / and # to avoid accidentally creating comments in the prefix)
fn code_prefix_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_=+\\-*<>!&|()\\[\\]{},;:.@ ]{0,50}")
        .expect("valid regex")
        .prop_filter("must not end with / or contain #", |s| {
            !s.ends_with('/') && !s.contains('#') && !s.contains("/*")
        })
}

/// Strategy to generate code suffix that doesn't start with comment-related chars
fn code_suffix_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_=+\\-<>!&|()\\[\\]{},;:.@ ]{0,50}")
        .expect("valid regex")
        .prop_filter("must not start with / or *", |s| {
            !s.starts_with('/') && !s.starts_with('*')
        })
}

/// Strategy to generate hash comment content (for Python/Ruby)
fn hash_comment_content_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,30}").expect("valid regex")
}

/// Strategy to generate C-style line comment content
fn cstyle_comment_content_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,30}").expect("valid regex")
}

/// Strategy to generate string content (no quotes or backslashes to avoid escaping complexity)
fn string_content_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,20}").expect("valid regex")
}

/// Strategy to generate template literal content (no backticks)
fn template_literal_content_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,20}").expect("valid regex")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // ==================== Property 3: Comment Masking by Language ====================

    // Feature: diffguard-completion, Property 3: Comment Masking by Language
    // For any source code line containing comments in the language's comment syntax
    // (hash for Python/Ruby, C-style for others), when `ignore_comments` is enabled,
    // the preprocessor SHALL replace comment content with spaces while preserving line length.
    // **Validates: Requirements 2.1, 2.3, 2.5, 2.7, 2.8**

    #[test]
    fn property_hash_comment_masking_python(
        prefix in code_prefix_strategy(),
        comment in hash_comment_content_strategy(),
    ) {
        // Python uses hash comments
        let line = format!("{}# {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::Python,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: comment content is masked (replaced with spaces)
        // The prefix should remain, but the comment part should be spaces
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );

        // If there was comment content, it should be masked
        if !comment.is_empty() {
            let comment_part = &result[prefix.len()..];
            prop_assert!(
                comment_part.chars().all(|c| c == ' '),
                "Comment content should be masked with spaces. Got: '{}'",
                comment_part
            );
        }
    }

    #[test]
    fn property_hash_comment_masking_ruby(
        prefix in code_prefix_strategy(),
        comment in hash_comment_content_strategy(),
    ) {
        // Ruby uses hash comments
        let line = format!("{}# {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::Ruby,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
    }

    #[test]
    fn property_cstyle_line_comment_masking_javascript(
        prefix in code_prefix_strategy(),
        comment in cstyle_comment_content_strategy(),
    ) {
        // JavaScript uses C-style comments
        let line = format!("{}// {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::JavaScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );

        // Property: comment is masked
        if !comment.is_empty() {
            let comment_part = &result[prefix.len()..];
            prop_assert!(
                comment_part.chars().all(|c| c == ' '),
                "Comment content should be masked with spaces. Got: '{}'",
                comment_part
            );
        }
    }

    #[test]
    fn property_cstyle_line_comment_masking_typescript(
        prefix in code_prefix_strategy(),
        comment in cstyle_comment_content_strategy(),
    ) {
        // TypeScript uses C-style comments
        let line = format!("{}// {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::TypeScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
    }

    #[test]
    fn property_cstyle_line_comment_masking_go(
        prefix in code_prefix_strategy(),
        comment in cstyle_comment_content_strategy(),
    ) {
        // Go uses C-style comments
        let line = format!("{}// {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::Go,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
    }

    #[test]
    fn property_cstyle_block_comment_masking(
        prefix in code_prefix_strategy(),
        comment in cstyle_comment_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // Test block comments /* */ for C-style languages
        let line = format!("{}/* {} */{}", prefix, comment, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::JavaScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );

        // Property: suffix is preserved
        prop_assert!(
            result.ends_with(&suffix),
            "Suffix should be preserved. Expected suffix '{}' in '{}'",
            suffix,
            result
        );
    }

    #[test]
    fn property_unknown_language_uses_cstyle_comments(
        prefix in code_prefix_strategy(),
        comment in cstyle_comment_content_strategy(),
    ) {
        // Unknown language should fall back to C-style comments
        let line = format!("{}// {}", prefix, comment);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::Unknown,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix is preserved (C-style comment should be masked)
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
    }

    // ==================== Property 4: String Masking by Language ====================

    // Feature: diffguard-completion, Property 4: String Masking by Language
    // For any source code line containing string literals in the language's string syntax,
    // when `ignore_strings` is enabled, the preprocessor SHALL replace string content
    // with spaces while preserving line length.
    // **Validates: Requirements 2.2, 2.4, 2.6**

    #[test]
    fn property_double_quoted_string_masking(
        prefix in code_prefix_strategy(),
        content in string_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // Double-quoted strings are common across languages
        let line = format!("{}\"{}\"{}",  prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::Python,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: string content is masked but delimiters may or may not be preserved
        // The key property is that the content inside is masked
        if !content.is_empty() {
            // The string content should be replaced with spaces
            let string_start = prefix.len();
            let string_end = string_start + content.len() + 2; // +2 for quotes
            let masked_section = &result[string_start..string_end];
            prop_assert!(
                masked_section.chars().all(|c| c == ' '),
                "String content should be masked. Got: '{}'",
                masked_section
            );
        }
    }

    #[test]
    fn property_single_quoted_string_masking_python(
        prefix in code_prefix_strategy(),
        content in string_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // Python supports single-quoted strings
        let line = format!("{}'{}'{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::Python,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );
    }

    #[test]
    fn property_single_quoted_string_masking_javascript(
        prefix in code_prefix_strategy(),
        content in string_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // JavaScript supports single-quoted strings
        let line = format!("{}'{}'{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::JavaScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );
    }

    #[test]
    fn property_template_literal_masking_javascript(
        prefix in code_prefix_strategy(),
        content in template_literal_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // JavaScript template literals use backticks
        let line = format!("{}`{}`{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::JavaScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix and suffix are preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
        prop_assert!(
            result.ends_with(&suffix),
            "Suffix should be preserved. Expected suffix '{}' in '{}'",
            suffix,
            result
        );
    }

    #[test]
    fn property_template_literal_masking_typescript(
        prefix in code_prefix_strategy(),
        content in template_literal_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // TypeScript also supports template literals
        let line = format!("{}`{}`{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::TypeScript,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );
    }

    #[test]
    fn property_backtick_raw_string_masking_go(
        prefix in code_prefix_strategy(),
        content in template_literal_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // Go uses backticks for raw strings
        let line = format!("{}`{}`{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::Go,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix and suffix are preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
        prop_assert!(
            result.ends_with(&suffix),
            "Suffix should be preserved. Expected suffix '{}' in '{}'",
            suffix,
            result
        );
    }

    #[test]
    fn property_triple_quoted_string_masking_python(
        prefix in code_prefix_strategy(),
        content in string_content_strategy(), // Use simpler content without newlines for single-line test
        suffix in code_suffix_strategy(),
    ) {
        // Python triple-quoted strings (double quotes)
        let line = format!("{}\"\"\"{}\"\"\"{}",  prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::Python,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix and suffix are preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
        prop_assert!(
            result.ends_with(&suffix),
            "Suffix should be preserved. Expected suffix '{}' in '{}'",
            suffix,
            result
        );
    }

    #[test]
    fn property_triple_single_quoted_string_masking_python(
        prefix in code_prefix_strategy(),
        content in string_content_strategy(),
        suffix in code_suffix_strategy(),
    ) {
        // Python triple-quoted strings (single quotes)
        let line = format!("{}'''{}'''{}", prefix, content, suffix);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::strings_only(),
            Language::Python,
        );

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is preserved
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must be preserved. Input: '{}', Output: '{}'",
            line,
            result
        );

        // Property: prefix and suffix are preserved
        prop_assert!(
            result.starts_with(&prefix),
            "Prefix should be preserved. Expected prefix '{}' in '{}'",
            prefix,
            result
        );
        prop_assert!(
            result.ends_with(&suffix),
            "Suffix should be preserved. Expected suffix '{}' in '{}'",
            suffix,
            result
        );
    }

    // ==================== Combined Properties ====================

    #[test]
    fn property_line_length_always_preserved(
        line in prop::string::string_regex("[a-zA-Z0-9_\"'`#/ ]{0,100}").expect("valid regex"),
        mask_comments in prop::bool::ANY,
        mask_strings in prop::bool::ANY,
        lang in prop::sample::select(&[
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Ruby,
            Language::Unknown,
        ]),
    ) {
        let opts = PreprocessOptions {
            mask_comments,
            mask_strings,
        };
        let mut preprocessor = Preprocessor::with_language(opts, lang);

        let result = preprocessor.sanitize_line(&line);

        // Property: line length is ALWAYS preserved regardless of options or language
        prop_assert_eq!(
            result.len(),
            line.len(),
            "Line length must always be preserved. Input len: {}, Output len: {}, Input: '{}', Output: '{}'",
            line.len(),
            result.len(),
            line,
            result
        );
    }

    #[test]
    fn property_no_masking_preserves_line(
        line in prop::string::string_regex("[a-zA-Z0-9_\"'`#/ ]{0,100}").expect("valid regex"),
        lang in prop::sample::select(&[
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Ruby,
            Language::Unknown,
        ]),
    ) {
        // When no masking is enabled, the line should be unchanged
        let mut preprocessor = Preprocessor::with_language(PreprocessOptions::none(), lang);

        let result = preprocessor.sanitize_line(&line);

        // Property: with no masking, output equals input
        prop_assert_eq!(
            &result,
            &line,
            "With no masking enabled, line should be unchanged. Input: '{}', Output: '{}'",
            line,
            result
        );
    }
}

// ==================== Property 5: Built-in Rules Compile Successfully ====================

use diffguard_domain::compile_rules;
use diffguard_types::ConfigFile;

// Feature: diffguard-completion, Property 5: Built-in Rules Compile Successfully
// For all rules returned by `ConfigFile::built_in()`, the `compile_rules` function
// SHALL succeed without returning an error.
// **Validates: Requirements 3.6**
#[test]
fn property_builtin_rules_compile_successfully() {
    // Get all built-in rules
    let config = ConfigFile::built_in();

    // Verify that we have rules to test (sanity check)
    assert!(
        !config.rule.is_empty(),
        "ConfigFile::built_in() should return at least one rule"
    );

    // Attempt to compile all built-in rules
    let result = compile_rules(&config.rule);

    // Property: compile_rules SHALL succeed without returning an error
    assert!(
        result.is_ok(),
        "All built-in rules should compile successfully, but got error: {:?}",
        result.err()
    );

    // Additional verification: the number of compiled rules matches input
    let compiled_rules = result.unwrap();
    assert_eq!(
        compiled_rules.len(),
        config.rule.len(),
        "Number of compiled rules should match number of input rules"
    );

    // Verify each rule has at least one compiled pattern
    for (i, rule) in compiled_rules.iter().enumerate() {
        assert!(
            !rule.patterns.is_empty(),
            "Compiled rule {} ('{}') should have at least one pattern",
            i,
            rule.id
        );
    }
}

// Feature: diffguard-completion, Property 5: Built-in Rules Compile Successfully
// Additional test: verify each built-in rule individually to provide better error messages
// **Validates: Requirements 3.6**
#[test]
fn property_each_builtin_rule_compiles_individually() {
    let config = ConfigFile::built_in();

    for rule_config in &config.rule {
        // Compile each rule individually
        let result = compile_rules(std::slice::from_ref(rule_config));

        assert!(
            result.is_ok(),
            "Built-in rule '{}' should compile successfully, but got error: {:?}",
            rule_config.id,
            result.err()
        );

        let compiled = result.unwrap();
        assert_eq!(compiled.len(), 1, "Should compile exactly one rule");

        let compiled_rule = &compiled[0];

        // Verify the compiled rule has the expected properties
        assert_eq!(
            compiled_rule.id, rule_config.id,
            "Compiled rule ID should match config"
        );
        assert_eq!(
            compiled_rule.patterns.len(),
            rule_config.patterns.len(),
            "Rule '{}': number of compiled patterns should match config",
            rule_config.id
        );
    }
}

// ==================== Property 10: Error Messages Contain Context ====================

use diffguard_domain::RuleCompileError;
use diffguard_types::{RuleConfig, Severity};

/// Strategy to generate valid rule IDs (alphanumeric with dots and underscores)
fn rule_id_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_.]{0,29}")
        .expect("valid regex")
        .prop_filter("must not be empty", |s| !s.is_empty())
}

/// Strategy to generate invalid regex patterns
/// These patterns will fail to compile due to regex syntax errors
fn invalid_regex_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(&[
        // Unclosed groups
        "(unclosed",
        "[unclosed",
        // Invalid quantifiers
        "*invalid",
        "+invalid",
        "?invalid",
        // Invalid escape sequences
        "\\",
        // Unclosed repetition
        "a{",
        "a{1,",
        // Invalid character class
        "[z-a]",
        // Unmatched parentheses
        "(((",
        ")))",
        // Invalid backreference
        "\\99999",
    ])
    .prop_map(|s| s.to_string())
}

/// Strategy to generate invalid glob patterns
/// These patterns will fail to compile due to glob syntax errors
fn invalid_glob_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(&[
        // Unclosed brackets - definitely invalid
        "[unclosed",
        // Unclosed braces - definitely invalid
        "{unclosed",
        // Nested unclosed brackets - definitely invalid
        "[[invalid",
        // Another unclosed bracket variant
        "test[abc",
        // Unclosed brace with content
        "{a,b,c",
    ])
    .prop_map(|s| s.to_string())
}

/// Strategy to generate valid regex patterns (for use in rules that test other errors)
fn valid_regex_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(&[
        "simple",
        "word\\b",
        "[a-z]+",
        "\\d+",
        "foo|bar",
        "test.*pattern",
    ])
    .prop_map(|s| s.to_string())
}

/// Helper to create a basic rule config with given ID and patterns
fn make_rule_config(id: &str, patterns: Vec<String>) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        severity: Severity::Warn,
        message: "Test message".to_string(),
        languages: vec![],
        patterns,
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
    }
}

/// Helper to create a rule config with paths
fn make_rule_config_with_paths(id: &str, patterns: Vec<String>, paths: Vec<String>) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        severity: Severity::Warn,
        message: "Test message".to_string(),
        languages: vec![],
        patterns,
        paths,
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
    }
}

/// Helper to create a rule config with exclude paths
fn make_rule_config_with_exclude_paths(
    id: &str,
    patterns: Vec<String>,
    exclude_paths: Vec<String>,
) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        severity: Severity::Warn,
        message: "Test message".to_string(),
        languages: vec![],
        patterns,
        paths: vec![],
        exclude_paths,
        ignore_comments: false,
        ignore_strings: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: diffguard-completion, Property 10: Error Messages Contain Context
    // For any invalid rule configuration (invalid regex, invalid glob, or missing patterns),
    // the error returned by `compile_rules` SHALL contain the rule ID and the specific invalid element.
    // **Validates: Requirements 6.1, 6.2, 6.3**

    // Test: Invalid regex returns error with rule_id and pattern
    // **Validates: Requirement 6.1**
    #[test]
    fn property_invalid_regex_error_contains_rule_id_and_pattern(
        rule_id in rule_id_strategy(),
        invalid_pattern in invalid_regex_strategy(),
    ) {
        let config = make_rule_config(&rule_id, vec![invalid_pattern.clone()]);
        let result = compile_rules(&[config]);

        // Property: compile_rules SHALL return an error for invalid regex
        prop_assert!(
            result.is_err(),
            "compile_rules should fail for invalid regex pattern '{}' in rule '{}'",
            invalid_pattern,
            rule_id
        );

        let error = result.unwrap_err();

        // Property: error SHALL be InvalidRegex variant
        match &error {
            RuleCompileError::InvalidRegex {
                rule_id: err_rule_id,
                pattern: err_pattern,
                source: _,
            } => {
                // Property: error SHALL contain the rule ID
                prop_assert_eq!(
                    err_rule_id,
                    &rule_id,
                    "Error should contain the rule ID. Expected '{}', got '{}'",
                    rule_id,
                    err_rule_id
                );

                // Property: error SHALL contain the invalid pattern
                prop_assert_eq!(
                    err_pattern,
                    &invalid_pattern,
                    "Error should contain the invalid pattern. Expected '{}', got '{}'",
                    invalid_pattern,
                    err_pattern
                );

                // Property: error message (Display) SHALL contain rule_id and pattern
                let error_msg = error.to_string();
                prop_assert!(
                    error_msg.contains(&rule_id),
                    "Error message should contain rule ID '{}'. Got: '{}'",
                    rule_id,
                    error_msg
                );
                prop_assert!(
                    error_msg.contains(&invalid_pattern),
                    "Error message should contain invalid pattern '{}'. Got: '{}'",
                    invalid_pattern,
                    error_msg
                );
            }
            other => {
                prop_assert!(
                    false,
                    "Expected InvalidRegex error, got {:?}",
                    other
                );
            }
        }
    }

    // Test: Invalid glob in paths returns error with rule_id and glob
    // **Validates: Requirement 6.2**
    #[test]
    fn property_invalid_glob_in_paths_error_contains_rule_id_and_glob(
        rule_id in rule_id_strategy(),
        valid_pattern in valid_regex_strategy(),
        invalid_glob in invalid_glob_strategy(),
    ) {
        let config = make_rule_config_with_paths(
            &rule_id,
            vec![valid_pattern],
            vec![invalid_glob.clone()],
        );
        let result = compile_rules(&[config]);

        // Property: compile_rules SHALL return an error for invalid glob
        prop_assert!(
            result.is_err(),
            "compile_rules should fail for invalid glob '{}' in rule '{}'",
            invalid_glob,
            rule_id
        );

        let error = result.unwrap_err();

        // Property: error SHALL be InvalidGlob variant
        match &error {
            RuleCompileError::InvalidGlob {
                rule_id: err_rule_id,
                glob: err_glob,
                source: _,
            } => {
                // Property: error SHALL contain the rule ID
                prop_assert_eq!(
                    err_rule_id,
                    &rule_id,
                    "Error should contain the rule ID. Expected '{}', got '{}'",
                    rule_id,
                    err_rule_id
                );

                // Property: error SHALL contain the invalid glob
                prop_assert_eq!(
                    err_glob,
                    &invalid_glob,
                    "Error should contain the invalid glob. Expected '{}', got '{}'",
                    invalid_glob,
                    err_glob
                );

                // Property: error message (Display) SHALL contain rule_id and glob
                let error_msg = error.to_string();
                prop_assert!(
                    error_msg.contains(&rule_id),
                    "Error message should contain rule ID '{}'. Got: '{}'",
                    rule_id,
                    error_msg
                );
                prop_assert!(
                    error_msg.contains(&invalid_glob),
                    "Error message should contain invalid glob '{}'. Got: '{}'",
                    invalid_glob,
                    error_msg
                );
            }
            other => {
                prop_assert!(
                    false,
                    "Expected InvalidGlob error, got {:?}",
                    other
                );
            }
        }
    }

    // Test: Invalid glob in exclude_paths returns error with rule_id and glob
    // **Validates: Requirement 6.2**
    #[test]
    fn property_invalid_glob_in_exclude_paths_error_contains_rule_id_and_glob(
        rule_id in rule_id_strategy(),
        valid_pattern in valid_regex_strategy(),
        invalid_glob in invalid_glob_strategy(),
    ) {
        let config = make_rule_config_with_exclude_paths(
            &rule_id,
            vec![valid_pattern],
            vec![invalid_glob.clone()],
        );
        let result = compile_rules(&[config]);

        // Property: compile_rules SHALL return an error for invalid glob in exclude_paths
        prop_assert!(
            result.is_err(),
            "compile_rules should fail for invalid glob '{}' in exclude_paths of rule '{}'",
            invalid_glob,
            rule_id
        );

        let error = result.unwrap_err();

        // Property: error SHALL be InvalidGlob variant
        match &error {
            RuleCompileError::InvalidGlob {
                rule_id: err_rule_id,
                glob: err_glob,
                source: _,
            } => {
                // Property: error SHALL contain the rule ID
                prop_assert_eq!(
                    err_rule_id,
                    &rule_id,
                    "Error should contain the rule ID. Expected '{}', got '{}'",
                    rule_id,
                    err_rule_id
                );

                // Property: error SHALL contain the invalid glob
                prop_assert_eq!(
                    err_glob,
                    &invalid_glob,
                    "Error should contain the invalid glob. Expected '{}', got '{}'",
                    invalid_glob,
                    err_glob
                );

                // Property: error message (Display) SHALL contain rule_id and glob
                let error_msg = error.to_string();
                prop_assert!(
                    error_msg.contains(&rule_id),
                    "Error message should contain rule ID '{}'. Got: '{}'",
                    rule_id,
                    error_msg
                );
                prop_assert!(
                    error_msg.contains(&invalid_glob),
                    "Error message should contain invalid glob '{}'. Got: '{}'",
                    invalid_glob,
                    error_msg
                );
            }
            other => {
                prop_assert!(
                    false,
                    "Expected InvalidGlob error, got {:?}",
                    other
                );
            }
        }
    }

    // Test: Missing patterns returns error with rule_id
    // **Validates: Requirement 6.3**
    #[test]
    fn property_missing_patterns_error_contains_rule_id(
        rule_id in rule_id_strategy(),
    ) {
        // Create a rule with empty patterns
        let config = make_rule_config(&rule_id, vec![]);
        let result = compile_rules(&[config]);

        // Property: compile_rules SHALL return an error for missing patterns
        prop_assert!(
            result.is_err(),
            "compile_rules should fail for rule '{}' with no patterns",
            rule_id
        );

        let error = result.unwrap_err();

        // Property: error SHALL be MissingPatterns variant
        match &error {
            RuleCompileError::MissingPatterns {
                rule_id: err_rule_id,
            } => {
                // Property: error SHALL contain the rule ID
                prop_assert_eq!(
                    err_rule_id,
                    &rule_id,
                    "Error should contain the rule ID. Expected '{}', got '{}'",
                    rule_id,
                    err_rule_id
                );

                // Property: error message (Display) SHALL contain rule_id
                let error_msg = error.to_string();
                prop_assert!(
                    error_msg.contains(&rule_id),
                    "Error message should contain rule ID '{}'. Got: '{}'",
                    rule_id,
                    error_msg
                );
            }
            other => {
                prop_assert!(
                    false,
                    "Expected MissingPatterns error, got {:?}",
                    other
                );
            }
        }
    }
}

// Feature: diffguard-completion, Property 10: Error Messages Contain Context
// Additional unit tests for specific error message format verification
// **Validates: Requirements 6.1, 6.2, 6.3**

#[test]
fn test_invalid_regex_error_message_format() {
    // Test that the error message follows the expected format:
    // "rule '{rule_id}' has invalid regex '{pattern}': {source}"
    let rule_id = "test.rule";
    let invalid_pattern = "(unclosed";
    let config = make_rule_config(rule_id, vec![invalid_pattern.to_string()]);

    let result = compile_rules(&[config]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    // Verify message format
    assert!(
        error_msg.starts_with(&format!(
            "rule '{}' has invalid regex '{}'",
            rule_id, invalid_pattern
        )),
        "Error message should follow format. Got: '{}'",
        error_msg
    );
}

#[test]
fn test_invalid_glob_error_message_format() {
    // Test that the error message follows the expected format:
    // "rule '{rule_id}' has invalid glob '{glob}': {source}"
    let rule_id = "test.rule";
    let invalid_glob = "[unclosed";
    let config = make_rule_config_with_paths(
        rule_id,
        vec!["valid".to_string()],
        vec![invalid_glob.to_string()],
    );

    let result = compile_rules(&[config]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    // Verify message format
    assert!(
        error_msg.starts_with(&format!(
            "rule '{}' has invalid glob '{}'",
            rule_id, invalid_glob
        )),
        "Error message should follow format. Got: '{}'",
        error_msg
    );
}

#[test]
fn test_missing_patterns_error_message_format() {
    // Test that the error message follows the expected format:
    // "rule '{rule_id}' has no patterns"
    let rule_id = "test.rule";
    let config = make_rule_config(rule_id, vec![]);

    let result = compile_rules(&[config]);
    assert!(result.is_err());

    let error = result.unwrap_err();
    let error_msg = error.to_string();

    // Verify exact message format
    assert_eq!(
        error_msg,
        format!("rule '{}' has no patterns", rule_id),
        "Error message should match expected format"
    );
}

// ==================== Property: Evaluation Determinism ====================

use diffguard_domain::{evaluate_lines, InputLine};

/// Strategy to generate valid input lines for evaluation
fn input_line_strategy() -> impl Strategy<Value = InputLine> {
    (
        prop::string::string_regex("[a-zA-Z_][a-zA-Z0-9_/]{0,30}\\.[a-z]{1,4}")
            .expect("valid regex"),
        1u32..1000,
        prop::string::string_regex("[a-zA-Z0-9_ .(){}\\[\\];:,<>=+\\-*/&|!\"'#@$%^~`\\\\]{0,100}")
            .expect("valid regex"),
    )
        .prop_map(|(path, line, content)| InputLine {
            path,
            line,
            content,
        })
}

/// Strategy to generate valid rule configs that will compile successfully
fn valid_rule_config_strategy() -> impl Strategy<Value = RuleConfig> {
    (
        rule_id_strategy(),
        prop::sample::select(&[Severity::Info, Severity::Warn, Severity::Error]),
        prop::string::string_regex("[a-zA-Z ]{1,50}").expect("valid regex"),
        // Use simple, valid regex patterns
        prop::collection::vec(
            prop::sample::select(&["test", "foo", "bar", "\\w+", "[a-z]+", "hello"]),
            1..3,
        ),
    )
        .prop_map(|(id, severity, message, patterns)| RuleConfig {
            id,
            severity,
            message,
            languages: vec![],
            patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    // Feature: comprehensive-test-coverage, Property: Evaluation Determinism
    // For any given input (lines + rules), calling evaluate_lines twice
    // SHALL produce identical results.
    // **Validates: Requirements 7.1**
    #[test]
    fn property_evaluation_determinism(
        lines in prop::collection::vec(input_line_strategy(), 1..10),
        rule_config in valid_rule_config_strategy(),
    ) {
        // Compile the rule
        let compiled = compile_rules(&[rule_config]);
        prop_assume!(compiled.is_ok());
        let rules = compiled.unwrap();

        // Evaluate twice with the same input
        let result1 = evaluate_lines(lines.clone(), &rules, 100);
        let result2 = evaluate_lines(lines, &rules, 100);

        // Property: Both evaluations should produce identical results
        prop_assert_eq!(
            result1.findings.len(),
            result2.findings.len(),
            "Findings count should be identical"
        );
        prop_assert_eq!(
            result1.counts,
            result2.counts,
            "Verdict counts should be identical"
        );
        prop_assert_eq!(
            result1.files_scanned,
            result2.files_scanned,
            "Files scanned should be identical"
        );
        prop_assert_eq!(
            result1.lines_scanned,
            result2.lines_scanned,
            "Lines scanned should be identical"
        );

        // Compare each finding
        for (f1, f2) in result1.findings.iter().zip(result2.findings.iter()) {
            prop_assert_eq!(&f1.rule_id, &f2.rule_id, "Rule IDs should match");
            prop_assert_eq!(f1.severity, f2.severity, "Severities should match");
            prop_assert_eq!(&f1.path, &f2.path, "Paths should match");
            prop_assert_eq!(f1.line, f2.line, "Line numbers should match");
        }
    }

    // Feature: comprehensive-test-coverage, Property: Valid Configs Always Compile
    // For any RuleConfig with valid regex patterns and globs,
    // compile_rules SHALL succeed.
    // **Validates: Requirements 7.2**
    #[test]
    fn property_valid_configs_compile(
        rule_config in valid_rule_config_strategy(),
    ) {
        let result = compile_rules(&[rule_config]);
        prop_assert!(
            result.is_ok(),
            "Valid rule configs should always compile, but got error: {:?}",
            result.err()
        );
    }

    // Feature: comprehensive-test-coverage, Property: Counts Match Findings
    // The verdict counts SHALL always match the actual severity distribution
    // of the findings.
    // **Validates: Requirements 7.3**
    #[test]
    fn property_counts_match_findings(
        lines in prop::collection::vec(input_line_strategy(), 1..20),
        rule_config in valid_rule_config_strategy(),
    ) {
        let compiled = compile_rules(&[rule_config]);
        prop_assume!(compiled.is_ok());
        let rules = compiled.unwrap();

        let result = evaluate_lines(lines, &rules, 1000);

        // Add truncated findings to the counts (they were counted but not stored)
        // Note: truncated_findings are not broken down by severity,
        // so we check that counts >= findings counts
        let total_counted = result.counts.info + result.counts.warn + result.counts.error;
        let total_findings = result.findings.len() as u32 + result.truncated_findings;

        prop_assert_eq!(
            total_counted,
            total_findings,
            "Total counts ({}) should equal findings ({}) + truncated ({})",
            total_counted,
            result.findings.len(),
            result.truncated_findings
        );
    }

    // Feature: comprehensive-test-coverage, Property: Max Findings Respected
    // The number of stored findings SHALL never exceed max_findings.
    // **Validates: Requirements 7.4**
    #[test]
    fn property_max_findings_respected(
        lines in prop::collection::vec(input_line_strategy(), 10..50),
        max_findings in 1usize..20,
    ) {
        // Create a rule that matches many things
        let rule = RuleConfig {
            id: "test.any".to_string(),
            severity: Severity::Warn,
            message: "matched".to_string(),
            languages: vec![],
            patterns: vec![".*".to_string()], // Match everything
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
        };

        let compiled = compile_rules(&[rule]).expect("rule should compile");
        let result = evaluate_lines(lines, &compiled, max_findings);

        // Property: findings.len() <= max_findings
        prop_assert!(
            result.findings.len() <= max_findings,
            "Findings count ({}) should not exceed max_findings ({})",
            result.findings.len(),
            max_findings
        );
    }

    // Feature: comprehensive-test-coverage, Property: Lines Scanned Equals Input
    // lines_scanned SHALL equal the number of input lines.
    // **Validates: Requirements 7.5**
    #[test]
    fn property_lines_scanned_equals_input(
        lines in prop::collection::vec(input_line_strategy(), 1..50),
    ) {
        let rules = vec![]; // No rules - just counting
        let result = evaluate_lines(lines.clone(), &rules, 100);

        prop_assert_eq!(
            result.lines_scanned as usize,
            lines.len(),
            "lines_scanned ({}) should equal input lines count ({})",
            result.lines_scanned,
            lines.len()
        );
    }
}

// ==================== Property: Preprocessing Length Preservation ====================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: comprehensive-test-coverage, Property: Preprocessing Length Preservation
    // For any valid UTF-8 input, the preprocessor output length SHALL equal
    // the input length.
    // **Validates: Requirements 8.1**
    #[test]
    fn property_preprocessing_preserves_length_all_languages(
        line in prop::string::string_regex("[a-zA-Z0-9_\"'`#/ ]{0,100}").expect("valid regex"),
        lang in prop::sample::select(&[
            Language::Rust,
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Ruby,
            Language::C,
            Language::Cpp,
            Language::CSharp,
            Language::Java,
            Language::Kotlin,
            Language::Unknown,
        ]),
        mask_comments in prop::bool::ANY,
        mask_strings in prop::bool::ANY,
    ) {
        let opts = PreprocessOptions {
            mask_comments,
            mask_strings,
        };
        let mut preprocessor = Preprocessor::with_language(opts, lang);
        let result = preprocessor.sanitize_line(&line);

        prop_assert_eq!(
            result.len(),
            line.len(),
            "Output length ({}) should equal input length ({}) for language {:?}",
            result.len(),
            line.len(),
            lang
        );
    }

    // Feature: comprehensive-test-coverage, Property: Preprocessing Stability
    // Preprocessing with no options enabled SHALL return the original line unchanged.
    // **Validates: Requirements 8.2**
    #[test]
    fn property_no_masking_returns_unchanged(
        line in prop::string::string_regex("[a-zA-Z0-9_\"'`#/ ]{0,100}").expect("valid regex"),
        lang in prop::sample::select(&[
            Language::Rust,
            Language::Python,
            Language::JavaScript,
            Language::TypeScript,
            Language::Go,
            Language::Ruby,
            Language::Unknown,
        ]),
    ) {
        let mut preprocessor = Preprocessor::with_language(PreprocessOptions::none(), lang);
        let result = preprocessor.sanitize_line(&line);

        prop_assert_eq!(
            &result,
            &line,
            "With no masking, output should equal input"
        );
    }

    // Feature: comprehensive-test-coverage, Property: Preprocessing Idempotence (Comments)
    // Applying comment masking twice to a line that contains only comments
    // SHALL produce the same result (all spaces).
    // **Validates: Requirements 8.3**
    #[test]
    fn property_comment_masking_idempotent(
        comment_content in prop::string::string_regex("[a-zA-Z0-9_ ]{0,50}").expect("valid regex"),
    ) {
        // Create a line that is entirely a comment
        let line = format!("// {}", comment_content);
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_only(),
            Language::Rust,
        );

        let result1 = preprocessor.sanitize_line(&line);
        preprocessor.reset();
        let result2 = preprocessor.sanitize_line(&result1);

        // After first pass, line should be all spaces (comment masked)
        // After second pass, result should be unchanged (already all spaces)
        prop_assert_eq!(
            &result1,
            &result2,
            "Comment masking should be idempotent"
        );
    }

    // Feature: comprehensive-test-coverage, Property: Preprocessing Consistency Across Resets
    // After reset(), preprocessing the same line should produce the same result.
    // **Validates: Requirements 8.4**
    #[test]
    fn property_reset_produces_consistent_results(
        line in prop::string::string_regex("[a-zA-Z0-9_\"'`#/ ]{0,100}").expect("valid regex"),
        lang in prop::sample::select(&[
            Language::Python,
            Language::JavaScript,
            Language::Go,
        ]),
    ) {
        let mut preprocessor = Preprocessor::with_language(
            PreprocessOptions::comments_and_strings(),
            lang,
        );

        let result1 = preprocessor.sanitize_line(&line);
        preprocessor.reset();
        let result2 = preprocessor.sanitize_line(&line);

        prop_assert_eq!(
            &result1,
            &result2,
            "After reset, same line should produce same result"
        );
    }
}

// ==================== Property: Rule Application Correctness ====================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    // Feature: comprehensive-test-coverage, Property: Empty Rules Produce No Findings
    // With no rules, evaluate_lines SHALL produce no findings.
    // **Validates: Requirements 9.1**
    #[test]
    fn property_no_rules_no_findings(
        lines in prop::collection::vec(input_line_strategy(), 1..20),
    ) {
        let rules: Vec<diffguard_domain::CompiledRule> = vec![];
        let result = evaluate_lines(lines, &rules, 100);

        prop_assert!(
            result.findings.is_empty(),
            "With no rules, there should be no findings"
        );
        prop_assert_eq!(result.counts.info, 0);
        prop_assert_eq!(result.counts.warn, 0);
        prop_assert_eq!(result.counts.error, 0);
    }

    // Feature: comprehensive-test-coverage, Property: Empty Lines Produce No Findings
    // With no input lines, evaluate_lines SHALL produce no findings.
    // **Validates: Requirements 9.2**
    #[test]
    fn property_no_lines_no_findings(
        rule_config in valid_rule_config_strategy(),
    ) {
        let compiled = compile_rules(&[rule_config]);
        prop_assume!(compiled.is_ok());
        let rules = compiled.unwrap();

        let lines: Vec<InputLine> = vec![];
        let result = evaluate_lines(lines, &rules, 100);

        prop_assert!(
            result.findings.is_empty(),
            "With no input lines, there should be no findings"
        );
        prop_assert_eq!(result.lines_scanned, 0);
    }
}
