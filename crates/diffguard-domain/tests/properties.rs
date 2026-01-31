//! Property-based tests for diffguard-domain
//!
//! Feature: diffguard-completion

use proptest::prelude::*;
use std::path::Path;

use diffguard_domain::detect_language;

// Known extensions and their expected language mappings
// Based on Requirements 1.1-1.12
const KNOWN_EXTENSIONS: &[(&str, &str)] = &[
    // Rust (not in task list but in implementation)
    ("rs", "rust"),
    // Python - Requirement 1.1
    ("py", "python"),
    // JavaScript - Requirements 1.2, 1.5
    ("js", "javascript"),
    ("jsx", "javascript"),
    // TypeScript - Requirements 1.3, 1.4
    ("ts", "typescript"),
    ("tsx", "typescript"),
    // Go - Requirement 1.6
    ("go", "go"),
    // Java - Requirement 1.7
    ("java", "java"),
    // Kotlin - Requirement 1.8
    ("kt", "kotlin"),
    // Ruby - Requirement 1.9
    ("rb", "ruby"),
    // C - Requirement 1.10
    ("c", "c"),
    ("h", "c"),
    // C++ - Requirement 1.11
    ("cpp", "cpp"),
    ("cc", "cpp"),
    ("cxx", "cpp"),
    ("hpp", "cpp"),
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
