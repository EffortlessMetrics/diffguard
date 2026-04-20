//! Property tests for verifying the string_syntax() invariant after removing
//! the redundant Language::Yaml | Language::Toml | Language::Json match arm.
//!
//! Key invariant: Yaml, Toml, and Json languages must return StringSyntax::CStyle
//! even though they are now handled by the wildcard `_ => StringSyntax::CStyle`.

use proptest::prelude::*;
use diffguard_domain::preprocess::{Language, StringSyntax};

/// Property 1: All Language variants return a valid StringSyntax
/// This verifies no panics occur and a valid syntax is returned for any language.
prop_compose! {
    fn all_languages() -> Language {
        prop_oneof![
            Just(Language::Rust),
            Just(Language::Python),
            Just(Language::JavaScript),
            Just(Language::TypeScript),
            Just(Language::Go),
            Just(Language::Ruby),
            Just(Language::C),
            Just(Language::Cpp),
            Just(Language::CSharp),
            Just(Language::Java),
            Just(Language::Kotlin),
            Just(Language::Shell),
            Just(Language::Swift),
            Just(Language::Scala),
            Just(Language::Sql),
            Just(Language::Xml),
            Just(Language::Php),
            Just(Language::Yaml),
            Just(Language::Toml),
            Just(Language::Json),
            Just(Language::Unknown),
        ]
    }
}

proptest! {
    /// Property: All Language variants produce a valid StringSyntax without panicking.
    /// This is a sanity check that the match is exhaustive and doesn't panic.
    #[test]
    fn all_languages_return_valid_string_syntax(lang in all_languages()) {
        // Should not panic - this is the main property
        let syntax = lang.string_syntax();
        
        // Verify it's a valid variant (enum is not corrupted)
        match syntax {
            StringSyntax::CStyle |
            StringSyntax::Rust |
            StringSyntax::Python |
            StringSyntax::JavaScript |
            StringSyntax::Go |
            StringSyntax::Shell |
            StringSyntax::SwiftScala |
            StringSyntax::Sql |
            StringSyntax::Xml |
            StringSyntax::Php => {}
        }
    }
}

/// Property 2: Yaml, Toml, and Json MUST return CStyle
/// This is the core invariant that must hold after removing the redundant match arm.
#[test]
fn yaml_returns_cstyle() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "Yaml must return CStyle (invariant after removing redundant match arm)"
    );
}

#[test]
fn toml_returns_cstyle() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "Toml must return CStyle (invariant after removing redundant match arm)"
    );
}

#[test]
fn json_returns_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Json must return CStyle (invariant after removing redundant match arm)"
    );
}

/// Property 3: Parsing language strings and then calling string_syntax()
/// should return CStyle for yaml/toml/json aliases.
/// This ensures roundtrip: str -> Language -> StringSyntax works correctly.
proptest! {
    #[test]
    fn yaml_aliases_return_cstyle(alias in prop_oneof![
        "yaml",
        "yml",
        "YAML",
        "YML",
        "Yaml",
        "Yml",
    ]) {
        let lang: Language = alias.parse().unwrap();
        prop_assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "Parsed '{}' should give Language::Yaml which returns CStyle",
            alias
        );
    }
}

proptest! {
    #[test]
    fn json_aliases_return_cstyle(alias in prop_oneof![
        "json",
        "jsonc",
        "json5",
        "JSON",
        "JSONC",
        "JSON5",
        "Json",
        "Jsonc",
        "Json5",
    ]) {
        let lang: Language = alias.parse().unwrap();
        prop_assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "Parsed '{}' should give Language::Json which returns CStyle",
            alias
        );
    }
}

#[test]
fn toml_parsed_returns_cstyle() {
    let lang: Language = "toml".parse().unwrap();
    assert_eq!(
        lang.string_syntax(),
        StringSyntax::CStyle,
        "Parsed 'toml' should give Language::Toml which returns CStyle"
    );
}

/// Property 4: All "C-style-like" languages should return CStyle
/// These are: C, Cpp, CSharp, Java, Kotlin, Unknown, Yaml, Toml, Json
proptest! {
    #[test]
    fn cstyle_languages_return_cstyle(lang in prop_oneof![
        Just(Language::C),
        Just(Language::Cpp),
        Just(Language::CSharp),
        Just(Language::Java),
        Just(Language::Kotlin),
        Just(Language::Unknown),
        Just(Language::Yaml),
        Just(Language::Toml),
        Just(Language::Json),
    ]) {
        prop_assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle",
            lang
        );
    }
}

/// Property 5: Non-CStyle languages don't return CStyle unexpectedly
proptest! {
    #[test]
    fn non_cstyle_languages_return_correct_syntax(lang in prop_oneof![
        Just(Language::Rust),
        Just(Language::Python),
        Just(Language::JavaScript),
        Just(Language::TypeScript),
        Just(Language::Go),
        Just(Language::Ruby),
        Just(Language::Shell),
        Just(Language::Swift),
        Just(Language::Scala),
        Just(Language::Sql),
        Just(Language::Xml),
        Just(Language::Php),
    ]) {
        let syntax = lang.string_syntax();
        prop_assert_ne!(
            syntax,
            StringSyntax::CStyle,
            "{:?} should NOT return CStyle",
            lang
        );
    }
}
