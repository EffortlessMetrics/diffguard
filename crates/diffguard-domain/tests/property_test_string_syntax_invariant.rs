//! Property-based tests for the string_syntax() invariant after removing
//! the redundant Language::Yaml | Language::Toml | Language::Json match arm.
//!
//! Issue: #515 - preprocess.rs: redundant Yaml/Toml/Json match arms + wildcard — duplicate coverage
//! Work Item: work-65ff3da7
//!
//! Key invariant: Yaml, Toml, and Json languages must return StringSyntax::CStyle
//! even though they are now handled by the wildcard `_ => StringSyntax::CStyle`.

use diffguard_domain::preprocess::{Language, StringSyntax};
use proptest::prelude::*;

proptest! {
    #[test]
    fn all_languages_return_valid_string_syntax(lang in prop_oneof![
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
        Just(Language::Unknown)
    ]) {
        // Should not panic - this is the main property
        let _syntax = lang.string_syntax();
    }
}

/// Property 2: Yaml, Toml, and Json MUST return CStyle.
/// This is the core invariant that must hold after removing the redundant match arm.
/// If this fails, the wildcard coverage is broken.
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

proptest! {
    #[test]
    fn yaml_aliases_return_cstyle(alias in prop_oneof![
        Just("yaml"), Just("yml"), Just("YAML"), Just("YML"),
        Just("Yaml"), Just("Yml"), Just("YAM"), Just("ymL")
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
        Just("json"), Just("jsonc"), Just("json5"),
        Just("JSON"), Just("JSONC"), Just("JSON5"),
        Just("Json"), Just("Jsonc"), Just("Json5")
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
fn toml_string_parse_returns_cstyle() {
    let lang: Language = "toml".parse().unwrap();
    assert_eq!(
        lang.string_syntax(),
        StringSyntax::CStyle,
        "Parsed 'toml' should give Language::Toml which returns CStyle"
    );
}

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

proptest! {
    #[test]
    fn non_cstyle_languages_do_not_return_cstyle(lang in prop_oneof![
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

/// Property 7: Each non-CStyle language returns its expected unique syntax.
#[test]
fn each_non_cstyle_language_returns_correct_syntax() {
    // These languages have specific string syntax that is NOT CStyle
    assert_eq!(Language::Rust.string_syntax(), StringSyntax::Rust);
    assert_eq!(Language::Python.string_syntax(), StringSyntax::Python);
    assert_eq!(
        Language::JavaScript.string_syntax(),
        StringSyntax::JavaScript
    );
    assert_eq!(
        Language::TypeScript.string_syntax(),
        StringSyntax::JavaScript
    ); // Same as JS
    assert_eq!(Language::Ruby.string_syntax(), StringSyntax::JavaScript); // Same as JS
    assert_eq!(Language::Go.string_syntax(), StringSyntax::Go);
    assert_eq!(Language::Shell.string_syntax(), StringSyntax::Shell);
    assert_eq!(Language::Swift.string_syntax(), StringSyntax::SwiftScala);
    assert_eq!(Language::Scala.string_syntax(), StringSyntax::SwiftScala);
    assert_eq!(Language::Sql.string_syntax(), StringSyntax::Sql);
    assert_eq!(Language::Xml.string_syntax(), StringSyntax::Xml);
    assert_eq!(Language::Php.string_syntax(), StringSyntax::Php);
}
