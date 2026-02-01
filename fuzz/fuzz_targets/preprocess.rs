//! Fuzz target for preprocessor with language-aware fuzzing.
//!
//! This target exercises the Preprocessor with various languages and
//! input patterns to discover edge cases in comment/string masking.
//!
//! Requirements: 8.1-8.4

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Structured fuzz input for the preprocessor.
#[derive(Arbitrary, Debug)]
struct PreprocessInput {
    /// Language to use for preprocessing.
    language: FuzzLanguage,
    /// Options for preprocessing.
    options: FuzzOptions,
    /// Lines to preprocess.
    lines: Vec<String>,
}

/// Fuzz-friendly language enum.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Ruby,
    C,
    Cpp,
    CSharp,
    Java,
    Kotlin,
    Unknown,
}

impl From<FuzzLanguage> for Language {
    fn from(lang: FuzzLanguage) -> Self {
        match lang {
            FuzzLanguage::Rust => Language::Rust,
            FuzzLanguage::Python => Language::Python,
            FuzzLanguage::JavaScript => Language::JavaScript,
            FuzzLanguage::TypeScript => Language::TypeScript,
            FuzzLanguage::Go => Language::Go,
            FuzzLanguage::Ruby => Language::Ruby,
            FuzzLanguage::C => Language::C,
            FuzzLanguage::Cpp => Language::Cpp,
            FuzzLanguage::CSharp => Language::CSharp,
            FuzzLanguage::Java => Language::Java,
            FuzzLanguage::Kotlin => Language::Kotlin,
            FuzzLanguage::Unknown => Language::Unknown,
        }
    }
}

/// Fuzz-friendly preprocessing options.
#[derive(Arbitrary, Debug)]
struct FuzzOptions {
    mask_comments: bool,
    mask_strings: bool,
}

impl From<FuzzOptions> for PreprocessOptions {
    fn from(opts: FuzzOptions) -> Self {
        PreprocessOptions {
            mask_comments: opts.mask_comments,
            mask_strings: opts.mask_strings,
        }
    }
}

fuzz_target!(|input: PreprocessInput| {
    let language = Language::from(input.language);
    let options = PreprocessOptions::from(input.options);

    let mut preprocessor = Preprocessor::with_language(options, language);

    // Process multiple lines to exercise multi-line state.
    for line in input.lines.iter().take(32) {
        let result = preprocessor.sanitize_line(line);

        // Property: output length must equal input length
        assert_eq!(
            result.len(),
            line.len(),
            "Output length ({}) must equal input length ({}) for language {:?}",
            result.len(),
            line.len(),
            input.language
        );
    }

    // Test reset behavior
    preprocessor.reset();

    // Process again after reset to ensure consistent behavior
    for line in input.lines.iter().take(16) {
        let _ = preprocessor.sanitize_line(line);
    }

    // Test language switching
    preprocessor.set_language(Language::Python);
    for line in input.lines.iter().take(8) {
        let result = preprocessor.sanitize_line(line);
        assert_eq!(
            result.len(),
            line.len(),
            "Length must be preserved after language switch"
        );
    }
});

