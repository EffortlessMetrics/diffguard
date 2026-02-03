//! Domain logic: preprocessing + rule evaluation.
//!
//! This crate is designed to be I/O-free and highly testable.

pub mod evaluate;
pub mod preprocess;
pub mod rules;
pub mod suppression;

pub use evaluate::{evaluate_lines, Evaluation, InputLine};
pub use preprocess::{Language, PreprocessOptions, Preprocessor};
pub use rules::{compile_rules, detect_language, CompiledRule, RuleCompileError};
pub use suppression::{
    parse_suppression, EffectiveSuppressions, Suppression, SuppressionKind, SuppressionTracker,
};
