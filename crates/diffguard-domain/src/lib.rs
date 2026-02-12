//! Domain logic: preprocessing + rule evaluation.
//!
//! This crate is designed to be I/O-free and highly testable.

pub mod evaluate;
pub mod preprocess;
pub mod rules;
pub mod suppression;

pub use evaluate::{Evaluation, InputLine, evaluate_lines};
pub use preprocess::{Language, PreprocessOptions, Preprocessor};
pub use rules::{CompiledRule, RuleCompileError, compile_rules, detect_language};
pub use suppression::{
    EffectiveSuppressions, Suppression, SuppressionKind, SuppressionTracker, parse_suppression,
};
