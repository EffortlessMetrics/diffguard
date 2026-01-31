//! Domain logic: preprocessing + rule evaluation.
//!
//! This crate is designed to be I/O-free and highly testable.

pub mod evaluate;
pub mod preprocess;
pub mod rules;

pub use evaluate::{evaluate_lines, Evaluation, InputLine};
pub use preprocess::{PreprocessOptions, Preprocessor};
pub use rules::{compile_rules, CompiledRule, RuleCompileError};
