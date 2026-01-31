//! Unified diff parsing.
//!
//! This crate parses `git diff` style unified diffs and extracts added/changed lines.

mod unified;

pub use unified::{parse_unified_diff, ChangeKind, DiffLine, DiffParseError, DiffStats};
