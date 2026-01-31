//! Unified diff parsing.
//!
//! This crate parses `git diff` style unified diffs and extracts added/changed lines.

mod unified;

pub use unified::{
    // Detection functions for special diff content (Requirements 4.1-4.5)
    is_binary_file,
    is_deleted_file,
    is_mode_change_only,
    is_new_file,
    is_submodule,
    parse_rename_from,
    parse_rename_to,
    parse_unified_diff,
    ChangeKind,
    DiffLine,
    DiffParseError,
    DiffStats,
};
