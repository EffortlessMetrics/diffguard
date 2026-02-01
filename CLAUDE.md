# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**diffguard** is a diff-scoped governance linter for PR automation. It applies rules only to added/changed lines in Git diffs, emitting JSON receipts, Markdown summaries, and GitHub Actions annotations.

## Common Commands

```bash
# Build
cargo build

# Run all tests
cargo test --workspace

# Format check
cargo fmt --check

# Lint (treat warnings as errors)
cargo clippy --workspace --all-targets -- -D warnings

# Full CI suite (fmt + clippy + test)
cargo run -p xtask -- ci

# Generate JSON schemas to schemas/
cargo run -p xtask -- schema

# Run CLI against current diff
cargo run -p diffguard -- check --base origin/main --head HEAD

# Mutation testing
cargo mutants

# Fuzz testing (requires nightly)
cargo +nightly fuzz run unified_diff_parser
```

## Architecture

The workspace follows a layered architecture with I/O pushed to the edges:

```
diffguard (CLI) - thin wrapper, clap parsing, file I/O, git subprocess
    │
    ▼
diffguard-app - orchestration: run_check(), render_markdown()
    │
    ├─► diffguard-domain - I/O-free business logic
    │       rules.rs     - compile RuleConfig → CompiledRule (regex + glob)
    │       evaluate.rs  - match rules against lines, produce findings
    │       preprocess.rs - language-aware comment/string masking
    │
    ├─► diffguard-diff - I/O-free unified diff parsing
    │       unified.rs   - parse git diff output, extract DiffLine items
    │
    └─► diffguard-types - pure DTOs with serde + schemars
            ConfigFile, RuleConfig, CheckReceipt, Finding, Verdict
```

**Key principle:** `diffguard-diff`, `diffguard-domain`, and `diffguard-types` have no I/O, enabling easy unit testing, property testing, and fuzzing.

## Crate Responsibilities

| Crate | Purpose |
|-------|---------|
| `diffguard-types` | Serializable DTOs, severity/scope enums, built-in rule definitions |
| `diffguard-diff` | Parse unified diff format, handle binary/submodule/rename detection |
| `diffguard-domain` | Compile rules, evaluate lines, preprocess (mask comments/strings for 11 languages) |
| `diffguard-app` | Orchestrate check runs, compute verdicts, render markdown/annotations |
| `diffguard` | CLI binary: arg parsing, config loading, git invocation, file output |
| `xtask` | Repo automation tasks (ci, schema generation) |

## Testing

- **Unit tests:** Co-located in source files (`#[cfg(test)]`)
- **Integration tests:** `tests/` directories per crate
- **Snapshot tests:** `insta` crate for output stability
- **Property tests:** `proptest` for generative testing
- **Mutation tests:** `cargo-mutants` (config in `mutants.toml`)
- **Fuzz tests:** Three targets in `fuzz/fuzz_targets/`: `unified_diff_parser`, `preprocess`, `rule_matcher`

## Exit Codes

- `0`: Pass
- `1`: Tool error (I/O, parse, git, config)
- `2`: Policy failure (error-level findings)
- `3`: Warn-level failure (when `fail_on = "warn"`)

## Configuration

Rules are defined in `diffguard.toml`. See `diffguard.toml.example` for format. Key fields:
- `patterns`: regex patterns to match
- `paths`/`exclude_paths`: glob-based file filtering
- `ignore_comments`/`ignore_strings`: preprocessor control
- `languages`: optional language filter (auto-detected from extension)

## MSRV

Rust 1.75 (Minimum Supported Rust Version)
