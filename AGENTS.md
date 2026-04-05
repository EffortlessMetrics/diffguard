# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Project Overview

**diffguard** is a diff-scoped governance linter for PR automation. It applies rules only to added/changed lines in Git diffs, emitting JSON receipts, Markdown summaries, and GitHub Actions annotations.

## Design Goals

1. **Diff-only scope** - Only lint added/modified lines, not entire files
2. **Deterministic** - Same inputs always produce same outputs (no randomness, stable ordering)
3. **Clean architecture** - I/O at edges, pure logic in core crates

## Common Commands

```bash
cargo build                                          # Build
cargo test --workspace                               # Run all tests
cargo fmt --check                                    # Format check
cargo clippy --workspace --all-targets -- -D warnings # Lint
cargo run -p xtask -- ci                             # Full CI suite
cargo run -p xtask -- schema                         # Generate JSON schemas
cargo run -p diffguard -- check --base origin/main --head HEAD  # Run CLI
cargo mutants                                        # Mutation testing
cargo +nightly fuzz run unified_diff_parser          # Fuzz testing
```

## Architecture

Dependency direction flows downward (CLI depends on app, app depends on domain/diff, all depend on types):

```
diffguard (CLI)          I/O boundary: clap, file I/O, git subprocess, env vars
       │
       ▼
diffguard-core            Use-cases: run_check(), render_markdown_for_receipt(), compute verdicts
       │
       ├────────────────────────┐
       ▼                        ▼
diffguard-domain         diffguard-diff
  Pure business logic      Pure diff parsing
  - rules.rs               - unified.rs
  - evaluate.rs
  - preprocess.rs
       │                        │
       └──────────┬─────────────┘
                  ▼
          diffguard-types
            Pure DTOs (serde + schemars)
```

| Crate | Purpose |
|-------|---------|
| `diffguard-types` | Serializable DTOs, severity/scope enums, built-in rule definitions |
| `diffguard-diff` | Parse unified diff format, handle binary/submodule/rename detection |
| `diffguard-domain` | Compile rules, evaluate lines, preprocess (mask comments/strings) |
| `diffguard-core` | Orchestrate check runs, compute verdicts, render markdown/annotations |
| `diffguard` | CLI binary: arg parsing, config loading, git invocation, file output |
| `xtask` | Repo automation tasks (ci, schema generation) |

## Key Invariants

These are contracts that must be maintained:

- **Exit codes are stable API**: `0`=pass, `1`=tool error, `2`=policy fail, `3`=warn-fail
- **Receipt schemas are versioned** - avoid breaking changes to JSON output structure
- **Domain crates are I/O-free** - `diffguard-diff`, `diffguard-domain`, `diffguard-types` must not use `std::process`, filesystem, or environment variables
- **Diff parsing never panics** - malformed input returns errors, never crashes (fuzz-tested)
- **Language preprocessing is best-effort** - uses C-like syntax heuristics; not a full parser for any language

## Testing

- **Unit tests:** Co-located in source files (`#[cfg(test)]`)
- **Integration tests:** `tests/` directories per crate
- **Snapshot tests:** `insta` crate for output stability
- **Property tests:** `proptest` for generative testing
- **Mutation tests:** `cargo-mutants` (config in `mutants.toml`)
- **Fuzz tests:** `fuzz/fuzz_targets/` - `unified_diff_parser`, `preprocess`, `rule_matcher`

## Extending diffguard

### Adding a new rule config field

1. Add field to `RuleConfig` in `diffguard-types/src/lib.rs`
2. Update `CompiledRule` in `diffguard-domain/src/rules.rs` if needed at compile time
3. Update evaluation logic in `diffguard-domain/src/evaluate.rs`
4. Regenerate schemas: `cargo run -p xtask -- schema`
5. Update `diffguard.toml.example`

### Adding new rule behavior

1. Modify `evaluate_line()` in `diffguard-domain/src/evaluate.rs`
2. Add unit tests in same file
3. Add property tests if behavior is complex
4. Run `cargo mutants` to verify test coverage

### Changes to diff parsing

1. Modify `diffguard-diff/src/unified.rs`
2. Add regression test cases
3. Run fuzz target: `cargo +nightly fuzz run unified_diff_parser`
4. Ensure no panics on malformed input

### Adding CLI flags

1. Add to `Args` struct in `diffguard/src/main.rs`
2. Wire through to `diffguard-core` if it affects orchestration
3. Update `--help` text and any documentation

## Configuration

Rules defined in `diffguard.toml`. See `diffguard.toml.example`. Key fields:
- `patterns`: regex patterns to match
- `paths`/`exclude_paths`: glob-based file filtering
- `ignore_comments`/`ignore_strings`: preprocessor control (best-effort, C-like syntax)
- `languages`: optional language filter (auto-detected from extension)

## MSRV

Rust 1.92 (Minimum Supported Rust Version)
