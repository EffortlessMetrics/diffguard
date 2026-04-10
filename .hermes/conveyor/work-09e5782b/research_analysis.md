# Research Analysis: Add --no-color flag to suppress ANSI output in CI logs

## Issue Summary
- **Issue:** #46 — Add a `--no-color` flag to suppress ANSI output in CI logs
- **URL:** https://github.com/EffortlessMetrics/diffguard/issues/46
- **Priority:** P1 (FULL pipeline)

## Relevant Codebase Areas

### Key Files
- `crates/diffguard/src/main.rs` — CLI entry point using `clap` derive macros
- Line 695-712: `init_logging()` function initializes `tracing_subscriber`
- Line 697: `use tracing_subscriber::{EnvFilter, fmt, prelude::*};`
- Line 709-710: `tracing_subscriber::registry().with(fmt::layer().with_writer(std::io::stderr))`

### Existing Patterns
The codebase uses `tracing_subscriber::fmt::layer()` for structured logging. The layer writes to stderr. Coloring is controlled via `.with_ansi(bool)` on the layer builder. Clap 4.x has built-in support for `--color` flag via `Color` enum.

### What Needs to Change
The `init_logging()` function at line 695 takes `verbose: bool` and `debug: bool` but no color control. We need to:
1. Add a `--color` flag to the global `Cli` struct
2. Pass color preference to `init_logging()`
3. Configure `fmt::layer().with_ansi(...)` based on the flag

### Clap Color Support
Clap 4.x provides `Color::Never`, `Color::Always`, `Color::Auto` via `#[arg(long, value_enum)]`. When `Color::Never` is set, clap itself won't color `--help` output, but we also need to control `tracing_subscriber` output.

## Dependencies
- `clap` (already in dependencies, version 4.5.57)
- `tracing-subscriber` (transitive dependency via `anyhow`/`tracing`)

## Constraints
- MSRV: Rust 1.92
- Must not break existing exit codes
- Domain crates must remain I/O-free (color is CLI/presentation concern, fine in diffguard crate)

## Key Findings
1. **clap 4.x has built-in `Color` enum:** We can use `clap::Color` directly for the `--color` flag
2. **tracing_subscriber fmt layer supports `with_ansi(bool)`:** This controls ANSI color output
3. **Standard pattern:** `--color=never` for CI, `--color=always` for interactive, `--color=auto` for auto-detect
4. **NO_COLOR env var:** Industry standard; many tools also respect `NO_COLOR` environment variable

## Approach Options
1. **Simple `--no-color` flag:** Sets color=never, ignores `NO_COLOR` env
2. **Full `--color <never|always|auto>`:** More flexible, idiomatic clap

Option 2 is better as it's the standard Rust CLI pattern and more flexible.

## Verification Plan
1. Test `--no-color` / `--color=never` suppresses colors
2. Test `--color=always` forces colors
3. Test `--color=auto` respects terminal detection
4. Run full CI suite

## Status: Ready for implementation
