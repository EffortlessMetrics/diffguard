# Specification: `--color` Flag for DiffGuard

## Feature / Behavior Description

Add a `--color <never|always|auto>` global flag to the diffguard CLI that controls whether ANSI color codes are emitted in logging output.

- **`--color=never`** — Suppress all ANSI color codes regardless of terminal type. Use this for CI log files.
- **`--color=always`** — Emit ANSI color codes even when output is piped to a file. Use this for screenshot/diff tools.
- **`--color=auto`** (default) — Emit ANSI codes only when `stderr` is connected to a terminal.

When not specified, behavior defaults to `auto` (existing behavior unchanged).

The `NO_COLOR=1` environment variable is respected by the implementation (not clap) when `--color` is not explicitly passed or when `--color=auto` is set — per the no-color.org standard.

## Acceptance Criteria

1. **`--color=never`** flag is recognized and produces zero ANSI escape codes in all output
2. **`--color=always`** flag is recognized and forces ANSI codes even when output is piped
3. **`--color=auto`** flag (or omission) produces ANSI codes only in TTY context
4. `NO_COLOR=1` environment variable suppresses colors without any CLI flag
5. `--help` text correctly documents all three options
6. The flag is global — works with all subcommands (`check`, `rules`, `explain`, `sarif`, etc.)
7. No existing behavior changes for users who don't specify `--color`

## Non-Goals

- This does not affect SARIF/JSON/JUnit/XML structured output (those don't contain ANSI codes)
- This does not add color to non-logging output (e.g., rule text rendering)
- This does not persist color preference across invocations

## Dependencies

- `clap` 4.5.57+ (already in dependency tree, `ColorChoice` is built-in)
- `tracing-subscriber` (already in dependency tree, `.with_ansi(bool)` is stable API)
- `std::io::IsTerminal` (MSRV 1.70 — stable in std)

## Test Plan

1. **Unit test:** `init_logging(verbose, debug, Some(ColorChoice::Never))` produces `use_ansi = false`
2. **Unit test:** `init_logging(verbose, debug, Some(ColorChoice::Always))` produces `use_ansi = true`
3. **Unit test:** `init_logging(verbose, debug, Some(ColorChoice::Auto))` produces `use_ansi = is_terminal()`
4. **CLI integration test:** `--color=never --check` produces no ANSI codes in output
5. **CLI integration test:** `--color=always --check` piped to file produces ANSI codes
