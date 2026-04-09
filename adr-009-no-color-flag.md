# ADR-009: Add `--color` Flag for CI Log Output Control

**Status:** Accepted

**Date:** 2026-04-09

**Work Item:** work-09e5782b

---

## Context

Issue #46 requests a `--no-color` flag to suppress ANSI color codes in CI log output. Diffguard currently emits colored logging output via `tracing_subscriber`, but CI environments (GitHub Actions, GitLab CI, Jenkins) render ANSI escape codes as raw text, making logs harder to read and parse.

Users need fine-grained control over when colors are emitted, including:
- Forced color (for screenshot/diff tools)
- Forced no-color (for CI logs)
- Auto-detect based on terminal (default behavior)

---

## Decision

Implement `--color <never|always|auto>` as a global CLI flag using clap 4.x's built-in `ColorChoice` enum. Wire the value through to `tracing_subscriber::fmt::layer().with_ansi(bool)`.

**Implementation details:**
1. Add `color: Option<ColorChoice>` field to `Cli` struct with `#[arg(long, value_enum, global = true)]`
2. Modify `init_logging()` signature to accept `color: Option<&ColorChoice>`
3. In `init_logging`, compute `use_ansi: bool` from the color choice, defaulting to `stderr.is_terminal()` for auto
4. Pass `use_ansi` to `fmt::layer().with_ansi(use_ansi)`

**Supported values:**
- `--color=never` → no ANSI regardless of terminal
- `--color=always` → ANSI even when piped
- `--color=auto` (default) → ANSI only when stderr is a terminal

**Environment variable:** The `NO_COLOR=1` environment variable (no-color.org standard) is respected by the implementation when `--color` is not explicitly passed or when `--color=auto` is set — any `NO_COLOR` value suppresses ANSI output regardless of terminal type. Explicit `--color=always` or `--color=never` flags override the `NO_COLOR` env var.

---

## Alternatives Considered

### 1. `--no-color` boolean flag
A simple `--no-color` boolean would require choosing between "never" and "auto" with no way to force colors. The three-value enum is strictly more expressive and follows industry conventions (ripgrep, bat, fd).

### 2. `NO_COLOR` environment variable only
Only respecting `NO_COLOR` without a CLI flag means users cannot force colors in pipeline contexts. The CLI flag is necessary for full control.

### 3. `TERM` environment variable detection
Detecting `TERM=dumb` or similar is less reliable than `is_terminal()` and doesn't give explicit override capability. The chosen approach is simpler and more predictable.

---

## Consequences

**Positive:**
- CI logs become readable without ANSI noise
- Users can force colors when needed
- Default auto-detection preserves existing behavior for terminal users
- Follows established CLI conventions (ripgrep, bat, fd)
- Purely additive — no existing behavior changes

**Negative:**
- Adds a new CLI flag to document
- `is_terminal()` is MSRV 1.70 compatible (stable in std)

**Neutral:**
- The `ColorChoice` enum is handled entirely by clap — no custom parsing needed

---

## Risk Assessment

- **CI compatibility (LOW):** `tracing_subscriber` + clap pattern is well-tested in CI environments
- **Redirection handling (LOW):** `is_terminal()` correctly detects non-TTY output
- **Clap stability (VERY LOW):** `ColorChoice` is stable API in clap 4.x
- **`is_terminal()` MSRV:** `std::io::IsTerminal::is_terminal()` was stabilized in Rust 1.70

---

## Files Affected

- `crates/diffguard/src/main.rs` — add `color` field to `Cli`, modify `init_logging()`
