# ADR-001: Use Display Format for CLI Error Output

**Status:** Accepted

**Date:** 2026-04-09

**Work Item:** work-cac2f34f

---

## Context

The CLI error handler in `crates/diffguard/src/main.rs` line 642 uses debug format (`{err:?}`) when printing top-level errors to stderr:

```rust
Err(err) => {
    eprintln!("{err:?}");
    std::process::ExitCode::from(1)
}
```

This produces verbose, implementation-focused output (e.g., `Error: kind: "io"`) instead of clean user-facing messages. The `diffguard` crate is documented as the "I/O boundary" — the only crate that performs file I/O, subprocess calls, and environment variable access — and serves as the user-facing interface. Its CLAUDE.md explicitly identifies exit codes as a "Stable API" contract, but error *messages* to stderr are user-facing output that should be human-readable.

The error type is `anyhow::Error` (returned by `run_with_args()` which returns `Result<i32>` using `anyhow::Result`). `anyhow::Error` always implements `Display` by design contract — it is intentionally a user-facing error type. The codebase already demonstrates this pattern at line 1990:

```rust
eprintln!("diffguard: catastrophic failure: {err}");
```

---

## Decision

Change line 642 from debug format to display format:

**Before:**
```rust
Err(err) => {
    eprintln!("{err:?}");
    std::process::ExitCode::from(1)
}
```

**After:**
```rust
Err(err) => {
    eprintln!("{err}");
    std::process::ExitCode::from(1)
}
```

Exit code behavior remains unchanged (`1` for errors — the Stable API contract is preserved).

---

## Consequences

### Positive
1. **User-facing clarity**: Display format produces human-readable messages without implementation noise
2. **Consistency**: Aligns with the established pattern at line 1990 in the same file
3. **Idiomatic anyhow usage**: `anyhow::Error` is designed for user-facing error messages; Display is the primary trait
4. **Minimal blast radius**: One-line change with zero semantic impact beyond output format

### Negative / Tradeoffs
1. **Scripts relying on debug format break**: Scripts that parse stderr expecting the debug format's `Error(...)` pattern or `Caused by:` chain labels will get different output. However, relying on debug format for stderr parsing is itself an anti-pattern.
2. **Loss of error chain visibility**: Debug format shows the full error chain with `Caused by:` labels. Display format shows only the top-level message. Users who depend on chain information for debugging will receive less detail.

### Neutral
1. **Untested code path**: The `#[cfg(not(test))]` attribute on `main()` means the error arm at line 642 is never executed by the 56 unit tests. This is a pre-existing structural gap, not introduced by this change.

---

## Alternatives Considered

### 1. Keep debug format (`{err:?}`)
**Decision:** Not chosen. Debug format produces implementation-focused output inappropriate for a user-facing CLI tool.

### 2. Add `diffguard: error: {err}` prefix
**Decision:** Not chosen as required, flagged as optional refinement. Adding a `diffguard:` prefix would improve stderr distinguishability for scripts and align with line 1990's pattern. However, the essential fix is the Display vs Debug choice — the prefix is cosmetic polish. The plan review recommended this as a consideration but it is not a blocker.

### 3. Add stderr prefix without changing format
**Decision:** Not chosen. Same rationale as alternative 2 — prefix without Display format change would still produce verbose debug output.

---

## References

- Research Analysis: `research_analysis.md` (prior artifact)
- Verification Comment: `verification_comment.md` (prior artifact)
- Plan Review: `plan_review_comment.md` (prior artifact)
- Vision Alignment: `vision_alignment_comment.md` (prior artifact)
- Fix location: `crates/diffguard/src/main.rs:642`
- Consistency reference: `crates/diffguard/src/main.rs:1990`
- Error type: `anyhow::Error` (confirmed via `use anyhow::{Context, Result, bail}` at line 9)
