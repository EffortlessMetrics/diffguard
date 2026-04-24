# ADR-2026-001: Add #[must_use] to suppression parsing functions

## Status
Accepted

## Context
Issue #307 reported that `parse_suppression` and `parse_suppression_in_comments` in `crates/diffguard-domain/src/suppression.rs` lacked the `#[must_use]` attribute despite returning `Option<Suppression>`. Callers who ignore the return value would silently drop suppressions, causing rules to fire incorrectly — a semantic correctness bug in a security-critical path.

The `diffguard-domain` crate emphasizes pure/testable functions with no I/O. Suppression parsing is particularly sensitive because it determines whether a finding should be suppressed; silently ignoring a suppression directive means a rule fires when it shouldn't.

## Decision
Add `#[must_use]` to both functions:
- `parse_suppression` (line 70) — parses raw input lines for suppression directives
- `parse_suppression_in_comments` (line 85) — parses only masked comment spans

This follows the established pattern in the codebase (commits `e0c2094`, `f741116`) of annotating pure-returning functions where ignoring the return value is a semantic error.

## Consequences

### Benefits
- Compile-time warning if any caller ignores the suppression result
- Documents intent that callers must act on the suppression directive
- Aligns with the crate's pure-function philosophy — no side effects, return value is the sole output

### Trade-offs / Risks
- Slight verbosity for callers that intentionally ignore the result (e.g., in tests validating malformed input)
- `#[allow(clippy::must_use_candidate)]` could be used if the false-positive rate becomes problematic, but no such cases were found during verification

## Alternatives Considered

1. **Document in doc comment only** — Rejected because documentation is advisory; `#[must_use]` enforces at compile time
2. **Wrap return in a type that implements Drop** — Rejected as overly complex for a simple lint-level concern
3. **No action (leave as-is)** — Rejected because ignoring `Option<Suppression>` is a semantic correctness bug that causes false positive rule violations

## Resolution
This ADR documents the fix that was already merged in commit `3e1d9e1` (PR #543) resolving issue #307. No further implementation is required.

## Related Commits
- `3e1d9e1` — Add #[must_use] to parse_suppression functions (#543) — Fixes #307
- `e0c2094` — fix: add #[must_use] to resolve(), suppresses(), builder structs (#532)
- `f741116` — fix(diffguard-lsp): add #[must_use] to find_rule (issue #519) (#529)
