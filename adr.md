# ADR-0059: Add #[must_use] to parse_suppression() in diffguard-domain

## Status
Accepted (already implemented in PR #543)

## Context

Issue #364 reported that `parse_suppression(line: &str) -> Option<Suppression>` in `diffguard-domain` is a `#[must_use]` candidate because callers who discard the return value would silently drop suppression directives, causing rules to fire when they should have been suppressed. The function is `pub` and exported via `pub use suppression::parse_suppression` in `lib.rs:22` for external use.

The crate runs with `-W clippy::pedantic` which enables `must_use_candidate` linting. The function returns `Option<Suppression>` and has no side effects — discarding it is always a bug.

## Decision

Add `#[must_use]` to both suppression-parsing functions:
- `parse_suppression(line: &str) -> Option<Suppression>` at `suppression.rs:70`
- `parse_suppression_in_comments(line: &str, masked_comments: &MaskedComments) -> Option<Suppression>` at `suppression.rs:85`

This was implemented in PR #543 (commit `3e1d9e1`).

## Consequences

**Benefits:**
- Compile-time enforcement prevents silent suppression drops
- Consistent with diffguard's deterministic-behavior design goal (suppression directives must always be acted upon)
- Consistent with `diffguard-domain` being a pure-logic crate with no I/O fallback where return values must be handled
- Both sibling functions now carry `#[must_use]`, making the API contract explicit

**Tradeoffs / Risks:**
- Fuzz harness uses `let _ = parse_suppression(...)` intentionally (to test non-panicking behavior). This pattern correctly silences the warning and is the intended use of `let _ =`.
- No runtime cost — `#[must_use]` only produces a compile-time warning
- Non-breaking change — adding `#[must_use]` to an existing function is always backwards-compatible

## Alternatives Considered

1. **Do nothing (leave as-is)**: Rejected because clippy pedantic's `must_use_candidate` explicitly warns about this pattern. Leaving it unwarned means external callers could silently misuse the API.

2. **Rename function to indicate must-use (e.g., `parse_suppression_must_use`)**: Rejected because renaming is a breaking change for external callers and the `#[must_use]` attribute achieves the same goal without API churn.

3. **Document in docstring only**: Rejected because documentation is advisory and not enforced. `#[must_use]` produces a hard compiler warning that cannot be ignored without explicit `let _ =`.

## Related Decisions

- ADR-0057: Clippy pedantic enforcement in CI
- PR #543: Add #[must_use] to parse_suppression functions

## Implementation Note

The fix was applied in PR #543. The `#[must_use]` attribute is confirmed present at line 70 of `suppression.rs`. Issue #364 remains open on GitHub and should be closed by a maintainer referencing PR #543.
