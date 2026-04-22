# ADR-0538: Add #[must_use] to RuleOverrideMatcher::resolve()

## Status
**Accepted** (retroactive documentation — fix merged in PR #532)

## Context

Issue #538 reported that `RuleOverrideMatcher::resolve()` in `crates/diffguard-domain/src/overrides.rs:108` was missing `#[must_use]`. The return type `ResolvedRuleOverride` carries meaningful state — `enabled: bool` and `severity: Option<Severity>` — and discarding it means callers operate with defaults instead of the configured override.

This is a correctness bug: callers who write `m.resolve(path, &rule.id)` without assigning the result silently lose override configuration.

## Decision

The `#[must_use]` attribute was added to `RuleOverrideMatcher::resolve()` in **PR #532** (commit `e0c2094`). This was the correct decision.

Issue #538 is a duplicate of issue #483, which PR #532 also closed. The fix follows established precedent in the codebase: PR #532 systematically added `#[must_use]` to `resolve()`, `suppresses()`, and builder structs in the same crate.

## Consequences

### Benefits
- Compile-time enforcement prevents callers from silently discarding override state
- Zero runtime cost — `#[must_use]` is purely a compiler lint
- Aligns with Rust idioms for functions returning meaningful results
- Follows systematic `#[must_use]` effort started in PR #532

### Tradeoffs / Risks
- None significant. The attribute has no performance impact and only generates warnings.

### Process Observation
PR #532 closed #483 but failed to close its duplicate #538. Process improvement: when closing a bug as fixed, search for and close any linked duplicates.

## Alternatives Considered

1. **Do nothing** — Accept that callers must read documentation. Rejected: silent semantic bugs from discarded return values are exactly the class of error `#[must_use]` is designed to prevent.

2. **Rename function to signal importance** (e.g., `resolve_and_apply()`). Rejected: renaming is a breaking API change; `#[must_use]` achieves the goal without churn.

3. **Return `()` instead of `ResolvedRuleOverride`** and require callers to call a separate accessor. Rejected: this bifurcates the API and requires more boilerplate at every call site.

## Resolution

Issue #538 is closed as **duplicate of #483**. No new code is required — the fix was already merged in PR #532.
