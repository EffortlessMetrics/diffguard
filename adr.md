# ADR: work-fd366614 — `#[must_use]` on `RuleOverrideMatcher::resolve()`

## Title
ADR-2026-04-27: Close as Already Resolved — `#[must_use]` on `RuleOverrideMatcher::resolve()`

## Status
**Accepted** — The fix was already delivered in PR #532 (commit `e0c2094`).

## Context

Issue #483 reported that `RuleOverrideMatcher::resolve()` in `crates/diffguard-domain/src/overrides.rs:108` was missing the `#[must_use]` attribute. The method returns a `ResolvedRuleOverride` whose default value is `{ enabled: true, severity: None }`. If a caller discards the return value and assumes the rule is disabled when no override matches, they get the opposite behavior — the rule runs with default enabled state.

The conveyor created work item `work-fd366614` to address this issue. However, the fix was already applied in PR #532 (merged 2026-04-16) before the work item was created.

## Decision

**Close work item `work-fd366614` as Already Resolved.**

The `#[must_use]` attribute is already present on line 108 of `crates/diffguard-domain/src/overrides.rs`:

```rust
#[must_use]
pub fn resolve(&self, path: &str, rule_id: &str) -> ResolvedRuleOverride {
```

All callers properly handle the return value:
- `evaluate.rs:187`: `let resolved_override = overrides.map(|m| m.resolve(path, &rule.id));` — result is bound and used
- All test callers assign to variables and access `.enabled`

No code changes are required.

## Consequences

### Positive
- No new code needed — fix already in `main`
- `#[must_use]` attribute correctly prevents silent discard of semantically important return values
- Consistent with existing `#[must_use]` pattern in `suppression.rs` (lines 46, 70, 85)
- Zero runtime cost — purely compile-time annotation
- No breaking changes — all existing callers handle the return value

### Negative
- The conveyor expected branch `feat/work-fd366614/overrides.rs:108:-ruleoverridematcher::r` was never created (work item generated retroactively after fix was merged)
- The latent semantic issue (`ResolvedRuleOverride::default()` returning `{ enabled: true }`) remains unaddressed but is out of scope for this work item

## Alternatives Considered

### Alternative 1: Create Confirmation Branch/PR
Create a fresh branch and open a PR confirming the fix is in `main`.

**Rejected**: The work item was generated retroactively. A no-op confirmation PR would clutter git history without adding value. The fix is verified present and correct.

### Alternative 2: Change Default Semantics
Change `ResolvedRuleOverride::default()` from `{ enabled: true }` to `{ enabled: false }` or make it `Option<ResolvedRuleOverride>`.

**Rejected**: This would be a breaking change to `evaluate.rs:188`'s logic and requires a dedicated breaking-change work item with full caller audit. The current default may be intentional.

## References
- Issue #483: https://github.com/answerdotai/diffguard/issues/483
- PR #532: https://github.com/answerdotai/diffguard/pull/532
- Commit `e0c2094`: Already in `main` history