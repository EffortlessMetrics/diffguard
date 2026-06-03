# Specs: work-95bdb9f2 — RuleOverrideMatcher::resolve() #[must_use]

## Feature / Behavior Description

Ensure that `RuleOverrideMatcher::resolve()` return value is not silently discarded by callers. The `ResolvedRuleOverride` type carries meaningful state (`enabled: bool`, `severity: Option<Severity>`) that must be acted upon for override configuration to take effect.

## Acceptance Criteria

1. **`#[must_use]` attribute is present on `resolve()`** — `crates/diffguard-domain/src/overrides.rs:108` has `#[must_use]` above `pub fn resolve(...)`. Verification: `grep -n '#\[must_use\]' overrides.rs` finds it at the resolve function.

2. **`cargo clippy -p diffguard-domain` produces zero must_use warnings** — No caller silently discards `resolve()` return value. The existing callers in `evaluate.rs:187` and `check.rs:124` already use the result correctly.

3. **Issue #538 is closed** — GitHub issue #538 is closed as duplicate of #483, which was fixed in PR #532. No additional code changes needed.

## Non-Goals

- This spec does not require new tests — the fix is a compile-time attribute, not behavioral change
- This spec does not require changes to call sites — all known callers already use the return value
- This spec does not address `suppresses()` or builder structs — those were covered in PR #532

## Dependencies

- PR #532 (commit `e0c2094`) — already merged; provides the `#[must_use]` fix
- Issue #483 — already closed by PR #532; #538 is duplicate of this

## Verification Commands

```bash
# Verify #[must_use] is present
grep -A1 'must_use' crates/diffguard-domain/src/overrides.rs | head -20

# Verify no clippy warnings
cargo clippy -p diffguard-domain 2>&1 | grep -i must_use || echo "No must_use warnings"

# Verify issue is closed
gh issue view 538 --json state  # should show "CLOSED"
```
