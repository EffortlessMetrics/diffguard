# Specs: work-fd366614 — `#[must_use]` on `RuleOverrideMatcher::resolve()`

## Feature Description
This work item is **already resolved**. The `#[must_use]` attribute was already added to `RuleOverrideMatcher::resolve()` at `overrides.rs:108` by PR #532. No new implementation is required.

The attribute ensures that callers cannot accidentally discard the return value of `resolve()`, which returns `ResolvedRuleOverride` with a default of `{ enabled: true, severity: None }` — a non-obvious default that could cause silent bugs if discarded.

## Acceptance Criteria

### AC1: `#[must_use]` Present on `resolve()`
- [x] `#[must_use]` attribute is present on line 108 of `crates/diffguard-domain/src/overrides.rs`
- [x] Attribute is directly above `pub fn resolve()` method signature
- **Verified by**: `grep -n "must_use" crates/diffguard-domain/src/overrides.rs`

### AC2: All Callers Handle Return Value
- [x] `evaluate.rs:187` captures result: `let resolved_override = overrides.map(|m| m.resolve(path, &rule.id));`
- [x] Result is used: `is_some_and(|resolved| !resolved.enabled)` and `.and_then(|resolved| resolved.severity)`
- [x] All test callers assign to variables and access `.enabled`
- **Verified by**: Code inspection of `evaluate.rs` and `overrides.rs` test code

### AC3: Issue #483 is Closed
- [x] Issue state: `CLOSED`
- [x] Closed at: `2026-04-16T00:28:28Z`
- **Verified by**: `gh issue view 483 --json state,closedAt`

### AC4: Fix Delivered via PR #532
- [x] PR #532 merged at: `2026-04-16T00:28:26Z`
- [x] Commit `e0c2094` is in `main` history
- **Verified by**: `gh pr view 532 --json mergedAt,mergeCommit` and `git merge-base --is-ancestor`

### AC5: Tests Pass
- [x] `cargo test -p diffguard-domain` passes all 14 tests
- [x] No new compiler warnings introduced by `#[must_use]`
- **Verified by**: `cargo test -p diffguard-domain`

## Non-Goals
- This work item does **not** address changing `ResolvedRuleOverride::default()` semantics (tracked separately)
- This work item does **not** add `#[must_use]` to other methods (e.g., `preprocess.rs` factory methods — tracked by separate ADR)
- This work item does **not** create a confirmation branch/PR since the fix was retroactively assigned to this work item after being merged

## Dependencies
- None — the fix is already in `main`

## Verification Commands
```bash
# Verify #[must_use] is present
grep -n "must_use" crates/diffguard-domain/src/overrides.rs

# Verify no new warnings
cargo build -p diffguard-domain 2>&1 | grep -i "must_use" || echo "No must_use warnings"

# Run tests
cargo test -p diffguard-domain

# Confirm issue is closed
gh issue view 483 --json state,title
```