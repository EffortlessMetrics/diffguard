# Specs — work-eea0aaf4

## Feature / Behavior Description

Add the `#[must_use]` attribute to `RuleOverrideMatcher::resolve()` in `crates/diffguard-domain/src/overrides.rs`. This ensures the compiler warns if any caller discards the returned `ResolvedRuleOverride`, preventing silent fallback to default (no override) behavior.

> **Note**: This feature was implemented in PR #532 (commit e0c2094) before this work item was processed. The `#[must_use]` attribute is already present on `resolve()` at line 108. This specs document records the acceptance criteria for completeness.

## Acceptance Criteria

1. **`#[must_use]` present on `RuleOverrideMatcher::resolve()`**
   - In `crates/diffguard-domain/src/overrides.rs`, the line directly above `pub fn resolve()` at line 109 reads `#[must_use]` (line 108).
   - Verified by: `grep -n '#\[must_use\]' crates/diffguard-domain/src/overrides.rs` shows the attribute at line 108.
   - **Status**: ✅ Already satisfied (PR #532, commit e0c2094)

2. **`cargo clippy -p diffguard-domain` produces no new warnings**
   - Clippy runs clean with no warnings related to `resolve()` or `#[must_use]`.
   - Verified by: running `cargo clippy -p diffguard-domain 2>&1 | grep -i "must_use\|resolve"` — no relevant warnings.
   - **Status**: ✅ Already satisfied (confirmed by verification agent)

3. **All existing callers use the return value**
   - The calling site in `crates/diffguard-domain/src/evaluate.rs:187` properly captures the return value: `let resolved_override = overrides.map(|m| m.resolve(path, &rule.id));`
   - Verified by: grep for `.resolve(` calls shows proper usage in evaluate.rs.
   - **Status**: ✅ Already satisfied (confirmed by verification agent)

4. **Issue #346 is closed as duplicate of #483**
   - **Status**: ⚠️ Pending — needs manual action to close the issue

## Non-Goals

- This spec does **not** change the return type of `resolve()`
- This spec does **not** add `#[must_use]` to any other functions (already done in PR #532)
- This spec does **not** require any new tests — the existing test suite covers the behavior

## Dependencies

- No new dependencies introduced
- `#[must_use]` is supported by all Rust versions supported by this crate
