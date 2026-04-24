# Specs — work-7e718b3e

## Feature / Behavior

Add `#[must_use]` attribute to `parse_suppression` and `parse_suppression_in_comments` functions in `crates/diffguard-domain/src/suppression.rs` to ensure callers do not silently ignore suppression directives.

## Acceptance Criteria

1. **`parse_suppression` has `#[must_use]`** — The function at line 70 of `suppression.rs` is annotated with `#[must_use]` directly above its signature.

2. **`parse_suppression_in_comments` has `#[must_use]`** — The function at line 85 of `suppression.rs` is annotated with `#[must_use]` directly above its signature.

3. **Clippy passes for scoped functions** — Running `cargo clippy -p diffguard-domain -- -W clippy::must_use_candidate` produces no warnings for `parse_suppression` or `parse_suppression_in_comments`. (Note: Other unrelated functions in the same file may still produce warnings; those are out of scope for this work item.)

## Non-Goals

- This work item does NOT address the 4 other `#[must_use_candidate]` warnings in `suppression.rs` (`is_wildcard`, `SuppressionTracker::new`, `is_suppressed`, `is_empty`). Those may be addressed in a separate follow-up work item.
- This work item does NOT change the behavior of the suppression logic — only adds a lint-level annotation.

## Dependencies

- Issue #307 (original report)
- PR #543 (fix already merged)
- Commit `3e1d9e1` (already applied to `origin/main`)

## Resolution Status

**Already resolved** — The fix was merged in commit `3e1d9e1` (PR #543). This specs document verifies the fix is in place.
