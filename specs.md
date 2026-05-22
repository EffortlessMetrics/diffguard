# Spec: parse_suppression() #[must_use] Annotation — work-ec9e1665

## Feature / Behavior Description

Add the `#[must_use]` attribute to the `parse_suppression()` function in `diffguard-domain` to prevent callers from silently discarding suppression directives. When a caller discards a `Some(Suppression)` return value, suppression is effectively dropped and rules will fire when they should not.

This spec covers the `#[must_use]` addition to both `parse_suppression` and its sibling `parse_suppression_in_comments`, both in `crates/diffguard-domain/src/suppression.rs`.

## Acceptance Criteria

1. **`#[must_use]` is present on `parse_suppression` at line 70 of `suppression.rs`**
   - Verified by: `grep -n '^\#\[must_use\]' crates/diffguard-domain/src/suppression.rs` shows `#[must_use]` at line 70
   - No clippy `must_use_candidate` warning for `parse_suppression` under `-W clippy::pedantic`

2. **`#[must_use]` is present on `parse_suppression_in_comments` at line 85 of `suppression.rs`**
   - Verified by: `grep -n '^\#\[must_use\]' crates/diffguard-domain/src/suppression.rs` shows `#[must_use]` at line 85
   - Both sibling functions now consistently carry the attribute

3. **No regressions in existing tests**
   - Verified by: `cargo test -p diffguard-domain` passes
   - Fuzz harness (`fuzz/fuzz_targets/rule_matcher.rs:270`) uses `let _ =` which correctly silences the warning — this is intentional

4. **No remaining `must_use_candidate` clippy warnings for suppression.rs functions**
   - Verified by: `cargo clippy -p diffguard-domain -- -W clippy::must_use_candidate 2>&1 | grep parse_suppression` produces no output
   - Note: Remaining warnings in `preprocess.rs` (`comment_syntax`, `string_syntax`) are out of scope for this issue

## Non-Goals

- This spec does NOT cover adding `#[must_use]` to `comment_syntax()` or `string_syntax()` in `preprocess.rs` — those are separate issues (tracked elsewhere)
- This spec does NOT cover adding a test to verify `#[must_use]` is present — clippy's `must_use_candidate` lint automatically enforces this at compile time
- This spec does NOT cover closing GitHub issue #364 — that requires a maintainer action to close the issue referencing PR #543

## Dependencies

- `-W clippy::pedantic` must remain enabled in the crate's clippy configuration (it is, per `clippy.toml`)
- PR #543 must remain in the git history (it is, at commit `3e1d9e1`)

## Verification Commands

```bash
# Verify #[must_use] is at the correct lines
grep -n '^\#\[must_use\]' crates/diffguard-domain/src/suppression.rs
# Expected: lines 46, 70, 85

# Run clippy must_use_candidate check
cargo clippy -p diffguard-domain -- -W clippy::must_use_candidate 2>&1 | grep -E "(parse_suppression|warning|error)"
# Expected: no warnings for parse_suppression or parse_suppression_in_comments

# Run tests
cargo test -p diffguard-domain 2>&1 | tail -5
# Expected: test result: ok

# Verify fuzz harness still compiles
cargo build -p fuzz 2>&1 | tail -3
# Expected: compilation succeeds (the let _ = silences the warning)
```
