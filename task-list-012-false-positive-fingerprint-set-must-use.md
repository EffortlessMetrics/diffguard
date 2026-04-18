# Task List — work-ea81e659

## Implementation Tasks

- [ ] Add `#[must_use]` attribute to `false_positive_fingerprint_set()` in `crates/diffguard-analytics/src/lib.rs` (between doc comment line 138 and `pub fn` on line 139)
- [ ] Verify `cargo check -p diffguard-analytics` passes
- [ ] Verify `cargo test -p diffguard-analytics` passes
- [ ] Create commit on branch `feat/work-ea81e659/diffguard-analytics-must-use-false-positive-fingerprint-set` with message: `fix(diffguard-analytics): add #[must_use] to false_positive_fingerprint_set (issue #540)`

## Verification Checklist

1. `#[must_use]` is present before `pub fn false_positive_fingerprint_set` in lib.rs
2. `cargo check -p diffguard-analytics` passes
3. `cargo test -p diffguard-analytics` passes
4. Commit created on correct branch