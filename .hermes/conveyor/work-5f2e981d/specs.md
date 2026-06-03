# Spec — add #[must_use] to CompiledRule::applies_to()

**Work ID:** work-5f2e981d

**Issue:** https://github.com/EffortlessMetrics/diffguard/issues/547

**File:** `crates/diffguard-domain/src/rules.rs:58`

## Feature Description

Add the `#[must_use]` attribute to the `CompiledRule::applies_to()` method in `crates/diffguard-domain/src/rules.rs` at line 58. This causes the compiler to emit a warning when any caller discards the returned `bool`, preventing silent bypass of rule scope filters (include/exclude globs and language filters).

## Acceptance Criteria

1. **Compilation**: `cargo build -p diffguard-domain` completes without error
2. **Tests pass**: `cargo test -p diffguard-domain` passes with no new failures
3. **Clippy clean**: `cargo clippy -p diffguard-domain` produces no new warnings related to `applies_to`
4. **Attribute applied**: `#[must_use]` appears directly above `pub fn applies_to` in `rules.rs:58`

## Non-Goals

- This change does not modify the function body or its logic
- This change does not add new tests (existing tests already cover behavior)
- This change does not add `#[must_use]` to any other functions
- This change does not modify any other crate or file

## Dependencies

- No new dependencies
- No Cargo.toml changes
- The existing `#[must_use]` patterns in `diffguard-domain` (on `Suppression` and `Override` methods) and in `diffguard-diff` (on `is_binary_file`, `is_submodule`, etc.) serve as precedent