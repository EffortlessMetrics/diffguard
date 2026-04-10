# Plan: Fix Missing #[must_use] on as_str Methods

## Goal
Add `#[must_use]` attributes to `as_str` methods on `Severity`, `Scope`, and `FailOn` enums to satisfy `clippy::must_use` lint.

## Current Context
- **Issue**: #124 — Three enum impl blocks define `as_str` methods flagged by `#[must_use]` lint
- **Files affected**:
  - `Severity::as_str` (line 52) in `diffguard-types/src/lib.rs`
  - `Scope::as_str` (line 71) in `diffguard-types/src/lib.rs`
  - `FailOn::as_str` (line 90) in `diffguard-types/src/lib.rs`
- **All tests pass**: 502+ tests across workspace
- **Clippy**: Clean (no warnings currently)
- **Branch**: `feat/work-8d7001a2/verify-parallel-pipeline`

## Proposed Approach
Add `#[must_use]` attribute to each of the three `as_str` impl blocks. The `as_str` methods return `&'static str` which callers use for rendering (SARIF, GitLab Quality JSON, Checkstyle, CSV). Silently discarding the return value would be a caller bug.

## Step-by-Step Plan
1. Open `crates/diffguard-types/src/lib.rs`
2. Locate the `impl Severity` block (around line 52) and add `#[must_use]` before `pub fn as_str`
3. Locate the `impl Scope` block (around line 71) and add `#[must_use]` before `pub fn as_str`
4. Locate the `impl FailOn` block (around line 90) and add `#[must_use]` before `pub fn as_str`
5. Run `cargo clippy --workspace --all-targets -- -D warnings` to verify
6. Run `cargo test --workspace` to ensure no regressions
7. Commit with message: `fix(types): add #[must_use] to Severity/Scope/FailOn::as_str methods`
8. Create PR against `main`

## Files Likely to Change
- `crates/diffguard-types/src/lib.rs` (3 lines added)

## Tests / Validation
- Clippy passes with `-D warnings`
- All 502+ workspace tests pass
- No functional change — purely attribute addition

## Risks
- **Low**: Single-attribute addition, no logic changes
- No risk of breaking existing behavior

## Open Questions
- Should `to_str` / `as_str` variants on other enums also get `#[must_use]`? Only the three named in #124.
