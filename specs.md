# Spec — work-dcc10c76: Handle GlobSetBuilder::build() Failures

## Feature/Behavior Description

Replace unreachable `.expect()` calls on `GlobSetBuilder::build()` with proper typed error handling. The three affected locations are:

1. `compile_filter_globs()` in `crates/diffguard-core/src/check.rs:268`
2. `compile_globs()` in `crates/diffguard-domain/src/rules.rs:200`
3. `compile_exclude_globs()` in `crates/diffguard-domain/src/overrides.rs:197`

## Acceptance Criteria

### AC1: Three error variants added
- `PathFilterError::GlobSetBuild { source: globset::Error }` added to `check.rs`
- `RuleCompileError::GlobSetBuild { rule_id: String, source: globset::Error }` added to `rules.rs`
- `OverrideCompileError::GlobSetBuild { rule_id: String, directory: String, source: globset::Error }` added to `overrides.rs`

### AC2: Source error preserved
- The `globset::Error` from `build()` is preserved as `source` in each variant (not discarded via `map_err(|_| ...)`)
- The `#[error(...)]` format string references `{source}` so the underlying error is visible to users

### AC3: `expect()` replaced with `map_err` + `?`
- Each `b.build().expect("globset build should succeed")` becomes `b.build().map_err(|source| ...::GlobSetBuild { ... source })?`

### AC4: Build and test pass
- `cargo build` passes with no errors
- `cargo test` passes with no regressions
- `cargo clippy` reports no new warnings

### AC5: New variants have doc comments
- Each new variant has a doc comment explaining when it's triggered

## Non-Goals

- No test for the overflow path (difficult to construct reliably)
- No `#[non_exhaustive]` on error enums (separate discussion)
- No change to public API surface (error types are internal)

## Dependencies

- `globset = "0.4.18"` (existing)
- `thiserror = "..."` (existing, used by error types)
- All three error types already derive `thiserror::Error`
