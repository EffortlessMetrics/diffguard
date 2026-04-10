# Plan: Security Hardening (Issues #81–#84)

## Goal
Address 4 security vulnerabilities identified in issues #81, #82, #83, and #84.

## Priority Ranking

| # | Issue | Risk | Effort |
|---|-------|------|--------|
| 81 | Unchecked `.expect()` in `compile_globs` | Medium (panic→DoS) | S |
| 82 | No input length limits on diff lines | High (memory exhaustion) | S |
| 83 | Unbounded env var expansion memory | High (memory exhaustion) | M |
| 84 | Include path traversal guard missing | Medium (path escape) | M |

## Step-by-Step Plan

### Issue #81: Fix `.expect()` in compile_globs
**File:** `crates/diffguard-domain/src/rules.rs` (~line 190)
1. Change `RuleCompileError` enum to have an `InvalidGlob` variant with `source: globset::Error`
2. Replace `.expect()` with `.map_err(|e| RuleCompileError::InvalidGlob { rule_id, glob, source: e })?`
3. Ensure `RuleCompileError` implements `std::error::Error` with `source()` for the new variant
4. Add unit tests for malformed glob patterns

### Issue #82: Add input length limits
**Files:** `diffguard-core` input boundary or `diffguard` CLI layer
1. Add a constant `MAX_LINE_LENGTH: usize = 100_000` (100KB) to the domain crate
2. Add length validation in `diffguard-domain/src/preprocess.rs` `sanitize_line()` — return error for oversized lines
3. Add length validation in multiline candidate building in `evaluate.rs`
4. Add property test for extremely long lines
5. Wire error through `RuleError` / `CheckError` types

### Issue #83: Bound env var expansion
**File:** `crates/diffguard/src/env_expand.rs`
1. Add constants: `MAX_EXPANSION_COUNT: usize = 1_000`, `MAX_EXPANSION_LEN: usize = 1_048_576`
2. Track expansion count and total output length
3. Return `ConfigError::EnvExpansionLimitExceeded` if exceeded
4. Add tests for large env values and many references

### Issue #84: Path traversal guard for includes
**File:** `crates/diffguard/src/config_loader.rs`
1. Determine a "root" directory (directory of the base config file)
2. After canonicalizing included paths, verify they are within the root
3. Handle `canonicalize()` errors gracefully (don't expose full paths in errors)
4. Add test with symlink outside root

## Files Likely to Change
- `crates/diffguard-domain/src/rules.rs` (#81)
- `crates/diffguard-domain/src/error.rs` (#81, new error variant)
- `crates/diffguard-domain/src/preprocess.rs` (#82)
- `crates/diffguard-domain/src/evaluate.rs` (#82)
- `crates/diffguard-domain/src/error.rs` (#83 — new error type)
- `crates/diffguard/src/env_expand.rs` (#83)
- `crates/diffguard/src/config_loader.rs` (#84)
- Various test files

## Tests / Validation
- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- `cargo fmt --check` passes
- New unit/property tests for each fix
- Fuzz targets should still pass

## Risks
- Error type changes in domain crate can cascade (check downstream consumers)
- Memory limits may break legitimate use cases (need sane defaults)

## Dependencies
- Issue #81: No dependencies
- Issue #82: No dependencies
- Issue #83: No dependencies
- Issue #84: No dependencies
