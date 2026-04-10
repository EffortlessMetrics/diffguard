# Plan: Error Type Trait Verification — Complete v0.2 Enhancement Work

## Goal

Complete the error chain propagation work by adding missing trait bounds (`Send + Sync`, `Error`) and edge-case `source()` tests to `OverrideCompileError` in `overrides.rs`, then either commit or stash the changes.

## Current Context / Assumptions

- **Branch:** `feat/v0.2-enhancements-v2`
- **Status:** PR #5 (feat/v0.2 enhancements) is **MERGED**
- **Uncommitted work:** Regression tests for error type trait bounds on `RuleCompileError`, `OverrideCompileError`, and `SchemaValidationError`
- **Stash:** `stash@{0}` contains a fix for `ENV_LOCK` mutex poison recovery in xtask tests
- **All workspace tests pass** (`cargo test --workspace` ✓)
- **Clippy clean** ✓
- **Fmt clean** ✓

### What's on the branch already (uncommitted)
| File | Change |
|------|--------|
| `crates/diffguard-testkit/src/schema.rs` | `Send+Sync`, `Error` trait bounds + edge-case `source()` tests |
| `crates/diffguard-domain/src/rules.rs` | Edge-case `source()` tests for `MissingPatterns`, `InvalidMultilineWindow`, `UnknownDependency` |
| `crates/diffguard-domain/src/overrides.rs` | `Send+Sync`, `Error` trait bounds + edge-case `source()` tests |

### What's in the stash
- `xtask/src/conform_real.rs` + `xtask/src/main.rs`: `lock_env()` poison recovery + `CARGO_BIN_EXE_diffguard` env var fix for xtask test environment

## Proposed Approach

### Option A: Commit on Branch (recommended)
1. Add `Send + Sync` bounds to `OverrideCompileError` (if not already present — verify in source)
2. Add `Error` trait impl verification compile-time check (already in tests)
3. Commit each logical unit separately:
   - Commit 1: `overrides.rs` error trait tests
   - Commit 2: `rules.rs` error trait tests
   - Commit 3: `schema.rs` error trait tests
4. Pop stash and handle xtask changes separately (they may belong on a different branch or PR)

### Option B: Stash and Defer
- Stash the current branch work, pop the ENV_LOCK stash, address xtask changes first
- This would require a decision about which branch the xtask fix belongs on

## Step-by-Step Plan

1. **Verify current state:**
   ```bash
   cargo test --workspace  # confirm all pass
   cargo clippy --workspace --all-targets -- -D warnings  # confirm clean
   ```

2. **Inspect `OverrideCompileError` in `overrides.rs`:**
   - Check if `Send + Sync` bounds are already present on the enum
   - Check if `Error` trait is already implemented

3. **If trait bounds are missing (likely):**
   - Add `#[derive(Debug)]` and manual `Display`/`Error` impl with `source()` for each variant
   - Ensure `Send + Sync` are enforced (may need `static` lifetime on `source()` return)

4. **Commit logical units:**
   ```bash
   git add crates/diffguard-domain/src/overrides.rs
   git commit -m "test(domain): add source() edge case tests for OverrideCompileError
   
   Adds Send+Sync and Error trait compile-time verification tests.
   Verifies source() returns None for variants without inner errors."
   
   git add crates/diffguard-domain/src/rules.rs
   git commit -m "test(domain): add source() edge case tests for RuleCompileError
   
   Adds tests for MissingPatterns, InvalidMultilineWindow, UnknownDependency
   variants where source() should return None."
   
   git add crates/diffguard-testkit/src/schema.rs
   git commit -m "test(testkit): add source() edge case tests for SchemaValidationError
   
   Adds tests for empty errors Vec, multiple errors, and compile-time
   Error trait verification."
   ```

5. **Handle stash:**
   - Inspect stash contents to determine if xtask changes should be committed here or moved to a separate PR
   - If unrelated: pop stash into a new branch or leave for separate work

6. **Verify tests still pass:**
   ```bash
   cargo test --workspace
   ```

## Files Likely to Change

- `crates/diffguard-domain/src/overrides.rs` — may need `Send + Sync` bounds + trait impls
- `crates/diffguard-domain/src/rules.rs` — already has tests added (verify no source changes needed)
- `crates/diffguard-testkit/src/schema.rs` — already has tests added (verify no source changes needed)
- `xtask/src/conform_real.rs` — from stash (possibly separate PR)
- `xtask/src/main.rs` — from stash (possibly separate PR)

## Tests / Validation

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## Risks, Tradeoffs, and Open Questions

1. **Risk:** The `Send + Sync` bounds may require lifetime annotations on the `source()` return type, which can be tricky if the inner error contains references.
2. **Tradeoff:** Committing small test-only PRs vs. grouping with the stash work.
3. **Open Question:** Should the xtask `ENV_LOCK` poison recovery fix be part of this PR or a separate one? It's a bugfix for test infrastructure, not a v0.2 feature.
4. **Dependency:** The work on `RuleCompileError::source()` was addressed in commit `5578525` ("docs(adr): source() for error chain propagation"). This work extends that pattern.

## Success Criteria

- [ ] `OverrideCompileError` has `Send + Sync` bounds verified
- [ ] All three files have compile-time `Error` trait verification tests
- [ ] All workspace tests pass
- [ ] Changes committed in logical units
