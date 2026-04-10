# Plan: Fix broken test compilation in properties.rs (Issue #78)

## Goal

Fix compilation errors in `crates/diffguard-domain/tests/properties.rs` so the test suite runs cleanly.

## Current Context

- **Issue:** #78 — "Broken test compilation in properties.rs: invalid regex::Error variants"
- **Branch:** `feat/work-8cb6a554/diffguard` (current HEAD)
- **Problem:** Lines 1982-1983 reference `regex::Error::InvalidRepeat` and `regex::Error::Bug`, which do not exist in `regex` 1.12.3
- **Current variants in regex 1.x:** `Syntax`, `CompiledTooBig`

## Proposed Approach

1. Read the failing test around lines 1980-2000
2. Remove references to `InvalidRepeat` and `Bug`
3. Use only valid `regex::Error::Syntax` and `regex::Error::CompiledTooBig` variants
4. Add a comment documenting valid variants for current regex crate version
5. Verify: `cargo test --package diffguard-domain --test properties --no-run`
6. Run: `cargo test --package diffguard-domain --test properties`

## Step-by-Step

1. `grep -n "InvalidRepeat\|Bug" crates/diffguard-domain/tests/properties.rs` to locate exact lines
2. Read surrounding context to understand what the test verifies
3. Replace invalid variants with valid ones
4. Add doc comment noting valid regex::Error variants
5. Confirm compilation and test pass

## Files Likely to Change

- `crates/diffguard-domain/tests/properties.rs`

## Tests / Validation

- Compilation: `cargo test --package diffguard-domain --test properties --no-run`
- Execution: `cargo test --package diffguard-domain --test properties`

## Risks, Tradeoffs, Open Questions

- **Risk:** Low — isolated test-only change, no production code affected
- **Tradeoff:** Removing `InvalidRepeat`/`Bug` means some error chain paths aren't tested; however since these variants don't exist in the actual crate, the test is non-functional anyway
- **Open Question:** Should the test be rewritten to test valid error variants instead, or is it acceptable to simply remove the non-existent references?
