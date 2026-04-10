# Plan: Fix files_scanned Silent Truncation (Issue #137)

## Goal

Fix silent data truncation in `Evaluation.files_scanned` — when a diff contains > u32::MAX files, the count wraps to 0 instead of being reported correctly.

## Issue

**#137** — `evaluate.rs: files_scanned silently truncates to 0 for repos with >4B files`

Line 312 in `crates/diffguard-domain/src/evaluate.rs`:
```rust
files_scanned: files_seen.len() as u32,
```

`files_seen.len()` returns `usize` (up to 2^64). Silently casting to `u32` wraps on overflow — no warning, no error, just wrong data.

## Current Context

- Line 99 in the same file already uses the `.min()` clamping pattern:
  ```rust
  .min(u32::MAX as usize) as u32
  ```
- But line 312 does not — inconsistent within the same file.
- This is a **silent data corruption** bug in the JSON receipt output.

## Proposed Fix

### Step 1 — Add clamping at the overflow point

In `crates/diffguard-domain/src/evaluate.rs` line ~312, change:
```rust
files_scanned: files_seen.len() as u32,
```
to:
```rust
files_scanned: files_seen.len().min(u32::MAX as usize) as u32,
```

This matches the existing pattern already used at line 99 in the same file.

### Step 2 — Add a test

Add a unit test that verifies overflow behavior:
```rust
#[test]
fn test_files_scanned_overflow_clamping() {
    let mut files_seen = std::collections::HashSet::new();
    // Simulate adding u32::MAX + 1 entries
    for i in 0..(u32::MAX as usize + 1) {
        files_seen.insert(format!("file_{}", i));
    }
    let result = files_seen.len().min(u32::MAX as usize) as u32;
    assert_eq!(result, u32::MAX);
}
```

### Step 3 — Verify no schema bump needed

The `files_scanned` field is already `u32` in the JSON schema. The clamping approach keeps the output within the existing schema — no breaking change.

## Files Likely to Change

- `crates/diffguard-domain/src/evaluate.rs` — fix line 312
- `crates/diffguard-domain/src/evaluate.rs` — add overflow test (or add to existing property tests)

## Tests / Validation

1. `cargo test -p diffguard-domain evaluate::` — all existing tests still pass
2. New overflow clamping test passes
3. `cargo clippy` clean
4. `cargo build` passes

## Risks

- **Schema change risk**: None — output still u32
- **Behavioral risk**: Minimal — capping at u32::MAX is correct for any practical diff
- **Testing risk**: Need to ensure the new test actually exercises the clamping path

## Open Questions

- Should `files_scanned` be upgraded to `u64` in a future schema version instead of clamping? This would be a breaking change but semantically more correct. Recommend filing a follow-up issue.
