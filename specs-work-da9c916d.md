# Specs: Fix RuleTestCase Doc Comment Backticks — work-da9c916d

## Feature Description
Add backticks around field name identifiers `ignore_comments` and `ignore_strings` in the `RuleTestCase` struct doc comments in `crates/diffguard-types/src/lib.rs` to satisfy the `clippy::doc_markdown` lint (pedantic).

## Behavior Changes

### Before
```rust
/// Optional: override ignore_comments for this test case.
pub ignore_comments: Option<bool>,

/// Optional: override ignore_strings for this test case.
pub ignore_strings: Option<bool>,
```

### After
```rust
/// Optional: override `ignore_comments` for this test case.
pub ignore_comments: Option<bool>,

/// Optional: override `ignore_strings` for this test case.
pub ignore_strings: Option<bool>,
```

## Acceptance Criteria

1. **`cargo clippy -p diffguard-types -- -W clippy::doc_markdown`** — The warnings at lines 398 and 402 must be eliminated. Other `doc_markdown` warnings in the file (lines 447, 507, 520, 536) must remain as they are out of scope.

2. **No functional changes** — The change is purely cosmetic (doc comment formatting only). The struct's fields, types, and behavior are unchanged.

## Non-Goals
- Fixing other `doc_markdown` warnings in the file (lines 447, 507, 520, 536)
- Any logic changes to the `diffguard-types` crate
- Suppressing or disabling the lint globally

## Dependencies
- Rust toolchain with clippy (1.92.0 or compatible)
- The `diffguard-types` crate must compile (no new compilation errors introduced)

## Verification Commands
```bash
# Before fix: warnings at lines 398, 402
cargo clippy -p diffguard-types -- -W clippy::doc_markdown 2>&1 | grep -E "^warning.*lib.rs:[0-9]+"

# After fix: warnings at 398, 402 should be gone
cargo clippy -p diffguard-types -- -W clippy::doc_markdown 2>&1 | grep -E "^warning.*lib.rs:[0-9]+"
```

## Files in Scope
- `crates/diffguard-types/src/lib.rs` — only lines 398 and 402 doc comments