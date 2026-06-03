# Spec: Fix silent truncation in byte_to_column→u32 conversion

## Feature/Behavior Description

Replace the silent truncation at `evaluate.rs:298` (`u32::try_from(c).ok()`) with explicit clamping (`c.min(u32::MAX as usize) as u32`), making the unavoidable u32 truncation explicit rather than silent.

**Current behavior:** When `byte_to_column` returns a column value exceeding `u32::MAX` (~4.29 billion), `.ok()` silently discards it, returning `None`.

**New behavior:** When `byte_to_column` returns a column value exceeding `u32::MAX`, explicit clamping returns `Some(u32::MAX)`. This makes the truncation visible in code.

**Note on practicality:** Columns > u32::MAX require a single line exceeding ~4GB of text. This cannot occur in real-world diff content (typically <1MB per line). The fix addresses the **principle** of avoiding silent data loss, not a practical bug.

## Acceptance Criteria

### AC1: Explicit clamping at call site
- [ ] Line 298 in `crates/diffguard-domain/src/evaluate.rs` is changed from:
  ```rust
  .and_then(|c| u32::try_from(c).ok());
  ```
  To:
  ```rust
  // Explicit truncation: u32 cannot represent columns > ~4.3B chars.
  // A single line this long is practically impossible in diff content.
  // Using .min() instead of .ok() makes the truncation explicit rather than silent.
  .and_then(|c| Some(c.min(u32::MAX as usize) as u32))
  ```

### AC2: No type changes to Finding.column or downstream consumers
- [ ] `Finding.column` remains `Option<u32>` (no change)
- [ ] No changes to `SarifRegion`, `SensorLocation`, `error_element()` parameter types
- [ ] No changes to SARIF, Checkstyle, or Sensor export code

### AC3: Build verification
- [ ] `cargo build -p diffguard-domain` compiles without errors
- [ ] `cargo build -p diffguard-types` compiles without errors

### AC4: Test verification
- [ ] `cargo test -p diffguard-domain` passes all existing tests
- [ ] `cargo test -p diffguard-types` passes all existing tests

## Non-Goals

- This fix does **NOT** eliminate truncation (u32 cannot hold >4GB column values)
- This fix does **NOT** change `Finding.column` to `u64` (downstream consumers constrain to u32)
- This fix does **NOT** add new tests for byte_to_column (out of scope for this issue)
- This fix does **NOT** address any other silent truncation issues in the codebase

## Dependencies

- No new dependencies required
- No schema changes required
- No changes to any consuming crate beyond `evaluate.rs`

## Edge Cases

| Input | Current Behavior | New Behavior | Acceptable? |
|-------|-----------------|--------------|-------------|
| Column ≤ u32::MAX | `Some(column)` | `Some(column)` | ✓ Identical |
| Column > u32::MAX | `None` (silent loss) | `Some(u32::MAX)` (explicit) | ✓ Better |
| Empty string, byte_idx=0 | `Some(1)` | `Some(1)` | ✓ Identical |
| Non-ASCII chars | `Some(char_count+1)` | `Some(char_count+1)` | ✓ Identical |

## Implementation Notes

The fix is a single-line change with an added comment explaining the rationale. No refactoring of `byte_to_column` is needed — the function is correct as-is; only its call site was problematic.

The `byte_to_column` function signature (`fn byte_to_column(s: &str, byte_idx: usize) -> Option<usize>`) remains unchanged — the truncation happens at the point where `Option<usize>` is converted to `Option<u32>` for `Finding.column`.