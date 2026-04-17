# Spec: byte_to_column u32 Conversion Safety — work-ebcfcf30

## Feature/Behavior Description

When converting the result of `byte_to_column(&str, usize) -> Option<usize>` to `u32` for storage in `Finding.column: Option<u32>`, the code must not silently truncate values exceeding `u32::MAX`. Instead, such values must result in `None` (representing "unknown column").

## Background

- **Location:** `crates/diffguard-domain/src/evaluate.rs:298`
- **Function:** `byte_to_column(s: &str, byte_idx: usize) -> Option<usize>`
- **Type contract:** Returns 1-based character column, or `None` if `byte_idx > s.len()`
- **Finding.column:** `Option<u32>` — `None` means "column unknown"

The issue was originally reported as "potential sign loss" in issue #355, but this was a mischaracterization — `usize` is unsigned. The real issue is **silent truncation** when `usize > u32::MAX`.

## Acceptance Criteria

1. **Clippy clean:** `cargo clippy -p diffguard-domain -- -D warnings` produces 0 warnings related to this conversion.

2. **Overflow returns None:** When `byte_to_column` would return a column number exceeding `u32::MAX` (4,294,967,295), the resulting `Finding.column` must be `None`, not a truncated value.

3. **Valid values pass through:** Column values ≤ `u32::MAX` are correctly converted to `Some(column as u32)`.

4. **Test coverage:** All 19 overflow tests in `byte_to_column_overflow_test.rs` pass, including:
   - `test_column_overflow_returns_none`
   - `test_column_u32_max_boundary_passes_through`
   - `test_column_u32_max_plus_one_returns_none`
   - `test_column_type_contract_honored_on_overflow`

5. **Issue closure:** Issues #234, #295, #355, and #481 are all closed as duplicates of the same truncation problem.

## Non-Goals

- This spec does NOT require changing `Finding.column` to `u64` or any other type.
- This spec does NOT require changing the return type of `byte_to_column`.
- This spec does NOT require adding an ADR document beyond the one created for this decision.

## Implementation

The fix was applied in commit `e38e907` (PR #535):

```rust
// Before (BAD):
.and_then(|c| c as u32)

// After (GOOD):
.and_then(|c| u32::try_from(c).ok())
```

## Dependencies

- Rust standard library `u32::try_from()` (no external dependencies)
- Existing `byte_to_column_overflow_test.rs` test suite
