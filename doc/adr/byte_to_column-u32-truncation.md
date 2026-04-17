# ADR-0XXX: Checked Conversion for byte_to_column usize→u32

## Status
Accepted

## Context

In `crates/diffguard-domain/src/evaluate.rs:298`, the result of `byte_to_column()` (which returns `Option<usize>`) was being cast directly to `u32` using `as u32`:

```rust
let column = event
    .match_start
    .and_then(|start| byte_to_column(&prepared.line.content, start))
    .map(|c| c as u32); // BAD: silent truncation
```

Clippy warned about this lossy cast. While `byte_to_column` returns `Option<usize>` which is always non-negative (no sign bit exists), the concern was **silent truncation** — if `usize` values exceed `u32::MAX` (~4.29 billion), the cast would silently produce a wrong value.

The `column` field in the `Finding` struct is `Option<u32>`, requiring a conversion.

## Decision

Replace the unsafe `as u32` cast with a checked conversion using `u32::try_from().ok()`:

```rust
let column = event
    .match_start
    .and_then(|start| byte_to_column(&prepared.line.content, start))
    .and_then(|c| u32::try_from(c).ok());
```

This change:
- Returns `None` when `c > u32::MAX` (overflow guard)
- Returns `Some(c as u32)` when `c <= u32::MAX` (safe conversion)
- Eliminates the Clippy warning
- Is consistent with the semantic meaning of `Option<u32>` — unknown column is `None`, not a wrong value

## Consequences

**Positive:**
- No silent truncation — overflow produces `None` rather than incorrect data
- Clippy warnings eliminated
- Idiomatic Rust error handling
- Aligns with diffguard's never-panic invariant

**Negative:**
- Columns exceeding u32::MAX are reported as `None` (graceful degradation)
- This is acceptable: no text editor or terminal displays columns beyond ~4 billion

**Risks:**
- The issue title "sign loss" was misleading (no sign bit in `usize`). The real issue is truncation.
- Multiple issues (#234, #295, #355, #481) describe the same problem — all should be formally closed.

## Alternatives Considered

1. **Keep `as u32` (rejected)** — Silently truncates, producing wrong column numbers with no indication of error.

2. **Panic on overflow (rejected)** — Would crash for extremely long lines. `None` is the correct representation for "column unknown".

3. **Change `Finding.column` to `Option<u64>` (rejected)** — Breaking API change. u32 is sufficient for all realistic use cases.

## References

- Issue #355: evaluate.rs:298: byte_to_column result cast as u32 — potential sign loss
- PR #535: fix: replace lossy usize→u32 casts with checked conversions
- Commit e38e907
- Test file: `crates/diffguard-domain/tests/byte_to_column_overflow_test.rs`
