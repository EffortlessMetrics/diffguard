# ADR: Use Checked Conversions for `DiffStats` Overflow Handling

## Status
Accepted

## Context
Issue #278 reported that `parse_unified_diff` in `crates/diffguard-diff/src/unified.rs` silently truncated `usize` values to `u32` when computing `DiffStats`. This violated the "Never panics" invariant stated in `CLAUDE.md` — malformed input must return errors, never crash — and produced incorrect statistics for diffs exceeding 4,294,967,295 files or lines with no indication to callers.

The `diffguard-diff` crate has two explicit constraints:
1. **Never panics** — malformed input must return errors, never crash
2. **No I/O** — purely parsing logic

## Decision
The fix was implemented in commit `e38e907` ("fix: replace lossy usize→u32 casts with checked conversions (#535)"). The decision was to use `u32::try_from()` with `map_err` to return `DiffParseError::Overflow` rather than:

- Using `unwrap()` which would panic on overflow (violates invariant)
- Using `as u32` with silent truncation (produces incorrect results silently)
- Migrating `DiffStats` to u64 (breaking API change, deferred as debt)

### Code Changes Applied

**`crates/diffguard-diff/src/unified.rs:337-342`** — Before:
```rust
let stats = DiffStats {
    files: files.len() as u32,   // silently truncates if > 4_294_967_295
    lines: out.len() as u32,     // silently truncates if > 4_294_967_295
};
```

**After:**
```rust
let stats = DiffStats {
    files: u32::try_from(files.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many files (> {})", u32::MAX)))?,
    lines: u32::try_from(out.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many lines (> {})", u32::MAX)))?,
};
```

**`crates/diffguard-diff/src/unified.rs:120-121`** — Added new error variant:
```rust
#[error("diff stats overflow: {0}")]
Overflow(String),
```

## Consequences

### Positive
- **Never-panics invariant preserved** — overflow returns an error, not a panic
- **Correct error signaling** — callers receive meaningful `DiffParseError::Overflow` for counts exceeding `u32::MAX`
- **No breaking changes** — `DiffStats` remains `u32`, API unchanged
- **Future u64 migration straightforward** — callers already handle errors, so returning `DiffStats` with `u64` later won't break them
- **Issue #475 was closed** — the original issue was fixed and closed

### Negative
- **`DiffStats` remains u32** — inconsistent with other counts in the codebase (`files_scanned: u64`, `lines_scanned: u64`)
- **`DiffParseError::Overflow` becomes dead code if u64 migration happens** — acceptable technical debt
- **No regression test** — the overflow path is not exercised by any test

## Alternatives Considered

### 1. Use `unwrap()` and panic on overflow
- Rejected: violates the "Never panics" invariant in `CLAUDE.md`

### 2. Use `as u32` with silent truncation (status quo before fix)
- Rejected: produces incorrect stats for large diffs with no indication to callers

### 3. Migrate `DiffStats` to u64
- Deferred: breaking API change tracked as technical debt (related to issue #278's scope)

## Issue Resolution
Issue #278 is a duplicate of issue #475. The fix in commit `e38e907` addressed both. Issue #278 should be closed as duplicate of #475.