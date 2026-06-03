# Specs: Extract Helpers from parse_unified_diff() — work-095e24f2

## Feature / Behavior Description

Refactor `parse_unified_diff()` in `crates/diffguard-diff/src/unified.rs` by extracting two private helper functions, reducing its logical line count from ~144 to ~75 to satisfy the `clippy::pedantic` `too_many_lines` lint (threshold: 100 lines).

The refactoring is purely structural — no algorithmic changes, no change to the public API, and no change to the set of inputs accepted or outputs produced.

## Extraction Targets

### 1. `process_diff_line_content()`

**Location**: New `pub(crate)` function in `unified.rs`, near the other detection helpers.

**Signature**:
```rust
fn process_diff_line_content(
    line: &str,
    first: u8,
    path: &str,
    scope: Scope,
    old_line_no: u32,
    new_line_no: u32,
    pending_removed: bool,
) -> Option<(Option<DiffLine>, bool, u32, u32)>
```

**Behavior**:
- Takes the raw content line, its first byte (`+`, `-`, or ` `), and all parser state
- Returns `None` for non-content lines (the caller skips — this overloads `None` meaning "not a content line")
- Returns `Some((Some(diff_line), pending_removed', old_line_no', new_line_no'))` when a `DiffLine` is produced and pushed
- Returns `Some((None, pending_removed', old_line_no', new_line_no'))` when the line is valid but filtered out by scope (e.g., `b' '` context lines or `b'+'` lines excluded by scope) — state is updated but no line is pushed

**Internal match arms**:
- `b'+'`: Check `is_submodule`, compute `ChangeKind` (`Changed` if `pending_removed` else `Added`), apply scope filter, increment `new_line_no`
- `b'-'`: Set `pending_removed = true`, increment `old_line_no`
- `b' '`: Reset `pending_removed = false`, increment both counters

### 2. `compute_diff_stats()`

**Location**: New `pub(crate)` function in `unified.rs`.

**Signature**:
```rust
fn compute_diff_stats(lines: &[DiffLine]) -> DiffStats
```

**Behavior**:
- Takes the parsed `&[DiffLine]` slice
- Counts unique file paths via `BTreeSet`
- Counts total lines as `u32::try_from(lines.len()).map_err(...)` wrapping in `DiffParseError::InternalError`
- Returns `DiffStats { files, lines }`

## Acceptance Criteria

### AC1: Clippy warning is resolved
```
cargo clippy --package diffguard-diff -- -W clippy::pedantic
```
must emit no `too_many_lines` warning for `parse_unified_diff`. The warning `warning: this function has too many lines (144/100)` at `crates/diffguard-diff/src/unified.rs:144` must disappear.

### AC2: All existing tests pass
```
cargo test --package diffguard-diff
```
must pass all 40+ tests with no regressions. The fuzz target `unified_diff_parser` (if available via `+nightly`) must also continue to pass.

### AC3: Public API is unchanged
No changes to:
- `parse_unified_diff` function signature or return type
- `DiffLine`, `DiffStats`, `ChangeKind`, `DiffParseError` type definitions
- Any `pub` item in the crate's public API

### AC4: Function line count is < 100
The refactored `parse_unified_diff` must contain fewer than 100 logical lines (per `clippy` counting). If it remains ≥100 after the two primary extractions, a third helper must be extracted (e.g., the `diff --git` header reset block).

### AC5: `pending_removed` state is preserved correctly
The refactoring must not change how `pending_removed` is managed:
- A `b'-'` line sets `pending_removed = true`
- A subsequent `b'+'` line consumes `pending_removed` (classifying the line as `Changed`) and resets it to `false`
- A `b' '` context line resets `pending_removed = false` without consuming it
- State must be correctly propagated through `process_diff_line_content`'s return tuple

## Non-Goals

- No changes to existing helper functions (`is_binary_file`, `is_submodule`, `parse_hunk_header`, etc.)
- No changes to `DiffLine`, `DiffStats`, `ChangeKind`, or `DiffParseError` type definitions
- No changes to any file outside `crates/diffguard-diff/src/unified.rs`
- No new fuzz corpus entries required
- `is_new_file()` at line 55 (dead code) is not addressed — follow-up issue

## Dependencies & Constraints

- **No I/O**: Per `CLAUDE.md`, the crate must not use `std::process`, `std::fs`, or `std::env`
- **No panics**: Malformed input must return `DiffParseError`, never crash or panic
- **Backwards compatibility**: All existing callers of `parse_unified_diff` must behave identically
- **Clippy pedantic**: Must satisfy `too_many_lines` lint at 100-line threshold
