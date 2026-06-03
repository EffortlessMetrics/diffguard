# ADR-2026-0427-095e24f2: Extract Helpers from parse_unified_diff() to Satisfy clippy::pedantic Line Count

## Status
**Proposed**

## Context
GitHub issue #327 reports that `parse_unified_diff()` in `crates/diffguard-diff/src/unified.rs:144` has ~144 logical lines, exceeding the project's 100-line `clippy::pedantic` threshold (`too_many_lines` lint). The function is a large `for` loop with ~15 dispatch branches over diff line types (git header, hunk header, content lines, etc.), with the content-line `match` block (~62 lines) being the largest single chunk.

Prior refactors #318 (`evaluate_lines()`, 201 lines) and #310 (`sanitize_line()`, 465 lines) established the pattern of extracting composable helpers to satisfy the same lint.

## Decision
Extract two helper functions from `parse_unified_diff()`:

1. **`process_diff_line_content(..., scope, old_line_no, new_line_no, pending_removed) -> Option<(Option<DiffLine>, bool, u32, u32)>`** — encapsulates the content-line processing `match` block (`b'+'`, `b'-'`, `b' '` arms). The return type uses `Option<DiffLine>` (not just `DiffLine`) because:
   - The `b' '` (context) arm requires state updates (`pending_removed = false`, increment both counters) but emits NO `DiffLine`
   - The `b'+'` arm when scope-filtered emits NO `DiffLine` but still increments `new_line_no`
   - Returning `None` from the outer `Option` signals "not a content line" (skip, no state change)

2. **`compute_diff_stats(lines: &[DiffLine]) -> DiffStats`** — encapsulates the `BTreeSet`-based file/line counting block, replacing the inline stats computation at the end of `parse_unified_diff()`.

The main `for raw in diff_text.lines()` loop becomes a clear dispatch table over line types, delegating complex content-line logic to `process_diff_line_content()` and finalizing stats via `compute_diff_stats(&out)`.

## Consequences

### Benefits
- `parse_unified_diff()` drops from ~144 to ~75 lines, satisfying the 100-line threshold
- The `pending_removed` state machine becomes isolated and testable in `process_diff_line_content()`
- Smaller functions are easier to fuzz and reason about
- Consistent with codebase extraction pattern established by #318 and #310

### Tradeoffs / Risks
- **State-passing complexity**: The helper must correctly propagate `pending_removed` state; incorrect return values silently corrupt line number counters and `ChangeKind` classification (`Added` vs `Changed`). The inner `Option<DiffLine>` prevents this silent corruption for the context-line and filtered-line cases.
- **Risk of not reaching <100 lines**: If the clippy count remains ≥100 after these two extractions, a third helper may be needed (e.g., extracting the `diff --git` header block).
- **No algorithmic change**: The refactoring is purely structural (extract helpers); all edge cases (binary files, submodules, renames, mode changes, malformed hunks) are preserved because the test suite covers them.

## Alternatives Considered

### 1. Do Nothing / Suppress the Lint
Rejecting the lint or leaving the function as-is was rejected because:
- Issue #327 explicitly requests the function be shortened
- The codebase has an explicit norm of keeping functions under 100 lines (enforced by `clippy::pedantic`)
- Prior art (#318, #310) shows this is the expected approach

### 2. Split into Multiple Files / Modules
Moving portions of `parse_unified_diff()` to submodules was rejected because:
- The function and its helpers are tightly coupled by the parsing state
- Module-level refactoring would be disproportionate to the problem (144 lines is not that large)
- It would complicate the crate's public API boundary

### 3. Return Raw Struct Instead of Tuple
Using a dedicated `ProcessResult` struct instead of `Option<(Option<DiffLine>, bool, u32, u32)>` was considered but rejected because:
- The tuple is already self-documenting (the fields are well-named in the destructuring)
- A new struct adds a type that must be exported/maintaned
- The existing codebase uses small tuples for helper return values (e.g., `parse_hunk_header` returns a tuple)

## References
- GitHub issue: EffortlessMetrics/diffguard#327
- Prior art: Issues #318 (`evaluate_lines()`), #310 (`sanitize_line()`)
- Plan review correction: `process_diff_line_content` return type must be `Option<(Option<DiffLine>, bool, u32, u32)>` — inner `Option` is mandatory for correctness
