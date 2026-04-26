# ADR-0016: Use clone_from() for Full-Text Replacement in diffguard-lsp

## Status
Proposed

## Context
The diffguard-lsp crate handles real-time document updates from editors via the Language Server Protocol. When a full-document text replacement occurs (indicated by a `TextDocumentContentChangeEvent` with no range), the current implementation uses direct string assignment which deallocates the existing string and allocates a new one. This happens even when the existing string's capacity would be sufficient to hold the new text.

The issue was reported in GitHub #316: "diffguard-lsp: apply_changes does full-text replacement unconditionally instead of using clone_from()". Note that while the issue title mentions `apply_changes`, the problematic pattern exists in two locations: `mark_saved()` and `apply_incremental_change()`.

## Decision
We will replace direct string assignment with `String::clone_from()` in two locations:

1. **`DocumentState::mark_saved()` in server.rs:92**
   - Before: `self.text = text;`
   - After: `self.text.clone_from(&text);`

2. **`apply_incremental_change()` in text.rs:63**
   - Before: `*text = change.text.clone();`
   - After: `text.clone_from(&change.text);`

This decision is consistent with the existing pattern already in the codebase at `server.rs:77` (introduced in commit `cc265f3`, PR #520).

## Consequences

### Benefits
- **Reduced memory allocations**: `clone_from()` allows the String implementation to reuse existing capacity when available, avoiding unnecessary heap deallocation/reallocation.
- **Better performance for large documents**: Users editing large files in LSP clients will experience fewer allocations during document updates.
- **Consistency**: Aligns all full-text replacement sites with the same pattern.
- **Zero behavioral change**: `clone_from()` guarantees identical end results; only allocation behavior differs.

### Tradeoffs
- **Minimal risk**: `clone_from()` is a stable, well-documented Rust idiom specifically designed for this use case.
- **No API changes**: This is an internal implementation optimization with no impact on function signatures or external behavior.

## Alternatives Considered

### 1. Keep Direct Assignment
**Rejected because**: Direct assignment always deallocates and reallocates, even when capacity would suffice. For an LSP server handling frequent document updates on large files, this creates unnecessary memory pressure.

### 2. Use `std::mem::replace()`
**Rejected because**: `mem::replace()` has identical allocation behavior to direct assignment. It swaps the old value out and moves the new value in, still causing allocation when the target had capacity. `clone_from()` is the idiomatic solution for capacity reuse.

### 3. Manual Buffer Management
**Rejected because**: Manually checking capacity and resizing/copying is error-prone and verbose when `clone_from()` already provides the optimization with zero additional complexity.

## Dependencies
- Rust standard library (no external dependencies added)
- `lsp_types` crate for `TextDocumentContentChangeEvent` type (already in use)

## Non-Goals
- This ADR does not address any changes beyond the two identified locations
- Does not introduce new public APIs
- Does not change any function signatures or return types