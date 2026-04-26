# Specification: Use clone_from() for Full-Text Replacement in diffguard-lsp

## Feature Description
Replace direct string assignment with `String::clone_from()` in two locations within the diffguard-lsp crate to enable capacity reuse and reduce unnecessary memory allocations during document updates.

## Background
The diffguard-lsp crate serves as a Language Server Protocol implementation for real-time editor integration. When applying full-document text replacements (changes without a range), the code previously used direct assignment which deallocates the existing string and allocates a new one. Using `clone_from()` allows the String implementation to reuse existing memory capacity when available.

This optimization is already applied at `server.rs:77` (commit `cc265f3`, PR #520) but was missing from two other locations.

## Scope

### In Scope
- `DocumentState::mark_saved()` in `crates/diffguard-lsp/src/server.rs` — change line 92 from `self.text = text;` to `self.text.clone_from(&text);`
- `apply_incremental_change()` in `crates/diffguard-lsp/src/text.rs` — change line 63 from `*text = change.text.clone();` to `text.clone_from(&change.text);`

### Out of Scope
- Any changes to `apply_changes()` function at server.rs:77 (already fixed)
- Any other crates or modules
- Changes to public API surfaces
- Addition of new tests (existing tests provide coverage)

## Acceptance Criteria

1. **Compilation**: Code compiles successfully with `cargo check -p diffguard-lsp`
2. **Existing Tests Pass**: All unit tests in the diffguard-lsp crate pass with `cargo test -p diffguard-lsp`
3. **Behavioral Equivalence**: The change produces identical output; only memory allocation behavior differs
4. **Consistency**: The pattern used matches the existing `clone_from()` usage at server.rs:77

## Technical Details

### Why clone_from()?
`String::clone_from()` is defined in the Rust standard library as:
> "Copies and clones a value from one string to another, reusing the allocation of the original string to store the result."

This allows the implementation to potentially reuse the existing capacity when the target string has sufficient allocation, avoiding a deallocation/reallocation cycle.

### Semantics
`clone_from()` guarantees that after the call, the target string contains the same value as the source. The difference from direct assignment is solely in memory allocation behavior:
- Direct assignment: Deallocates target, allocates new string with new content
- `clone_from()`: May reuse existing capacity, potentially avoiding allocation

### Risk Assessment
- **Risk Level**: Low
- **Reason**: `clone_from()` is a stable Rust idiom. The end result is guaranteed identical. No API changes. The pattern is already proven in the codebase at server.rs:77.

## Dependencies
- Rust toolchain (stable)
- `cargo` build tool
- `lsp_types` crate (already a dependency)

## Non-Goals
- This specification does not include adding new tests for this specific optimization
- Does not include addressing similar patterns in other crates
- Does not include any public API changes