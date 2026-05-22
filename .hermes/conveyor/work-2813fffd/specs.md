# Spec — work-2813fffd

## Feature/Behavior Description
Change the format! macro at `crates/diffguard-lsp/src/server.rs` line 552 from using a positional placeholder `{}` to a named variable placeholder `{err}` in the error message for invalid `DidOpenTextDocumentParams`.

**Before:**
```rust
&format!("invalid didOpen params: {}", err),
```

**After:**
```rust
&format!("invalid didOpen params: {err}"),
```

## Acceptance Criteria

1. **Line 552 uses named placeholder**: The format! call at line 552 in `crates/diffguard-lsp/src/server.rs` uses `{err}` instead of `{}`.

2. **Clippy passes**: Running `cargo clippy --package diffguard-lsp` produces no new warnings or errors.

3. **Build succeeds**: Running `cargo build --package diffguard-lsp` completes successfully.

4. **No behavioral change**: The runtime output of the format string is identical — only the source code form changes.

## Non-Goals
- This does not fix similar patterns elsewhere in the codebase (lines 299, 368, 519, 532, 546, 581, 599, 702, 728) — those have separate issues.
- This does not add any new functionality.
- This does not modify any test files.

## Dependencies
- None — this is a pure format string change with no external dependencies.
