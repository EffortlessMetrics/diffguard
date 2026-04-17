# Specs — work-bc6e41f0

## Feature: Replace redundant closure with `ToString::to_string` in `nth_string_arg`

### Feature/Behavior Description

Replace a redundant closure with a direct trait method reference in the `nth_string_arg` helper
function within `crates/diffguard-lsp/src/server.rs`. This is a code-quality fix that resolves
clippy's `redundant_closure_for_method_calls` lint.

**Before:**
```rust
.map(|value| value.to_string())
```

**After:**
```rust
.map(ToString::to_string)
```

### Acceptance Criteria

1. **Clippy pedantic passes** — Running `cargo clippy --package diffguard-lsp -- -W clippy::pedantic`
   produces no `redundant_closure_for_method_calls` warnings for `server.rs`.

2. **All existing tests pass** — `cargo test --package diffguard-lsp` completes successfully with
   no regressions. The change has zero functional impact.

3. **Only the targeted line changes** — No other files or lines are modified. The `config.rs:96`
   instance (the same lint in a different file) is intentionally left unchanged per issue scope.

### Non-Goals

- This fix does NOT address the same lint in `crates/diffguard-lsp/src/config.rs:96` (out of scope
  per issue #441).
- No refactoring of `nth_string_arg`'s logic — only the syntactic closure replacement.
- No new tests required — this is a pure syntactic change with zero behavioral impact.

### Dependencies

- Clippy `redundant_closure_for_method_calls` lint (pedantic level)
- `ToString` trait from `std::string` (already in scope via `&str` → `String` conversion)
