# Spec — work-f093d3fc

## Feature/Behavior Description

Add `#[must_use]` attributes to every `Self`-returning builder method on `DiffBuilder`, `FileBuilder`, and `HunkBuilder` in the `diffguard-testkit` crate. This makes the Rust compiler emit a warning when a caller discards the result of a builder method call, preventing the silent no-op bug described in issue #571.

## Background

The `diffguard-testkit` crate provides a fluent API for constructing unified diffs for testing:

```rust
// Fluent API (works correctly — FileBuilderInProgress has #[must_use])
let diff = DiffBuilder::new()
    .file("src/lib.rs")
        .hunk(1, 1, 1, 2)
            .add_line("fn new_function() {}")
            .done()
        .done()
    .build();

// Direct builder use (BUG — result silently discarded)
let file = FileBuilder::new("path.rs");
file.binary(); // file.is_binary is NEVER set — silently ignored
```

The bug occurs because `FileBuilder::binary()` returns `Self` but lacks `#[must_use]`, so the compiler silently accepts discarding the return value.

## Methods Requiring `#[must_use]`

### `DiffBuilder`
| Method | Line | Signature |
|--------|------|-----------|
| `add_file()` | 64 | `pub fn add_file(mut self, file: FileBuilder) -> Self` |

### `FileBuilder`
| Method | Line | Signature |
|--------|------|-----------|
| `binary()` | 215 | `pub fn binary(mut self) -> Self` |
| `deleted()` | 221 | `pub fn deleted(mut self) -> Self` |
| `new_file()` | 227 | `pub fn new_file(mut self) -> Self` |
| `mode_change()` | 233 | `pub fn mode_change(mut self, old_mode: &str, new_mode: &str) -> Self` |
| `rename_from()` | 240 | `pub fn rename_from(mut self, old_path: &str) -> Self` |
| `add_hunk()` | 250 | `pub fn add_hunk(mut self, hunk: HunkBuilder) -> Self` |

### `HunkBuilder`
| Method | Line | Signature |
|--------|------|-----------|
| `context()` | 364 | `pub fn context(mut self, content: &str) -> Self` |
| `add_line()` | 375 | `pub fn add_line(mut self, content: &str) -> Self` |
| `remove()` | 386 | `pub fn remove(mut self, content: &str) -> Self` |
| `add_lines()` | 393 | `pub fn add_lines(mut self, lines: &[&str]) -> Self` |
| `remove_lines()` | 401 | `pub fn remove_lines(mut self, lines: &[&str]) -> Self` |
| `add_lines_from_slice()` | 570 | `pub fn add_lines_from_slice(mut self, lines: &[&str]) -> Self` (in `impl HunkBuilder` block) |

## Acceptance Criteria

1. **Compilation**: `cargo check -p diffguard-testkit` completes without errors.

2. **Test pass**: `cargo test -p diffguard-testkit` passes all existing tests.

3. **Must-use warning**: After the fix, the following pattern produces a `#[must_use]` compiler warning:
   ```rust
   let hunk = HunkBuilder::new(1, 1, 1, 1);
   hunk.add_line("foo"); // warning: unused result of `HunkBuilder::add_line`
   ```

4. **No spurious warnings**: `build()` methods (which return `String`) do not gain `#[must_use]` warnings.

## Non-Goals

- No behavior changes to any method
- No changes to the public API surface
- No changes to other crates in the workspace
- `HunkBuilder::for_additions()` (line 355) is not modified — it's a constructor, not a builder method
- `HunkBuilderInProgress` and `FileBuilderInProgress` methods are not modified — they already have struct-level `#[must_use]`

## Dependencies

- This fix is self-contained within `diffguard-testkit/src/diff_builder.rs`
- No external dependencies or workspace changes required
- Adding `#[must_use]` is backward compatible (advisory only)