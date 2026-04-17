# ADR-0571: Add `#[must_use]` to diffguard-testkit builder methods

## Status
Proposed

## Context

GitHub issue #571 reports that `DiffBuilder`, `FileBuilder`, and `HunkBuilder` in the `diffguard-testkit` crate have builder methods that return `Self` but lack `#[must_use]` attributes. This means if a caller writes:

```rust
let file = FileBuilder::new("path.rs");
file.binary(); // SILENTLY IGNORED — the file is NOT marked as binary
```

or:

```rust
let hunk = HunkBuilder::new(1, 1, 1, 1);
hunk.add_line("foo"); // SILENTLY IGNORED — the line is NOT added
```

...the call is silently ignored with no compile-time warning. This is especially insidious in tests where a forgotten `.add_line()` or `.binary()` results in an empty or incorrect diff being built, with no indication why.

The `FileBuilderInProgress` and `HunkBuilderInProgress` structs already have struct-level `#[must_use]` (covering their builder methods), but `FileBuilder` and `HunkBuilder` themselves do not, and their methods lack method-level `#[must_use]`.

Additionally, `DiffBuilder::add_file` (line 64) returns `Self` without `#[must_use]`, creating the same silent no-op pattern.

## Decision

Apply `#[must_use]` at the method level to every `Self`-returning builder method on `DiffBuilder`, `FileBuilder`, and `HunkBuilder`. This is done at the method level rather than struct level because:

1. Adding `#[must_use]` to the struct would also make `build()` methods `#[must_use]` — `FileBuilder::build()` returns `String`, not `Self`, so struct-level would cause unintended warnings on `build()` calls.
2. Method-level `#[must_use]` is a valid Rust attribute and precisely targets the problematic builder methods.

### Methods requiring `#[must_use]` on `DiffBuilder`:

| Method | Line | Purpose |
|--------|------|---------|
| `add_file()` | 64 | Add a pre-built file to the diff |

### Methods requiring `#[must_use]` on `FileBuilder` (line 187):

| Method | Line | Purpose |
|--------|------|---------|
| `binary()` | 215 | Mark file as binary |
| `deleted()` | 221 | Mark file as deleted |
| `new_file()` | 227 | Mark file as new |
| `mode_change()` | 233 | Set old/new mode |
| `rename_from()` | 240 | Set old path for rename |
| `add_hunk()` | 250 | Add a hunk to the file |

### Methods requiring `#[must_use]` on `HunkBuilder` (line 326):

| Method | Line | Purpose |
|--------|------|---------|
| `context()` | 364 | Add a context line |
| `add_line()` | 375 | Add an added line |
| `remove()` | 386 | Add a removed line |
| `add_lines()` | 393 | Add multiple added lines |
| `remove_lines()` | 401 | Add multiple removed lines |
| `add_lines_from_slice()` | 570 | Add multiple lines from slice (in `impl HunkBuilder` block) |

### Not included (by design):

- `HunkBuilder::for_additions()` (line 355) — alternative constructor, not a builder method in the fluent chain
- `HunkBuilderInProgress` and `FileBuilderInProgress` methods — already covered by struct-level `#[must_use]`

## Consequences

**Positive:**
- Compile-time detection of forgotten builder chains — the exact bug described in issue #571
- Zero runtime overhead — `#[must_use]` is purely a compile-time lint
- Backward compatible — purely advisory, does not change any behavior
- Only affects `diffguard-testkit` (internal crate, `publish = false`)

**Negative:**
- Any existing code that legitimately discards builder results will now produce warnings — but discarding the result of a builder method is always a bug in this API
- New warnings in dependent crates that have buggy calls — but this is the fix, not a problem

## Alternatives Considered

### Alternative 1: Add `#[must_use]` at struct level for `FileBuilder` and `HunkBuilder`
Rejected because struct-level `#[must_use]` would also apply to non-builder methods like `build()` which return `String`, causing spurious warnings on legitimate code that captures the diff string.

### Alternative 2: Do nothing
Rejected because the silent no-op bug described in issue #571 is a real problem that causes incorrect test behavior with no indication of the cause.

### Alternative 3: Require fluent API only
Rejecting direct construction of `FileBuilder`/`HunkBuilder` in favor of `DiffBuilder::file(...).hunk(...)...` chain. This would be a breaking API change and was deemed too invasive for the benefit.