# ADR-058: Decompose sanitize_line() via Mode Handler Methods

## Status
**Proposed** — awaiting implementation

## Context

`sanitize_line()` in `crates/diffguard-domain/src/preprocess.rs` (line 304) is ~580 lines long, triggering the `clippy::too_many_lines` lint. The method implements a stateful preprocessor that masks comments and string literals across 18 supported languages using a single `while i < len` loop with a `match self.mode` dispatch.

The function grew organically as language-specific cases were added. The `Mode::Normal` arm alone is ~280 lines because it handles all string-start detection (Rust raw strings, Python triple-quoted, JS template literals, Go backtick strings, Shell $' ', SQL single-quotes, XML/PHP quotes, etc.) and all comment-start detection (//, /* */, #, --, <!-- -->) in one place. The remaining ~300 lines are the other 9 `Mode` variant arms.

The state machine architecture (`Mode` enum, `Preprocessor` struct, `while i < len` / `match self.mode` loop) is sound and should be preserved. The problem is purely structural: the function is doing too many things in one place.

## Decision

Decompose `sanitize_line()` through **method extraction on `Preprocessor`**, preserving all state machine semantics:

### 1. Extract mode handler methods

Each `Mode` variant's arm in `match self.mode` becomes a private method:

```rust
fn handle_mode_normal(&mut self, bytes: &[u8], i: usize, len: usize, out: &mut Vec<u8>) -> usize;
fn handle_mode_line_comment(&mut self, bytes: &[u8], i: usize, len: usize, out: &mut Vec<u8>) -> usize;
fn handle_mode_block_comment(&mut self, bytes: &[u8], i: usize, len: usize, out: &mut Vec<u8>) -> usize;
// ... one per Mode variant
```

`sanitize_line()` becomes the compact dispatch loop (~60 lines):

```rust
pub fn sanitize_line(&mut self, line: &str) -> Cow<str> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        i = match self.mode {
            Mode::Normal => self.handle_mode_normal(bytes, i, len, &mut out),
            Mode::LineComment => self.handle_mode_line_comment(bytes, i, len, &mut out),
            Mode::BlockComment { depth } => self.handle_mode_block_comment(bytes, i, len, &mut out, depth),
            // ...
        };
    }
    // post-loop cleanup (backslash line continuation, normalize_newlines, finalize incomplete modes)
    // ...
}
```

### 2. Extract Normal-mode sub-logic into focused helpers

Within `handle_mode_normal`, the string-start and comment-start detection are separated into:

- `fn try_string_start(&mut self, bytes: &[u8], i: usize, len: usize, out: &mut Vec<u8>) -> Option<usize>` — returns `Some(new_i)` if a string started (and updates `self.mode`), `None` if not. When `Some` is returned, the caller must `continue` to skip the trailing `i += 1`.
- `fn try_comment_start(&mut self, bytes: &[u8], i: usize, len: usize, out: &mut Vec<u8>) -> Option<usize>` — same contract for comments.

`handle_mode_normal` calls `try_string_start` first, then `try_comment_start` if no string started. If neither succeeds, the byte is passed through and `i += 1`.

### 3. Preserve exact control flow semantics

The critical invariants that must be preserved:
- When a string/comment **starts**, `self.mode` is updated and `continue` is called (skipping `i += 1`)
- When a string/comment **continues** (already in a non-Normal mode), `self.mode` is updated and `continue` is called
- When no pattern matches in Normal mode, the byte is appended to `out` and `i += 1` happens once at loop bottom
- `self.mode` persists across calls for multi-line tracking (e.g., `/*` on line 1 continues on line 2)

The `Option<usize>` return type for `try_string_start`/`try_comment_start` encodes the "found it / didn't find it" signal that drives the `continue` vs. `i += 1` decision.

## Consequences

### Positive
- `sanitize_line()` drops from ~580 lines to ~60 lines
- Each `handle_mode_*` is independently reviewable and testable
- `try_string_start` / `try_comment_start` separate two independent concerns that were interleaved in the Normal mode arm
- Normal mode becomes comprehensible and easier to extend when adding new languages
- No behavioral change — all preprocessing semantics are preserved

### Negative
- **Behavioral regression risk is HIGH** if method extraction breaks state machine semantics. The implementor must produce an annotated "after" sketch of `handle_mode_normal` showing the `Option<usize>` contract before coding.
- More methods on `Preprocessor` — though each is single-purpose and well-named
- No change to the public API, but private method signatures are part of the module's internal API

## Alternatives Considered

### 1. Suppress the lint
`#[allow(clippy::too_many_lines)]` on `sanitize_line()`. Rejected — the function genuinely violates the principle of single responsibility. Suppressing the lint defers the problem and signals that the code is acceptable as-is.

### 2. Extract to free functions or a separate module
Move handlers to free functions or a new `modes.rs` submodule. Rejected — the state machine is inherently stateful. Free functions would require threading `&mut self.mode` through every call. A submodule adds unnecessary indirection for what is a straightforward method extraction.

### 3. Split into multiple files
Rejected as premature. The handlers operate on the same data structures and are cohesive. Single-file decomposition via methods is sufficient and lower-risk.
