# Spec: Decompose sanitize_line() via Mode Handler Methods

## Feature / Behavior Description

Refactor the `sanitize_line()` method in `crates/diffguard-domain/src/preprocess.rs` from a ~580-line monolithic method into a compact dispatch loop with private handler methods. The refactoring is purely structural — no changes to preprocessing semantics, language support, masking behavior, or multi-line state tracking.

### What changes

1. `sanitize_line()` is reduced to a `while i < len` dispatch loop (~60 lines) that calls `handle_mode_*` methods for each `Mode` variant
2. Each `Mode` variant arm becomes a private `handle_mode_<variant>()` method on `Preprocessor` returning `usize` (the updated byte index `i`)
3. `Mode::Normal` arm delegates to two focused helpers:
   - `try_string_start()` — returns `Some(new_i)` if a string started (and updated `self.mode`), `None` if not
   - `try_comment_start()` — returns `Some(new_i)` if a comment started (and updated `self.mode`), `None` if not
4. Post-loop cleanup (backslash line continuation, `normalize_newlines`, finalizing incomplete multi-line modes) remains in `sanitize_line()`

### What does NOT change

- No changes to the `Mode`, `Language`, `CommentSyntax`, `StringSyntax`, `Preprocessor`, or `PreprocessOptions` types
- No changes to any public API
- No changes to masking or detection semantics — every branch's behavior is preserved exactly
- No changes to test files or fuzz targets
- No changes outside `preprocess.rs`

## Acceptance Criteria

### AC1: clippy passes
`cargo clippy -p diffguard-domain` reports zero `clippy::too_many_lines` warnings for `preprocess.rs`.

### AC2: all tests pass
`cargo test -p diffguard-domain` passes with all 375+ existing tests passing. No test may be modified or skipped.

### AC3: sanitize_line body is ≤~150 lines
After refactoring, `sanitize_line()` body (the function signature through all declarations before the `while` loop, the loop itself, and the post-loop cleanup) is no more than ~150 lines. This is measured by `sed -n '/pub fn sanitize_line/,/^fn \|^impl \|^struct \|^enum /p' preprocess.rs | wc -l` and should be ≤150.

### AC4: one handler method per Mode variant
Each `Mode` variant (`Normal`, `LineComment`, `BlockComment`, `NormalString`, `RawString`, `Char`, `TemplateLiteral`, `TripleQuotedString`, `ShellLiteralString`, `ShellAnsiCString`, `XmlComment`) has a corresponding private `handle_mode_*` method on `Preprocessor`.

### AC5: Normal mode uses try_string_start and try_comment_start helpers
`handle_mode_normal` calls `try_string_start()` and `try_comment_start()` to detect string and comment starts. Both return `Option<usize>` encoding whether the pattern was found.

### AC6: state machine semantics preserved
The refactoring must preserve:
- Multi-line state tracking: if `/*` starts on line N, `self.mode = BlockComment { depth: 1 }` and subsequent `sanitize_line()` calls on lines N+1, N+2, etc. continue in `BlockComment` mode until `*/` is found
- Byte-level index progression: exactly one `i` increment per byte consumed (except when `continue` is used to skip the increment after starting a string/comment)
- All 18 languages' string and comment syntax detection remain identical

### AC7: no new APIs exposed
All extracted methods are `fn ...(&mut self, ...)` private methods. No new `pub fn` or `pub struct` types are added.

## Non-Goals

- No new language support
- No changes to the fuzz target or test files
- No behavioral changes — pure code reorganization
- No changes to `normalize_newlines`, `mask_range`, `detect_raw_string_start`, or `detect_triple_quote_start` helpers (already separate and fine)

## Dependencies

- All 375+ existing tests in `diffguard-domain` as regression suite
- Fuzz target `fuzz/fuzz_targets/preprocess.rs` for additional coverage
- The implementor must produce an annotated "after" sketch of `handle_mode_normal` showing the `Option<usize>` control-flow contract before writing code (per Plan Reviewer recommendation)
