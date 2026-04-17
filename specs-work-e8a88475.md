# Specification: Add #[must_use] to preprocess.rs Factory/Constructor Methods

## Feature/Behavior Description

Add the `#[must_use]` attribute to 6 factory/constructor functions in `crates/diffguard-domain/src/preprocess.rs` that return `Self` values representing configuration or state that must not be silently dropped.

### Target Functions

| # | Function | Line | Type |
|---|----------|------|------|
| 1 | `PreprocessOptions::none()` | 169 | Factory method |
| 2 | `PreprocessOptions::comments_only()` | 176 | Factory method |
| 3 | `PreprocessOptions::strings_only()` | 183 | Factory method |
| 4 | `PreprocessOptions::comments_and_strings()` | 190 | Factory method |
| 5 | `Preprocessor::new(opts: PreprocessOptions) -> Self` | 272 | Constructor |
| 6 | `Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self` | 281 | Constructor |

### Placement
The `#[must_use]` attribute shall be placed immediately before `pub fn` on its own line, matching the established pattern in `suppression.rs` and `overrides.rs`:

```rust
#[must_use]
pub fn none() -> Self {
    // ...
}
```

## Acceptance Criteria

1. **`cargo check -p diffguard-domain` succeeds without errors**
   - After adding `#[must_use]` to all 6 functions, the code compiles cleanly
   - No new warnings or errors introduced by the change

2. **`cargo test -p diffguard-domain` passes without warnings related to `#[must_use]`**
   - All existing tests continue to pass
   - No test code uses `let _ = Preprocessor::...` or `let _ = PreprocessOptions::...` patterns that would trigger `#[must_use]` warnings
   - Tests in `properties.rs`, `preprocess.rs` unit tests, `evaluate.rs`, and `fuzz/fuzz_targets/rule_matcher.rs` all continue to work

3. **`#[must_use]` appears exactly 6 times in `preprocess.rs`**
   - One instance before each target function
   - No other functions in `preprocess.rs` receive `#[must_use]` (scope is limited to the 6 specified)

4. **Functions are identifiable by signature, not just line number**
   - The implementer verifies line numbers before editing (line numbers may have drifted)
   - Use `pub fn none() -> Self`, `pub fn comments_only() -> Self`, etc. as anchor patterns

## Non-Goals

- Adding `#[must_use]` to any other functions in `preprocess.rs` (e.g., `track_strings()`, `reset()`, `set_language()`)
- Adding `#[must_use]` to functions in other files
- Any behavioral changes to the codebase
- Changes to any tests

## Dependencies

- The change depends on the existing codebase being in a compilable state
- No new dependencies are introduced
- The pattern is already established in `suppression.rs`, `overrides.rs`, and `diff_builder.rs`