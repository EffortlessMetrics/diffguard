# ADR-2026-0417-001: Add #[must_use] to PreprocessOptions and Preprocessor Factory/Constructor Methods

## Status
**Proposed**

## Context
Issue #541 identifies 6 functions in `crates/diffguard-domain/src/preprocess.rs` that return `Self` values representing configuration or state that must not be silently dropped, but lack the `#[must_use]` attribute. This creates an inconsistency with similar functions in the codebase that received `#[must_use]` in recent commits:

- Commit `e0c2094`: Added `#[must_use]` to `RuleOverrideMatcher::resolve()` in `overrides.rs`
- Commit `e0c2094`: Added `#[must_use]` to builder structs in `diff_builder.rs`
- Commit `3e1d9e1`: Added `#[must_use]` to `parse_suppression()` and `parse_suppression_in_comments()` in `suppression.rs`

The 6 candidate functions are:
1. `PreprocessOptions::none()` — factory method returning configuration
2. `PreprocessOptions::comments_only()` — factory method returning configuration
3. `PreprocessOptions::strings_only()` — factory method returning configuration
4. `PreprocessOptions::comments_and_strings()` — factory method returning configuration
5. `Preprocessor::new(opts: PreprocessOptions) -> Self` — constructor
6. `Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self` — constructor

All usages across 100+ locations in the codebase properly capture the return values, confirming that ignoring them would be a bug.

## Decision
Add `#[must_use]` to the 6 specified factory/constructor functions in `crates/diffguard-domain/src/preprocess.rs`:
- `PreprocessOptions::none()` (line 169)
- `PreprocessOptions::comments_only()` (line 176)
- `PreprocessOptions::strings_only()` (line 183)
- `PreprocessOptions::comments_and_strings()` (line 190)
- `Preprocessor::new(opts: PreprocessOptions) -> Self` (line 272)
- `Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self` (line 281)

The attribute shall be placed immediately before the `pub fn` declaration on its own line, matching the established pattern in `suppression.rs` and `overrides.rs`.

## Consequences

### Benefits
1. **Compile-time bug prevention**: Catches bugs at compile time when callers accidentally ignore return values
2. **Consistency**: Aligns `preprocess.rs` with the `#[must_use]` pattern established in `suppression.rs`, `overrides.rs`, and `diff_builder.rs`
3. **Self-documenting API**: The attribute explicitly communicates that these return values represent state/config that must not be dropped
4. **No behavioral changes**: Purely additive lint attribute that produces warnings, not errors
5. **No breaking changes**: Adding `#[must_use]` is backward-compatible; existing code continues to work

### Risks
1. **GitHub API friction**: Post-comment API calls consistently fail with `BadRequestError [HTTP 400]` across all gates; findings may not reach GitHub automatically
2. **Incomplete pattern application**: Other similar functions in `diffguard-domain` (e.g., `Language::from_extension()`, factory methods in `rules.rs`) may also be candidates but are out of scope for this issue
3. **No warning cascade**: Verified that no existing code uses `let _ = Preprocessor::...` or `let _ = PreprocessOptions::...` patterns, so no compiler warnings will be introduced

## Alternatives Considered

### 1. No action (leave as-is)
**Rejected because**: The inconsistency with recently-updated files (`suppression.rs`, `overrides.rs`, `diff_builder.rs`) would remain. The codebase has already committed to the `#[must_use]` pattern for similar functions; leaving these 6 without it is a gap.

### 2. Apply `#[must_use]` to all `-> Self` functions in `preprocess.rs` broadly
**Rejected because**: The issue is scoped to 6 specific functions. A broader application would increase scope and risk. Future issues can address additional functions if warranted.

### 3. Apply `#[must_use]` to the struct definitions instead of individual functions
**Rejected because**: The established pattern in this codebase places `#[must_use]` on the `fn` line directly (see `suppression.rs:46`, `overrides.rs:108`), not on struct definitions. The struct-level `#[must_use]` (as seen in `diff_builder.rs:90,150`) applies to the builder pattern where the struct itself is the return value, not to free factory methods.

## Notes
- The implementer should use function signatures as anchors (e.g., `pub fn none() -> Self`), not line numbers, since line numbers may drift if the file is edited before the fix is applied
- All tests must pass after the change; run `cargo test -p diffguard-domain` to verify
- No other files in the codebase require modification for this change