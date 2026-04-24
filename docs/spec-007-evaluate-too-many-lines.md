# Spec — work-76372a5b: Refactor `evaluate_lines_with_overrides_and_language`

## Feature/Behavior Description
Refactor `evaluate_lines_with_overrides_and_language` in `crates/diffguard-domain/src/evaluate.rs` by extracting helper functions to bring the function under 100 lines (clippy limit). The extraction must preserve exact existing behavior, including the public API signature.

## Acceptance Criteria

1. **`cargo clippy -p diffguard-domain -- -W clippy::too-many_lines` passes** — The `evaluate_lines_with_overrides_and_language` function must have ≤100 lines after refactoring.

2. **`cargo test -p diffguard-domain` passes** — All existing tests in the `diffguard-domain` crate pass without modification. This verifies behavior is preserved.

3. **Public API unchanged** — The `evaluate_lines_with_overrides_and_language` function signature (parameters and return type) is identical before and after refactoring.

4. **Three private helpers extracted** — The following helper functions are extracted and called from the main function:
   - `prepare_lines()` — handles line preparation phase
   - `generate_match_events()` — handles match event generation phase
   - `collect_findings()` — handles findings collection phase

## Non-Goals

- This work does NOT fix `preprocess.rs:304` (465-line `sanitize_line` function) — that is a separate work item.
- This work does NOT change any function signatures, preprocessing logic, or rule matching logic.
- This work does NOT add new tests (though existing tests serve as verification).

## Dependencies

- The implementation must handle stateful preprocessors (`Preprocessor::set_language()` mutates in place)
- The implementation must handle `SuppressionTracker` which accumulates state across lines within a file
- The extracted helpers must return sufficient state (e.g., `files_seen` count) for the main function to use
