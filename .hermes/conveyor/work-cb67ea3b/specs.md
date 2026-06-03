# Specs: Fix `trim_snippet` to Use Match Bounds

## Feature Description

Fix `trim_snippet` in `crates/diffguard-domain/src/evaluate.rs` to use match bounds (via `safe_slice`) instead of hardcoding `MAX_CHARS = 240` and truncating from line start.

### Current Problem
- `trim_snippet(s: &str)` takes only a string, no match bounds
- It truncates at 240 characters from the **start** of the line, ignoring where the actual match occurs
- `RawMatchEvent` and `MatchEvent` only store `match_start`, discarding the `end` position

### Desired Behavior
- `trim_snippet` receives `start` and `end` parameters indicating the matched region
- It uses `safe_slice` to extract exactly that region (with Unicode-safe bounds clamping)
- If the matched region exceeds 240 characters, it truncates with ellipsis

## Acceptance Criteria

### AC1: `trim_snippet` Signature Updated
- `trim_snippet` changes from `fn trim_snippet(s: &str) -> String` to `fn trim_snippet(s: &str, start: usize, end: usize) -> String`
- The function uses `safe_slice(s, start, end)` internally to extract the bounded region
- The function still applies 240-char truncation with ellipsis for very long matches

### AC2: Event Structs Include `match_end`
- `RawMatchEvent` (line 56) includes `match_end: Option<usize>`
- `MatchEvent` (line 63) includes `match_end: Option<usize>`

### AC3: Single-Line Match Path
- In `find_positive_matches_for_rule` (line 397), the `end` value from `first_match` is captured and stored in `RawMatchEvent.match_end`
- The Finding construction (line 307) passes `event.match_start.unwrap()` and `event.match_end.unwrap()` to `trim_snippet`

### AC4: Multiline Match Path
- In `find_multiline_matches` (line 453), the `m_end` value is captured and stored in `RawMatchEvent.match_end`
- Multiline snippet extraction uses the same bounded approach

### AC5: Test Updated
- `trim_snippet_truncates_and_appends_ellipsis` test is updated to:
  - Pass `start` and `end` parameters to `trim_snippet`
  - Verify bounded extraction (string within [start, end) range)
  - Verify ellipsis is appended only when bounded region exceeds 240 chars

### AC6: Documentation
- The `Finding` struct documentation in `diffguard-types/src/lib.rs` is updated to clarify that `snippet` is the bounded matched region (not full line context)

## Non-Goals

- This fix does NOT add a "context window" feature (e.g., showing chars before/after the match)
- This fix does NOT make `MAX_CHARS` configurable — the hardcoded 240 remains as a safety limit
- This fix does NOT change `match_text` behavior — it remains the bounded matched text

## Dependencies

- `safe_slice` function (already exists, line 584)
- `first_match` function (already returns `(start, end)` tuple, end was just discarded)
- `RawMatchEvent` and `MatchEvent` structs (need `match_end` field added)

## Test Plan

1. Run existing tests: `cargo test -p diffguard-domain`
2. Update `trim_snippet_truncates_and_appends_ellipsis` test
3. Run tests again to verify: `cargo test -p diffguard-domain`
4. Run full test suite: `cargo test --workspace` (optional, for regression checking)
