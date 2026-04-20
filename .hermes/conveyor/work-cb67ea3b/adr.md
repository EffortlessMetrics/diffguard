# ADR-0351: Fix `trim_snippet` to Use Match Bounds via `safe_slice`

## Status
Proposed

## Context

Issue [#351](https://github.com/EffortlessMetrics/diffguard/issues/351) reports that `trim_snippet` in `evaluate.rs` hardcodes `MAX_CHARS = 240` internally and ignores match bounds. The issue title claims `safe_slice` end param is unused, but analysis shows `safe_slice` DOES use its `end` param correctly — the real problem is that `trim_snippet` does not USE `safe_slice` at all.

When building a `Finding` (line 307), `trim_snippet` receives only the full line content (`&prepared.line.content`) and truncates from the **start** of the line, completely ignoring where the actual match occurs. Meanwhile, `match_text` on line 306 correctly uses `safe_slice` with proper start/end bounds.

The `Finding` struct documents `snippet` as "for context" but the current behavior provides misleading context — it shows the first 240 characters of the line, not the matched region.

### Key Structural Issue

`RawMatchEvent` and `MatchEvent` only store `match_start`, not `match_end`. The `end` position is computed by `first_match()` but discarded instead of being preserved through the event pipeline.

## Decision

We will fix `trim_snippet` to accept `start` and `end` parameters and use `safe_slice` internally for bounded extraction. This requires:

1. **Add `match_end: Option<usize>` to `RawMatchEvent`** — preserve end position through the pipeline
2. **Add `match_end: Option<usize>` to `MatchEvent`** — propagate to match processing
3. **Propagate `end` in `find_positive_matches_for_rule`** (line 401) — capture `end` from `first_match`
4. **Propagate `end` in `find_multiline_matches`** (line 459) — capture `end` for multiline matches
5. **Update `trim_snippet(s: &str) -> String` to `trim_snippet(s: &str, start: usize, end: usize) -> String`** — use bounds
6. **Update `Finding` construction** (line 307) to pass match bounds to `trim_snippet`

### Semantic Outcome

After the fix, `snippet` will be the bounded matched region (identical to `match_text`), because:
- `match_text` is extracted via `safe_slice(line.content, start, end)` at line 306
- `snippet` will be extracted via `safe_slice(line.content, start, end)` at line 307 (after fix)
- Both use the same `line.content` and the same `start`/`end` bounds

This is **correct and intentional** because:
- The issue author explicitly wants bounds-based extraction
- The "context" that `snippet` was supposed to provide was already broken (truncated from line start, not from match)
- Making `snippet` equal to `match_text` is the straightforward fix

### Alternative Considered: Preserve Line Context

**Option B (Rejected)**: Keep `snippet` as showing a window around the match (e.g., 50 chars before + matched region + 50 chars after), preserving the "context" semantics.

Rejected because:
- The issue author explicitly wants `trim_snippet` to USE `safe_slice` with the match bounds
- Adding a "context window" feature is out of scope for this issue
- The current "context" (first 240 chars of line) was already not meaningful context

### Alternative Considered: Max_chars Configurable

**Option C (Rejected)**: Keep `trim_snippet` unchanged, just make `MAX_CHARS` a configurable parameter.

Rejected because:
- Does not address the core problem of `trim_snippet` not using match bounds
- The issue author explicitly mentions `safe_slice` end param, indicating they want bounds-based extraction

## Consequences

### Benefits
- `snippet` will correctly represent the matched region, not arbitrary truncation from line start
- The fix reuses existing `safe_slice` infrastructure which already handles Unicode correctly
- `match_end` propagation enables future features that need end positions

### Tradeoffs
- `snippet` and `match_text` become functionally identical (both = bounded matched region)
- This is a semantic change to the `Finding` API — `snippet` no longer provides "context" beyond `match_text`
- The redundancy is acceptable because the previous `snippet` semantics were already broken

### Risks
- Changing `trim_snippet` signature requires updating its single caller and tests
- Adding `match_end` to event structs affects multiple code paths
- Multiline matches may need special handling for snippet extraction

## Acceptance Criteria

From `specs.md`:
1. `trim_snippet` accepts `start` and `end` parameters and uses `safe_slice` internally
2. `RawMatchEvent` and `MatchEvent` both include `match_end: Option<usize>`
3. `match_end` is properly propagated through both single-line and multiline match paths
4. The test `trim_snippet_truncates_and_appends_ellipsis` is updated to verify bounded extraction
5. `cargo test -p diffguard-domain` passes
