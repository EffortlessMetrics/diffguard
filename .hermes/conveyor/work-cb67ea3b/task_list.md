# Task List — work-cb67ea3b

Implementation tasks for fixing `trim_snippet` to use match bounds via `safe_slice`.

## Implementation Tasks

- [ ] Add `match_end: Option<usize>` to `RawMatchEvent` struct (line 56)
- [ ] Add `match_end: Option<usize>` to `MatchEvent` struct (line 63)
- [ ] Propagate `end` value in `find_positive_matches_for_rule` (line 401)
- [ ] Propagate `end` value in `find_multiline_matches` (line 459)
- [ ] Update `trim_snippet` signature from `fn trim_snippet(s: &str) -> String` to `fn trim_snippet(s: &str, start: usize, end: usize) -> String`
- [ ] Have `trim_snippet` use `safe_slice` internally for bounded extraction
- [ ] Update `Finding` construction (line 307) to pass match bounds to `trim_snippet`
- [ ] Update `Finding` struct documentation in `diffguard-types/src/lib.rs` to clarify snippet semantics
- [ ] Update test `trim_snippet_truncates_and_appends_ellipsis` to verify bounded extraction
- [ ] Run tests: `cargo test -p diffguard-domain`

## Verification

- [ ] All existing tests pass: `cargo test -p diffguard-domain`
- [ ] New behavior verified: snippet = bounded matched region (same as match_text)
