# Initial Plan: work-039daebf

## Status: Research Complete — Fix Already Applied

The refactoring described in issue #140 has already been completed in this worktree.

## Approach

Since the fix is already applied, the approach for future reference would be:

### Original Fix Steps (Reference)
1. **Change function signature** from `Result<BTreeMap<u32, BlameLineMeta>>` to `BTreeMap<u32, BlameLineMeta>` because the function never returns Err
2. **Change return statement** from `Ok(out)` to `out` because the Result wrapper is unnecessary
3. **Update caller** in `collect_blame_allowed_lines` — remove `.with_context()` and `?` because parse_blame_porcelain no longer returns Result
4. **Update test** `parse_blame_porcelain_extracts_line_metadata` — remove `.expect("parse")` because the function cannot fail
5. **Verify** with `cargo clippy -p diffguard` and `cargo test -p diffguard` to ensure no regressions

### Current State Verification
- [ ] Run `cargo clippy -p diffguard` to confirm no lint warnings
- [ ] Run `cargo test -p diffguard` to confirm all tests pass

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Regression in blame parsing logic | Low | High | Existing test `parse_blame_porcelain_extracts_line_metadata` validates core behavior |
| Silent data loss from malformed entries | Low | Low | This is intentional design because incomplete metadata is tolerable for diff checking |

## Task Breakdown

### Completed
- [x] Investigate `parse_blame_porcelain` function
- [x] Review existing spec and ADR documents
- [x] Verify fix has been applied
- [x] Identify all call sites

### Pending Verification
1. Run clippy check
2. Run full test suite

## Files Reference

| File | Purpose |
|------|---------|
| `crates/diffguard/src/main.rs:1764` | Function definition |
| `crates/diffguard/src/main.rs:1857` | Caller in `collect_blame_allowed_lines` |
| `crates/diffguard/src/main.rs:4063` | Test function |
| `specs-011-parse-blame-porcelain-result.md` | Specification document |
| `adr-011-parse-blame-porcelain-result.md` | Architecture decision record |
