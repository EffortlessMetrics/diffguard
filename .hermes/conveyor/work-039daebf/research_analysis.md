# Research Analysis: work-039daebf

## Issue Summary and Context

**GitHub Issue:** https://github.com/EffortlessMetrics/diffguard/issues/140  
**Title:** main.rs: parse_blame_porcelain always returns Ok — Result is unnecessary

The issue reports that `parse_blame_porcelain` function in `crates/diffguard/src/main.rs` was typed to return `Result<BTreeMap<u32, BlameLineMeta>>` but never actually returned `Err`. The function silently skips malformed entries via `continue` statements rather than propagating errors, and always succeeded.

## Relevant Codebase Areas

### Primary File
- **`crates/diffguard/src/main.rs`** — Contains the `parse_blame_porcelain` function

### Function Location (Current State - Post-Fix)
- **Line 1764:** Function signature
  ```rust
  fn parse_blame_porcelain(blame_text: &str) -> BTreeMap<u32, BlameLineMeta>
  ```

### Call Sites
1. **Line 1857** (`collect_blame_allowed_lines` function):
   ```rust
   let blame_map = parse_blame_porcelain(&blame_text);
   ```

2. **Line 4063** (Test `parse_blame_porcelain_extracts_line_metadata`):
   ```rust
   let map = parse_blame_porcelain(porcelain);
   ```

### Supporting Infrastructure
- **`git_blame_porcelain`** (Line 1817): Calls `git blame --line-porcelain` and returns `Result<String>`. This is the actual function that can fail (I/O, git errors).
- **`collect_blame_allowed_lines`** (Line 1835): Uses `git_blame_porcelain` with `?` operator to propagate real errors, then calls `parse_blame_porcelain` on the result.

## Dependencies and Constraints

### Dependencies
- `anyhow::Result` type alias used throughout the crate
- `BTreeMap` from standard library
- `BlameLineMeta` struct (defined elsewhere in main.rs)

### Constraints
- The parsing logic silently skips malformed entries (invalid headers, parse failures) — this is **intentional behavior** to handle binary/untrusted files gracefully
- No call site ever checked for `Err` — the `Result` was purely ceremonial
- The `collect_blame_allowed_lines` function properly handles real errors from `git_blame_porcelain` before passing data to `parse_blame_porcelain`

## Key Findings

1. **Fix Already Applied:** The worktree at `run-20260411-160234-aa41d106` has already undergone the refactoring. The function signature is now `BTreeMap<u32, BlameLineMeta>` (not `Result`).

2. **Behavioral Unchanged:** The function's behavior is unchanged — it continues to silently skip malformed entries via `continue` statements. Only the type signature changed.

3. **No Breaking Changes:** All call sites were updated correctly:
   - The caller in `collect_blame_allowed_lines` no longer uses `.with_context()` or `?`
   - The test no longer uses `.expect("parse")`

4. **Existing Spec/ADR:** 
   - `specs-011-parse-blame-porcelain-result.md` documents the specification
   - `adr-011-parse-blame-porcelain-result.md` documents the architecture decision

5. **Rationale is Sound:** The silent-skip behavior is intentional because:
   - Git blame output for binary/untrusted content may contain partial entries
   - The function is used for allowed-line metadata extraction — incomplete data is tolerable
   - Hard failure is not desired for this use case

## Verification Status

The fix appears complete based on:
- Function signature matches the "After" state in the spec
- All call sites updated
- Test at line 4063 uses direct return value without `.expect()`
