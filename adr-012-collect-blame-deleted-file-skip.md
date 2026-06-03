# ADR-012: Defensive Deleted-File Filtering in collect_blame_allowed_lines

## Status
**Proposed**

## Work Item
**work-e1353518**

## Context

GitHub issue #223 reports that `collect_blame_allowed_lines` runs `git blame` on paths to deleted files, causing:
1. **Wasted work** — `git blame` on a deleted file path fails or returns meaningless data
2. **Misleading results** — if `git blame` succeeds, attribution is for the previous version, not the deleted state

### Code Analysis Findings

1. **`parse_unified_diff` (diffguard-diff crate) correctly skips deleted files** for non-deleted scopes (`Added`, `Changed`, `Modified`). When it encounters `deleted file mode`, it sets `skip_current_file = true` for these scopes.

2. **Scope guard at line 2393** prevents `Scope::Deleted` from reaching `collect_blame_allowed_lines` entirely:
   ```rust
   if matches!(scope, Scope::Deleted) {
       bail!("blame-aware filters are not supported with --scope deleted");
   }
   ```

3. **Tests confirm correct behavior** — `parse_unified_diff` tests at lines 1076–1127 verify deleted-file handling.

4. **The issue claim contradicts code analysis** — if `parse_unified_diff` correctly skips deleted files and the scope guard prevents `Scope::Deleted` from reaching `collect_blame_allowed_lines`, then `git_blame_porcelain` should not be called on deleted file paths for non-deleted scopes.

### Contradiction

- Issue asserts `git blame` is called on deleted files
- Code analysis shows this should not happen for standard diffs
- Possible explanations: edge case not caught by tests, different code path, or inaccurate issue description

## Decision

**Implement defensive deleted-file filtering in `collect_blame_allowed_lines`** by scanning `diff_text` for `deleted file mode` patterns and skipping `git_blame_porcelain` calls for those paths.

### Rationale

1. **Defensive depth** — Even if `parse_unified_diff` has edge-case bugs that leak deleted files, this filter provides a safety net.

2. **Addresses reported issue** — The reported symptom (wasted `git blame` calls) is addressed directly, regardless of whether the root cause is in `parse_unified_diff` or elsewhere.

3. **No API changes** — The fix doesn't modify `parse_unified_diff`'s public API, avoiding blast radius to other callers.

4. **Minimal implementation** — Uses existing `is_deleted_file` and `parse_diff_git_line` functions from `diffguard-diff`, avoiding full re-implementation.

### What This Fix Addresses

- **Wasted work (file not found)**: When a file was deleted at `head_ref`, `git blame` fails with exit code 128. Skipping the call prevents wasted work.

### What This Fix Does NOT Address

- **Misleading results**: If a file was deleted AFTER `head_ref` (exists at `head_ref` but not in working directory), `git blame` would succeed but attribute to the wrong version. This case requires verifying file existence at `head_ref`, not just diff-text analysis.

## Consequences

### Benefits
- Prevents unnecessary `git blame` calls on deleted files
- Provides defensive depth against edge-case bugs in `parse_unified_diff`
- Self-contained fix with minimal blast radius

### Risks / Tradeoffs
1. **DRY violation** — Duplicates deleted-file detection logic from `parse_unified_diff`. If git's diff format changes, both places must be updated.

2. **Band-aid on unknown wound** — If the root cause is a bug in `parse_unified_diff`, this fix masks it rather than fixing it.

3. **Misleading results unaddressed** — The "misleading results" aspect of the issue title is only partially addressed (wasted-work case only).

4. **Architectural ambiguity** — Future developers may not know which deleted-file detection is authoritative.

## Alternatives Considered

### Alternative 1: Fix `parse_unified_diff` to return deleted paths
- **Pros**: Single source of truth, proper fix if root cause is there
- **Cons**: Changes public API, affects other callers, more invasive
- **Decision**: Deferred. If deleted files leak through despite `parse_unified_diff`'s existing logic, that bug should be fixed in `parse_unified_diff` directly.

### Alternative 2: Do nothing and require root-cause investigation first
- **Pros**: Avoids technical debt, maintains architectural integrity
- **Cons**: Doesn't address reported issue, leaves user pain unresolved
- **Decision**: Rejected. The reported issue (wasted work) is real and the defensive fix addresses it.

### Alternative 3: Extend `parse_unified_diff` with new non-breaking API
- **Pros**: Doesn't break existing callers, centralizes logic
- **Cons**: More complex, requires versioning strategy
- **Decision**: Deferred. This is a better long-term approach but requires more design work.

## Future Work

1. **Root-cause investigation**: If deleted files can leak through `parse_unified_diff` despite existing tests, identify and fix the edge case.

2. **Misleading results fix**: If attribution-to-wrong-version is a real concern, add logic to verify file existence at `head_ref` before trusting blame results.

3. **API extension**: Consider extending `parse_unified_diff` to return metadata about deleted paths, eliminating the need for re-scanning in callers.
