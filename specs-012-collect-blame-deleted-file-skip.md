# Specs-012: Skip git blame for deleted file paths in collect_blame_allowed_lines

## Feature: Defensive deleted-file filtering in collect_blame_allowed_lines

### Work Item
**work-e1353518**

### Issue
GitHub issue #223: `collect_blame_allowed_lines` runs `git blame` on deleted-file paths — wasted work and misleading results

## Description

Modify `collect_blame_allowed_lines` to detect deleted file paths from `diff_text` and skip `git_blame_porcelain` calls for those paths. This prevents wasted work when `git blame` would fail (file not found at `head_ref`) and avoids potentially misleading attribution results.

### Behavior

**Before (problematic):**
```rust
for (path, lines) in lines_by_path {
    let blame_text = git_blame_porcelain(head_ref, &path)?; // Called even for deleted files
    // ...
}
```

**After (fixed):**
```rust
let deleted_paths = extract_deleted_paths(diff_text);

for (path, lines) in lines_by_path {
    if deleted_paths.contains(path) {
        debug!("skipping git blame for deleted file: {}", path);
        continue;
    }
    let blame_text = git_blame_porcelain(head_ref, &path)?;
    // ...
}
```

### Implementation Details

1. **Deleted-path extraction**: Scan `diff_text` for `diff --git a/<path> b/<path>` followed by `deleted file mode <mode>`. Use existing `is_deleted_file` and `parse_diff_git_line` functions from `diffguard-diff` crate.

2. **Skip git_blame_porcelain**: For paths in the deleted set, skip the `git_blame_porcelain` call entirely and continue to the next path.

3. **Return empty result**: Lines from deleted files are not valid for blame attribution at `head_ref`, so they should be skipped (not added to the allowed lines set).

## Acceptance Criteria

1. **No git blame on deleted files**: For a diff containing a deleted file, `collect_blame_allowed_lines` must not call `git_blame_porcelain` for that file's path.

2. **Non-deleted files unaffected**: Files that are added, modified, or changed (not deleted) must still have `git_blame_porcelain` called normally.

3. **Scope guard preserved**: The existing guard that prevents `Scope::Deleted` from using blame filters remains unchanged.

4. **Graceful degradation**: If deleted-file detection has edge-case bugs, `git_blame_porcelain` failures are handled gracefully (error is propagated, not silently ignored).

5. **No API changes**: `parse_unified_diff` public API is unchanged; all other callers are unaffected.

## Non-Goals

1. **Root-cause fix**: This spec does not investigate or fix potential bugs in `parse_unified_diff` that might leak deleted files. It provides defensive filtering regardless.

2. **Misleading results fully addressed**: This spec only addresses the "wasted work" case (file not found at `head_ref`). The "misleading results" case (file exists but was deleted later) is not addressed.

3. **API extension**: Returning deleted-path metadata from `parse_unified_diff` is deferred to future work.

## Dependencies

- `diffguard-diff` crate: Uses `is_deleted_file()` and `parse_diff_git_line()` functions
- Existing tests in `diffguard-diff` for deleted-file handling
- Scope guard at `main.rs:2393` (unchanged)
