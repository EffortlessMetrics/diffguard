# Specs — work-19033993

## Feature/Behavior Description
Resolution of GitHub issue #503: `clippy::items_after_statements` lint violation in `server.rs:921` (`run_git_diff()` function). The issue reported that `const GIT_DIFF_TIMEOUT` was declared after executable statements, which is visually misleading.

## Current State (Already Resolved)
The lint violation was fixed in commit `b604bf2` (PR #525). The current state of `run_git_diff()` at lines 912-952:

```rust
fn run_git_diff(...) -> Result<String> {
    // Spawn with a 10-second timeout...
    const GIT_DIFF_TIMEOUT: Duration = Duration::from_secs(10);  // Line 914 ✓

    let mut command = Command::new("git");  // Line 916 (first statement)
    command.current_dir(workspace_root).arg("diff");
    // ...
}
```

**No code changes are required.**

## Acceptance Criteria

### AC1: No clippy warnings
- [x] `cargo clippy -p diffguard-lsp` runs without `items_after_statements` warnings
- Verification: Run `cargo clippy -p diffguard-lsp 2>&1 | grep items_after_statements` returns empty

### AC2: Const declared before statements
- [x] `const GIT_DIFF_TIMEOUT` is at line 914, before the first executable statement at line 916
- Verification: `grep -n "const GIT_DIFF_TIMEOUT" crates/diffguard-lsp/src/server.rs` shows line ~914

### AC3: GitHub issue closed
- [ ] GitHub issue #503 is closed with reason "resolved" and references PR #525
- Verification: `gh issue view 503 --json state` shows "closed"

### AC4: Documentation complete
- [x] ADR created documenting the "close as already fixed" decision
- [x] Specs document the acceptance criteria and current state

## Non-Goals
- This spec does NOT require writing new code — the fix is already present
- This spec does NOT change any API or behavior — only closes an already-resolved issue
- This spec does NOT merge duplicate issues #469 and #503 (flagged for future consideration)

## Dependencies
- None — all acceptance criteria can be verified against the current codebase
- Closing the GitHub issue requires write access to the diffguard repository