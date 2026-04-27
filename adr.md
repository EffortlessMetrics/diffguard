# ADR-086: Confirm checkstyle.rs Severity Mapping is Correct (Issue #486)

## Status
Accepted

## Context
GitHub Issue #486 reported that in `checkstyle.rs`, both `Warn` and `Info` severities mapped to `"warning"`, making them indistinguishable in output. This was investigated by multiple agents.

The investigation revealed:
- **The bug was already fixed** in commit `b31d836` ("fix(checkstyle): Severity::Info maps to 'info' not 'warning'")
- Issue #486 is a duplicate of issue #443, which was already closed after the fix was merged
- The current code correctly maps:
  - `Severity::Error` → `"error"`
  - `Severity::Warn` → `"warning"`
  - `Severity::Info` → `"info"`

## Decision
**No code changes are required.** The severity mapping in `checkstyle.rs` is correct as-is. The fix from commit `b31d836` is already in place and all tests pass.

The ADR confirms that:
1. `Severity::Info` correctly maps to `"info"` (line 74 of `checkstyle.rs`)
2. The mapping matches the documented behavior in `CHANGELOG.md` line 57
3. Issue #486 should be closed as "Completed" (not a duplicate, since #443 is already closed)

## Consequences

### Benefits
- No changes needed to codebase
- No risk of regression from unnecessary changes
- Issue #486 is resolved without additional engineering work

### Tradeoffs
- None — the fix is already in place and working correctly

## Alternatives Considered

### Alternative 1: Modify the branch specified in work item
The work item specifies branch `feat/work-7634ff6b/checkstyle.rs:-warn-and-info-both-map-to` which does not exist. Creating this branch and attempting to "fix" already-fixed code would be wasteful and could introduce regressions.

**Rejected** — no code change is needed.

### Alternative 2: Close issue #486 as duplicate of #443
Since #443 is already closed after the fix was merged, closing #486 as duplicate would be accurate but could cause confusion since #443 predates #486.

**Rejected** — the agents recommended closing as "Completed" with note that bug was fixed before issue was filed.

## Artifact References
- Fix: Commit `b31d836` (merged April 15, 2026)
- Code: `crates/diffguard-core/src/checkstyle.rs` lines 71-75
- Documentation: `CHANGELOG.md` line 57
- Tests: `crates/diffguard-core/tests/test_checkstyle_info_severity.rs`
