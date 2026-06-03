# ADR — work-0ee52eea: items_after_statements lint in evaluate.rs:563

## Status
Accepted

## Context
GitHub issue #469 reported a Clippy `items_after_statements` lint at `evaluate.rs:563`,
claiming `const MAX_CHARS: usize = 240;` inside `fn trim_snippet()` was declared after
an executable statement (`let trimmed = s.trim_end();`).

The work item was created to fix this ordering. However, investigation revealed the fix was
already merged two days before the work item was created.

## Decision
**No code change is required.** The issue was already resolved in commit `b604bf2`
(April 15, 2026) as part of PR #525, which swapped the order of `const MAX_CHARS`
and `let trimmed` in `fn trim_snippet()`. The `const` is now correctly placed at
line 562, before `let trimmed` at line 563.

The work item is marked **stale** — the fix predates the conveyor routing.

## Consequences

### Benefits
- No CI resources spent on unnecessary changes
- No functional change to the codebase
- Clean Clippy signal maintained

### Tradeoffs / Risks
- Work item consumed conveyor cycles after the issue was already closed
- Potential conveyor state inconsistency when work items reference non-existent branches

### Mitigation
- Future lint-scanner work items should check if the referenced commit is already merged
  before routing through the conveyor pipeline

## Alternatives Considered

### 1. Create a no-op PR
Create a minimal commit noting the issue was already fixed.  
**Rejected:** Adds noise to the PR history and wastes CI resources on a meaningless change.

### 2. Auto-close stale work items
Detect when the referenced issue is already closed and skip conveyor routing.  
**Rejected (current):** Would require changes to the conveyor dispatch logic. Handled
by closing the work item manually at this gate.

## References
- GitHub issue #469 (CLOSED)
- Commit `b604bf2` — fix: clippy cleanup — items_after_statements + unnecessary_wrap (#525)
- Commit `f562073` — docs(evaluate.rs): add docstrings to safe_slice and byte_to_column (HEAD)
