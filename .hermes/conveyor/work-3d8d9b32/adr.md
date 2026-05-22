# ADR-0013: Close Issue #289 — Severity::Info Already Maps to "info"

## Status
Accepted

## Context

Issue #289 reported that `checkstyle.rs` had `Severity::Info` and `Severity::Warn` both mapping to the string `"warning"`, causing a `clippy::match_same_arms` warning and making the Info arm dead code.

However, prior investigation found that:
- The bug was already fixed in PR #460 (commit b31d836)
- The current code at `checkstyle.rs:71-75` correctly maps all three severities
- All 28 checkstyle tests pass
- Clippy is clean with no warnings

The issue remains OPEN on GitHub despite the fix being merged.

## Decision

**No code changes are needed.** Issue #289 should be closed as "Already resolved" referencing PR #460.

The current implementation is correct:
```rust
let severity_str = match f.severity {
    Severity::Error => "error",
    Severity::Warn => "warning",
    Severity::Info => "info",  // ← Correct
};
```

## Consequences

### Tradeoffs

| Alternative | Why Rejected |
|-------------|--------------|
| Create new PR with identical fix | Duplicates PR #460, wastes review time, risks new bugs |
| Leave issue open | Misleads contributors, suggests bug still exists |
| Modify working code | Unnecessary churn, no benefit |

### Benefits
- No risk of introducing regressions
- Preserves existing test coverage (`info_maps_to_info` test)
- Issue closure provides clear signal to contributors

### Risks
- Issue #289 must be closed on GitHub to prevent confusion
- If future refactoring moves the severity mapping, regression tests must catch it

## Alternatives Considered

1. **Create duplicate PR** — Rejected: PR #460 already contains the correct fix
2. **Do nothing** — Rejected: Open issue misleads contributors
3. **Modify working code** — Rejected: No benefit, introduces risk

## References

- Issue #289: `checkstyle.rs:50-51: Severity::Info and Severity::Warn produce identical "warning"`
- PR #460: `fix(checkstyle): Severity::Info maps to 'info' not 'warning'`
- Commit `b31d836`: Merge commit that applied the fix