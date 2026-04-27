# ADR-564d12dd: Close Issue #326 as Duplicate of #257

## Status
Accepted

## Context

GitHub issue #326 was opened reporting a `clippy::redundant_else` warning in `main.rs` at line 2870, describing an unnecessary `else` block after an `if let` in the `cmd_test` function's `rules.is_empty()` check.

However, investigation revealed that:
- The exact fix described in #326 was already applied in commit `31b8b6c` (April 13, 2026)
- That commit closed issue #257 (which reported the same bug)
- Issue #326 is a duplicate that was never formally closed
- The correct fixed code is present at lines 2887-2892

## Decision

**No code changes are required.** The fix was already applied. The appropriate remediation is to close issue #326 as a duplicate of #257, which was already resolved.

The code at lines 2887-2892 in `crates/diffguard/src/main.rs` is:
```rust
if rules.is_empty() {
    if let Some(filter) = &args.rule {
        bail!("No rules match filter '{}'", filter);
    }
    bail!("No rules defined in configuration");
}
```

This follows the correct Rust idiom: unconditional bail after conditional bail-within-if, with no redundant `else`.

## Consequences

### Positive
- No code changes needed, eliminating regression risk
- Issue tracker hygiene restored: #326 closed as duplicate of #257
- `cargo clippy --package diffguard` produces zero warnings

### Negative
- None — this is a verification-only resolution

### Neutral
- Feature branch will contain no code commits (verification-only work item)
- Issue #326 was left open longer than #257 due to duplicate filing

## Alternatives Considered

1. **Re-apply the fix as a new commit** — Rejected. The fix is already present. Creating a redundant commit pollutes history and offers no benefit.

2. **Ignore the duplicate issue** — Rejected. Leaving #326 open creates issue tracker noise and undermines the conveyor's governance promise of closed-loop issue resolution.

3. **Create an ADR for the fix itself** — Rejected. The fix was already documented in #257's closure. Creating a new ADR for code that already exists is ceremony without value.

## Resolution

- Issue #326 closed as duplicate of #257 via `gh issue close 326 --reason duplicate`
- No code commits required
- Work item closed as "verified — no action needed"
