# ADR-0323: Remove Vestigial .min(u32::MAX) Clamps from usize→u32 Casts in diffguard-analytics

## Status
Proposed

## Context
Issue #323 identifies two instances in `crates/diffguard-analytics/src/lib.rs` where `usize` values from `Vec::len()` calls are unnecessarily clamped to `u32::MAX` before casting to `u32`:

1. Line 228: `receipt.findings.len().min(u32::MAX as usize) as u32` in `trend_run_from_receipt`
2. Line 281: `history.runs.len().min(u32::MAX as usize) as u32` in `summarize_trend_history`

These clamps are described as "vestigial" — remnants that no longer serve a practical purpose but obscure the intent of the code. A `Vec` with more than 2^32 elements (~4.3 billion) would require approximately 16 exabytes of memory, which is physically impossible on any current hardware.

## Decision
Remove the `.min(u32::MAX as usize)` clamps from both locations, replacing them with direct `as u32` casts:

1. `receipt.findings.len().min(u32::MAX as usize) as u32` → `receipt.findings.len() as u32`
2. `history.runs.len().min(u32::MAX as usize) as u32` → `history.runs.len() as u32`

This is safe because the values being cast (`Vec::len()`) can never realistically exceed `u32::MAX` due to memory constraints.

## Consequences

### Benefits
- **Clarity**: Code intent is immediately obvious — lossy conversion is accepted
- **Consistency**: Aligns with the codebase's pragmatic approach to such conversions
- **Reduced noise**: Removes defensive code for an impossible overflow scenario

### Tradeoffs
- **Clippy warning**: `cast_possible_truncation` may trigger — acceptable per issue author, can be suppressed with `#[allow(...)]` if needed
- **Theoretical semantic change**: If (impossibly) a Vec exceeded u32::MAX, behavior would change from capping to truncating

## Alternatives Considered

### Alternative 1: Keep clamps with explanatory comment
```rust
// Defensive clamp omitted: Vec::len() cannot exceed u32::MAX in practice
findings: receipt.findings.len() as u32,
```
**Rejected**: The comment itself is noise. If the clamp is unnecessary, no comment is needed either.

### Alternative 2: Use checked conversion with unwrap_or
```rust
findings: u32::try_from(receipt.findings.len()).unwrap_or(u32::MAX),
```
**Rejected**: This approach implies there is a realistic error path to handle. For `Vec::len()` on realistic inputs, this is misleading. The issue author explicitly characterizes these clamps as "vestigial," implying full removal is appropriate.

### Alternative 3: Add #[allow(clippy::cast_possible_truncation)] without removing clamp
**Rejected**: This leaves the unnecessary clamp in place, perpetuating the code smell identified in issue #323.

## References
- Issue: https://github.com/EffortlessMetrics/diffguard/issues/323
- Related commit: e38e907 (fix: replace lossy usize→u32 casts with checked conversions #535) — different context (diffguard-domain)
