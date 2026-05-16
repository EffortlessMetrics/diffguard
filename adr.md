# ADR-0388: Handle GlobSetBuilder::build() Failures with Typed Errors

## Status
Proposed

## Context

GitHub issue #388 reports that three locations in the diffguard workspace use `GlobSetBuilder::build().expect()` to handle what is actually a recoverable error, not an unreachable panic:

| File | Line | Function |
|------|------|----------|
| `crates/diffguard-core/src/check.rs` | 268 | `compile_filter_globs` |
| `crates/diffguard-domain/src/rules.rs` | 200 | `compile_globs` |
| `crates/diffguard-domain/src/overrides.rs` | 197 | `compile_exclude_globs` |

`GlobSetBuilder::build()` returns `Result<GlobSet, globset::Error>` and **can fail** due to:
- Combined regex pattern overflow (NFA size limits when too many patterns are joined)
- Regex compilation failures

The codebase has a stated invariant: *"Diff parsing never panics — malformed input returns errors, never crashes"*. The `.expect()` calls violate this invariant.

## Decision

We will replace `.expect("globset build should succeed")` with proper error handling by adding new typed error variants:

### New Variants

1. **`PathFilterError::GlobSetBuild { source: globset::Error }`** in `check.rs`
2. **`RuleCompileError::GlobSetBuild { rule_id: String, source: globset::Error }`** in `rules.rs`
3. **`OverrideCompileError::GlobSetBuild { rule_id: String, directory: String, source: globset::Error }`** in `overrides.rs`

### Error Handling Pattern

Replace:
```rust
b.build().expect("globset build should succeed")
```

With:
```rust
b.build().map_err(|source| PathFilterError::GlobSetBuild { source })?
```

### Variant Naming: `GlobSetBuild` vs `PatternOverflow`

The initial plan used the name `PatternOverflow`. We choose `GlobSetBuild` instead because `build()` can fail for reasons beyond just overflow (e.g., regex compilation errors). The underlying `globset::Error` is preserved as `source`, providing the specific cause to callers.

### Source Error Preservation (Critical Fix)

**The initial plan's `map_err(|_| PatternOverflow { ... })` was incorrect.** It discarded the `globset::Error` source, breaking the error chain.

All existing `InvalidGlob` variants preserve `source: globset::Error`. The new variants follow the same pattern:
```rust
#[error("path filter glob set build failed: {source}")]
GlobSetBuild { source: globset::Error },
```

This ensures:
- Debugging: users can see the specific regex compilation error
- Future-proofing: if globset adds new error kinds, they're preserved
- Consistency: all glob-related error variants chain `source`

## Consequences

### Benefits
- Eliminates unreachable panics that can actually occur in production
- Error messages are actionable instead of "globset build should succeed"
- Follows existing `thiserror::Error` chain pattern consistently
- Preserves the "never panics on bad input" invariant

### Tradeoffs
- **Breaking API change**: Adding variants to `RuleCompileError`, `OverrideCompileError`, and `PathFilterError` is technically breaking for users who match exhaustively. However:
  - These error types are internal to their crates (not exposed in stable public API)
  - Domain crates use `anyhow::Error` at API boundaries
  - New variants are additive (appended at enum end)
- **Untested code path**: The new error variants cannot be easily tested without constructing a glob set known to overflow. Acceptable risk — the path is now handled vs. previously being a hidden panic.

### Non-Goals
- We are NOT adding `#[non_exhaustive]` to error enums (separate discussion)
- We are NOT testing the overflow path (difficult to construct reliably)

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| `PatternOverflow` name without `source` | Discards diagnostic information; initial plan was wrong |
| `#[allow(clippy::unnecessary_expect)]` | Masks a real problem; `build()` CAN fail |
| `map_err(\|_\| ...)` discarding source | Loses error chain; breaks consistency with `InvalidGlob` |
| `Option<GlobSet>` return type | Loses error information entirely |
| `anyhow::Result` at internal functions | Too broad; defeats typed error purpose |

## References

- GitHub Issue: #388
- Work Item: work-dcc10c76
- globset version: 0.4.18
- Related: `InvalidGlob` variants at check.rs:78, rules.rs:22, overrides.rs:26
