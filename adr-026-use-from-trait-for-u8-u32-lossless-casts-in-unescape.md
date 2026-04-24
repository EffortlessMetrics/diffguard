# ADR 026: Use From trait for u8→u32 lossless casts in unescape_git_path

## Status
Accepted

## Context
Issue #449 reports clippy `cast_lossless` warnings in `unescape_git_path()` at lines 546 and 550 (originally 535 and 539 before refactoring). Two `as u32` casts on `u8` values are used for octal escape sequence parsing:

```rust
let mut val = (next - b'0') as u32;           // line 546
val = val * 8 + (d - b'0') as u32;            // line 550
```

Clippy warns these are "lossy semantics" that could become silently lossy if types change in the future.

ADR-017 (`afebf70`) previously established the pattern of using `From::from` instead of `as` for lossless casts in similar contexts.

## Decision
Replace `as u32` with `u32::from()` for the u8→u32 conversions in octal digit parsing:

```rust
let mut val = u32::from(next - b'0');         // line 546
val = val * 8 + u32::from(d - b'0');          // line 550
```

## Consequences

### Benefits
- Eliminates clippy `cast_lossless` warnings
- Makes conversion intent explicit and self-documenting
- Prevents future silent lossy conversions if types change
- Aligns with ADR-017 pattern already established in codebase

### Tradeoffs
- None — this is a purely mechanical refactor with no behavioral change

### Risks
- **Line number drift**: Issue referenced lines 535,539 but code is now at 546,550 after refactoring commit `d6a3b91`. The fix must be applied at the current line numbers.
- **Fix propagation**: Commit `a6b4283` applied this fix on branch `feat/work-095e24f2/refactor-parse-unified-diff` but was never merged to main or propagated to other branches.

## Alternatives Considered

### 1. Keep `as u32` casts
Rejected — Clippy's `cast_lossless` lint correctly identifies these as potentially lossy semantics.

### 2. Use `TryFrom::try_from()`
Overkill for an infallible conversion. The `From` trait is the idiomatic choice for lossless conversions.

## References
- Issue #449
- ADR-017 (`afebf70`) — prior decision establishing same pattern
- Fix commit `a6b4283` on branch `feat/work-095e24f2/refactor-parse-unified-diff`
