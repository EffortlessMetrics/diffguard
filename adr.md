# ADR-048: Make byte_to_column→u32 truncation explicit at call site

## Status
Proposed

## Context

At `crates/diffguard-domain/src/evaluate.rs:298`, the `byte_to_column` function returns `Option<usize>` (64-bit on 64-bit systems), which is converted to `Option<u32>` for `Finding.column`:

```rust
let column = event
    .match_start
    .and_then(|start| byte_to_column(&prepared.line.content, start))
    .and_then(|c| u32::try_from(c).ok());
```

The `.ok()` silently discards the column value if it exceeds `u32::MAX` (~4.29 billion characters). While this is practically impossible (a single line exceeding 4GB of text), the **principle** matters: silent data loss is bad practice.

The codebase already addressed this same issue for `files_scanned` (lines 24-28 in `evaluate.rs`) by migrating from `u32` to `u64`, with detailed documentation explaining why silent truncation was unacceptable.

## Decision

**Replace the silent truncation with explicit clamping at the call site:**

```rust
.and_then(|c| Some(c.min(u32::MAX as usize) as u32))
```

This makes the truncation **explicit** rather than silent, following the existing codebase pattern for handling unavoidable type constraints.

### Why NOT change `Finding.column` to `Option<u64>`

The initial plan proposed changing `Finding.column` from `Option<u32>` to `Option<u64>`. This approach is **not feasible** because:

1. **Downstream consumers explicitly type `column` as `Option<u32>`:**
   - `SarifRegion.start_column: Option<u32>` (sarif.rs:171)
   - `error_element(column: Option<u32>)` (checkstyle.rs:35)
   - `SensorLocation.column: Option<u32>` (lib.rs:550)

2. **External schemas constrain to u32:**
   - SARIF schema uses integer columns
   - Checkstyle XML uses integer columns
   - Sensor schema specifies `"format": "uint32"`

3. **Truncation is unavoidable anyway:**
   - Even with `u64` internally, the export boundary (SARIF/Checkstyle/Sensor) would still truncate to `u32`
   - The `files_scanned` precedent is inapplicable — it's internal-only, not serialized to external schemas

4. **Blast radius underestimated:**
   - The type change approach would require modifications in 5+ files and a schema version bump
   - Not a "minimal change" as originally described

## Consequences

### Positive
- **Single-line fix** — no downstream type changes required
- **Explicit truncation** — the code clearly shows what happens when column > u32::MAX
- **No API churn** — `Finding.column` stays `Option<u32>`, no schema version bump
- **Consistent with codebase** — the `.min(u32::MAX as usize) as u32` pattern is already used elsewhere in the codebase

### Negative
- **Behavioral change for pathological inputs:** Lines >4GB will now produce `Some(u32::MAX)` instead of `None`. This is actually preferable — the finding includes a column number rather than losing it entirely.
- **Comment required** — Without explanation, the explicit clamping looks like it could be accidental

### Neutral
- **Practical impact is zero** — Lines exceeding 4GB cannot exist in practical diff content

## Alternatives Considered

### 1. Change `Finding.column` to `Option<u64>`
**Rejected.** Would cause compilation errors in multiple downstream consumers (SARIF, Checkstyle, SensorLocation all explicitly use `Option<u32>`). Would still truncate at export boundaries.

### 2. Return `Err` instead of `ok()`, propagate error
**Rejected.** Would require changing `Evaluation` from struct to `Result`-type, a major breaking API change throughout the codebase.

### 3. Add `column_was_truncated: bool` flag
**Rejected.** Unnecessary complexity for an edge case that cannot occur in practice.

### 4. Keep current behavior
**Rejected.** Silent truncation via `.ok()` violates the codebase's explicit-over-implicit principle, as demonstrated by the `files_scanned` precedent.

## Implementation

Replace line 298 in `crates/diffguard-domain/src/evaluate.rs`:

**Before:**
```rust
.and_then(|c| u32::try_from(c).ok());
```

**After:**
```rust
// Explicit truncation: u32 cannot represent columns > ~4.3B chars.
// A single line this long is practically impossible in diff content.
// Using .min() instead of .ok() makes the truncation explicit rather than silent.
.and_then(|c| Some(c.min(u32::MAX as usize) as u32))
```

## References

- Original issue: https://github.com/EffortlessMetrics/diffguard/issues/481
- `files_scanned` precedent: `evaluate.rs:24-28`
- `byte_to_column` function: `evaluate.rs:599-604`
- `Finding.column` type: `diffguard-types/src/lib.rs:151`