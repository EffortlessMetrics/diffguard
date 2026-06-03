# ADR-0428: Explicit Duration Overflow Handling in main.rs

**Status:** Proposed

**Created:** 2026-04-19

---

## Context

GitHub Issue #428 reports that `main.rs` contains silent u128→u64 truncation that can overflow for long-running diffguard processes. Two locations in `crates/diffguard/src/main.rs` use `as u64` to narrow larger integer types:

1. **Line 1923** (in `cmd_check`): `start_time.elapsed().as_millis()` returns `u128`, cast to `u64`
2. **Line 2607** (in `cmd_check_inner`): `num_milliseconds()` returns `i64`, cast to `u64`

The `duration_ms` value flows into:
- `SensorReportContext { duration_ms: u64 }` — cockpit/sensor reporting
- `trend_run_from_receipt(receipt, started_at, ended_at, duration_ms)` — analytics

The codebase already uses saturating arithmetic (`saturating_add`, `saturating_sub`) and documented sentinel patterns (`try_into().unwrap_or(u32::MAX)`). The issue is that these two duration calculations use silent truncation instead.

---

## Decision

Replace `as u64` with explicit saturating `.min()` clamping before casting:

**Line 1923** (u128→u64 via `std::time::Instant`):
```rust
let duration_ms = start_time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
```

**Line 2607** (i64→u64 via `chrono::DateTime`):
```rust
let duration_ms = (ended_at - *started_at).num_milliseconds().max(0).min(i64::MAX) as u64;
```

Both conversions use saturation because:
- **Saturation over errors**: A capped duration ("≥584M years") is meaningful in dashboards; errors would be disruptive in CLI context
- **Consistent with codebase**: The codebase uses `saturating_add` for similar scenarios, never `checked_add`
- **Schema compatible**: Both produce valid `uint64` values within the sensor report schema

**Saturation point note**: Line 1923 saturates at `u64::MAX` (~584M years), while line 2607 saturates at `i64::MAX` (~292M years). This minor inconsistency exists because `num_milliseconds()` returns `i64`. In practice, both represent durations so large they are effectively unreachable for any realistic process lifetime.

---

## Alternatives Considered

### 1. Checked conversion (`try_into()`)
```rust
let duration_ms = u64::try_from(start_time.elapsed().as_millis())
    .unwrap_or(u64::MAX);
```

**Rejected because:**
- Error propagation changes control flow in ways unsuitable for I/O-bound CLI context
- Saturation produces actionable values; errors do not
- Inconsistent with codebase patterns (uses saturating arithmetic, not checked)

### 2. Comment-only documentation
```rust
// Note: truncates if duration exceeds u64::MAX (~584M years)
let duration_ms = start_time.elapsed().as_millis() as u64;
```

**Rejected because:**
- Does not actually fix the code quality issue
- Silent truncation would still occur, bypassing type system safety

### 3. No action
**Rejected because:**
- Silent truncation is poor Rust practice
- Code hygiene issue, even if overflow is practically unreachable

---

## Consequences

### Benefits
- **Explicit overflow handling**: Developers can reason about behavior under overflow conditions
- **Meaningful capped values**: Dashboard displays "very long duration" rather than garbage truncated values
- **Codebase consistency**: Aligns with existing patterns (`saturating_add`, `.unwrap_or(MAX)`)
- **Schema compatibility**: Both produce valid `u64` values matching `sensor.report.v1.schema.json`

### Tradeoffs
- **Minor inconsistency**: Line 1923 saturates at `u64::MAX`, line 2607 at `i64::MAX`. Both are astronomically large; practical impact is zero.
- **Cognitive overhead**: Reviewers unfamiliar with the pattern may have questions

### Risks
- **Downstream expectations**: If downstream systems compare exact durations, capped values could produce false non-equalities. However, durations are inherently variable and exact comparison is unreliable.
- **Masking timing bugs**: If a bug causes `ended_at < started_at` AND duration > `i64::MAX`, saturation would hide it. This is an existing risk orthogonal to this fix.

---

## Verification

1. `cargo check` passes without errors
2. `cargo test -p diffguard` passes without regressions
3. Both lines use explicit saturation with clarifying comments
