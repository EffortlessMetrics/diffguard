# Spec: Explicit Duration Overflow Handling — work-3010cb68

## Feature Description

Replace silent u128→u64 and i64→u64 truncation in `crates/diffguard/src/main.rs` with explicit saturating conversions to prevent silent overflow for long-running diffguard processes.

### Issue Background

GitHub Issue #428 reports that `main.rs` contains u128→u64 truncation that silently overflows. Two locations in `main.rs` use `as u64` to narrow larger integer types:

| Line | Code Path | Source Type | Issue |
|------|-----------|-------------|-------|
| 1923 | `start_time.elapsed().as_millis()` | `u128` | Silent truncation |
| 2607 | `num_milliseconds().max(0)` | `i64` | Silent truncation |

The `duration_ms` value flows into `SensorReportContext` and `trend_run_from_receipt()`, both of which expect `u64`.

---

## Behavior Change

### Before (silent truncation)
```rust
let duration_ms = start_time.elapsed().as_millis() as u64;  // Line 1923
let duration_ms = (ended_at - *started_at).num_milliseconds().max(0) as u64;  // Line 2607
```

### After (explicit saturation)
```rust
// Line 1923 — u128→u64 via Instant
let duration_ms = start_time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

// Line 2607 — i64→u64 via chrono DateTime
let duration_ms = (ended_at - *started_at).num_milliseconds().max(0).min(i64::MAX) as u64;
```

---

## Acceptance Criteria

### Must Pass
1. **Line 1923 fix**: `start_time.elapsed().as_millis()` uses `.min(u128::from(u64::MAX))` before `as u64`
2. **Line 2607 fix**: `num_milliseconds().max(0)` uses `.min(i64::MAX)` before `as u64`
3. **`cargo check` passes**: No compilation errors from the changes
4. **`cargo test -p diffguard` passes**: No test regressions introduced

### Should Pass
5. **Comments added**: Each fix includes a comment explaining saturation rationale:
   - Practical overflow is impossible (~584M years for line 1923, ~292M years for line 2607)
   - Explicit handling is preferred over silent truncation for code hygiene
6. **No other narrowing casts introduced**: The changes don't create new `as u64` truncations elsewhere

---

## Non-Goals

- **Not a performance fix**: The change has negligible performance impact
- **Not schema change**: The `duration_ms` field remains `u64`; schema compatibility is preserved
- **Not error handling change**: No errors are introduced; saturation is used instead
- **Not a fix for other crates**: Only `crates/diffguard/src/main.rs` is in scope

---

## Dependencies

- Rust std library (`Duration::as_millis()` returns `u128`)
- chrono crate (`DateTime::signed_duration_since().num_milliseconds()` returns `i64`)
- `SensorReportContext` and `trend_run_from_receipt()` accept `u64` (no type changes needed)

---

## Edge Cases

| Edge Case | Behavior |
|-----------|----------|
| Duration < `u64::MAX` | Exact value computed and cast |
| Duration ≥ `u64::MAX` (line 1923) | Capped at `u64::MAX` |
| Duration ≥ `i64::MAX` (line 2607) | Capped at `i64::MAX` (~292M years) |
| `ended_at < started_at` | `.max(0)` handles negative durations (existing behavior) |

---

## Verification Commands

```bash
# Check compilation
cargo check -p diffguard

# Run tests
cargo test -p diffguard

# Verify only these two lines changed
grep -n "as u64" crates/diffguard/src/main.rs
# Expected output: lines 1923 and 2607 only
```
