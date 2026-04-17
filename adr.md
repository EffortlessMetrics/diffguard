# ADR-0534: Add #[must_use] to render_sensor_report()

## Status
Proposed

## Context

The `render_sensor_report()` function in `crates/diffguard-core/src/sensor.rs` returns a `SensorReport` containing critical sensor data (findings, verdict, run metadata, and artifacts). This function is part of the R2 Library Contract for Cockpit ecosystem integration — it is exported publicly from `diffguard-core` and used as the primary data contract for the sensor system.

Unlike other render functions that return `String` (where discarding the result produces visible empty output), `render_sensor_report()` returns a structured `SensorReport`. If a caller discards this value, the entire sensor report is silently lost with no compiler warning. In a governance/sensor system where findings, verdict status, and run metadata are critical, silent data loss is a serious failure mode.

The codebase already uses `#[must_use]` extensively on similar functions:
- `diffguard-diff/src/unified.rs` — `is_submodule()`, `is_added()`, etc.
- `diffguard-domain/src/suppression.rs` — `suppress()` variants
- `diffguard-domain/src/overrides.rs` — `override_finding()`
- `diffguard-types/src/lib.rs` — various type methods
- `diffguard-analytics/src/lib.rs` — multiple functions

## Decision

Add `#[must_use]` attribute to the `render_sensor_report()` function in `crates/diffguard-core/src/sensor.rs` at line 44.

```rust
/// Renders a CheckReceipt as a SensorReport.
#[must_use]
pub fn render_sensor_report(receipt: &CheckReceipt, ctx: &SensorReportContext) -> SensorReport {
```

## Consequences

### Benefits
- **Compile-time enforcement against silent data loss**: Any caller that discards the `SensorReport` will now receive a compiler warning, making the bug immediately visible rather than silently failing.
- **Consistency with codebase conventions**: The attribute aligns with the established pattern of `#[must_use]` usage across the monorepo.
- **Strengthens the R2 Library Contract**: The `SensorReport` is explicitly the stable integration surface for Cockpit/BusyBox consumers. Making it a compile-time error to discard the result reinforces this contract.
- **Purely additive change**: No runtime behavior change. No existing correct code is affected.

### Tradeoffs/Risks
- **Potential warnings in existing code**: If any existing code (inside or outside `diffguard-core`) calls `render_sensor_report()` and discards the result, it will now produce a compiler warning. However, this only exposes pre-existing bugs — such code was already silently losing sensor data.
- **CI lint gates**: If other work items or CI pipelines have `#[deny(warnings)]`, newly warned code could cause failures. However, this is the intended behavior — those callers need to be fixed.

### No impact on:
- `render_sensor_json()` — returns `Result<String, serde_json::Error>`, which has implicit `#[must_use]` on `Result` in Rust 2018+.
- Runtime behavior — `#[must_use]` is purely compile-time.
- Backward compatibility — only affects code that was already incorrect.

## Alternatives Considered

### 1. Do nothing (leave without #[must_use])
- **Rejected because**: Silent data loss remains a latent defect. As Cockpit ecosystem integration grows, more callers might emerge that accidentally discard the result, and the bug would only be discovered when sensor dashboards go blank or integration tests silently pass with no findings.

### 2. Add #[must_use] to multiple render_* functions
- **Rejected because**: The issue specifically calls out `render_sensor_report()`. Other render functions (`render_csv_for_receipt()`, `render_junit_for_receipt()`) return `String`, which produces visible empty output if discarded. `render_sensor_report()` returns a structured `SensorReport` with no visible indication when discarded — a qualitatively different failure mode.

### 3. Document the requirement in code comments only
- **Rejected because**: Documentation can be ignored. The `#[must_use]` attribute provides compile-time enforcement that comments cannot.

## Dependencies
- None. The change is self-contained and does not require any other work items or external dependencies.
