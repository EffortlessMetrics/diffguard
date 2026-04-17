# Specification: Add #[must_use] to render_sensor_report()

## Feature/Behavior Description

Add the `#[must_use]` attribute to the `render_sensor_report()` function in `crates/diffguard-core/src/sensor.rs`. This attribute ensures that callers who discard the returned `SensorReport` receive a compiler warning, preventing silent sensor data loss.

## Acceptance Criteria

1. **Compilation**: The `diffguard-core` crate compiles without errors after the change.
   - Verified by: `cargo build -p diffguard-core`

2. **Existing tests pass**: All existing tests in `diffguard-core` continue to pass (they already use the return value properly).
   - Verified by: `cargo test -p diffguard-core`

3. **Clippy passes**: `cargo clippy -p diffguard-core` produces no new warnings related to this change.

4. **Source code verification**: The `render_sensor_report()` function declaration at line 44 of `sensor.rs` includes `#[must_use]`:
   ```rust
   #[must_use]
   pub fn render_sensor_report(receipt: &CheckReceipt, ctx: &SensorReportContext) -> SensorReport {
   ```

## Non-Goals

- This change does NOT add `#[must_use]` to `render_sensor_json()` (already covered by `Result`'s implicit `#[must_use]`)
- This change does NOT modify any other `render_*` functions
- This change does NOT alter runtime behavior — purely a compile-time annotation
- This change does NOT require updating tests (existing tests already use the return value)

## Dependencies

- None. This is a self-contained one-line attribute addition with no external dependencies.
