# ADR-0453: Document Error Return for `render_gitlab_quality_json`

## Status
Proposed

## Context

The function `render_gitlab_quality_json` in `crates/diffguard-core/src/gitlab_quality.rs:86` returns `Result<String, serde_json::Error>` but its doc comment lacks an `# Errors` section, triggering the `clippy::missing_errors_doc` lint when enabled.

This is a pure documentation fix with no code logic changes. The lint enforces that functions returning `Result` should document what error variants can be returned and under what circumstances.

## Decision

Add an `# Errors` section to the doc comment of `render_gitlab_quality_json` that documents `serde_json::Error` as the sole error type, returned when JSON serialization fails.

**Change:**
```rust
// BEFORE:
/// Renders a GitLab Code Quality report as a JSON string.
pub fn render_gitlab_quality_json(receipt: &CheckReceipt) -> Result<String, serde_json::Error> {

// AFTER:
/// Renders a GitLab Code Quality report as a JSON string.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if serialization fails.
pub fn render_gitlab_quality_json(receipt: &CheckReceipt) -> Result<String, serde_json::Error> {
```

This follows the established pattern used in `check.rs:84-92` for the `run_check` function.

## Consequences

**Benefits:**
- Eliminates the `clippy::missing_errors_doc` warning for this function
- Improves API documentation for consumers of this public function
- Follows Rust doc conventions consistent with the rest of the crate

**Tradeoffs:**
- None — this is a pure documentation change with no behavior impact

## Alternatives Considered

1. **Leave undocumented** — Reject the lint fix as "not worth the churn." Rejected because the warning appears when the lint is enabled, and the fix is trivial.

2. **Document with more detail** — Explain that serialization can fail if the data contains unsupported types. Rejected because `serde_json::Error` is straightforward (std type with no variants to enumerate), and the minimal one-liner is sufficient and consistent with the crate's style.

3. **Fix all functions with this warning** — Include `render_sarif_json` (sarif.rs:230), `render_sensor_json` (sensor.rs:134), and `run_sensor` (sensor_api.rs:50). Rejected as out of scope for this issue; those functions belong to separate work items.

## Dependencies

- `serde_json::Error` — standard library error type from the `serde_json` crate
- `clippy::missing_errors_doc` lint — must be enabled with `-W clippy::missing_errors_doc` to surface the warning
