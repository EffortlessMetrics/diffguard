# ADR-0073: Add #[must_use] to Three Public Functions

## Status
Proposed

## Context
GitHub issue #398 reports that three public functions in diffguard lack `#[must_use]` attributes, triggering `clippy::must_use_candidate` warnings. Discarding return values from these functions is problematic:

1. **`render_sensor_report`** (`diffguard-core/src/sensor.rs:44`): Returns a `SensorReport` — the issue describes silently losing the sensor report as "a serious data loss bug in production."
2. **`split_lines`** (`diffguard-lsp/src/text.rs:6`): Returns a newly constructed `Vec<&str>` — ignoring it is almost certainly a bug.
3. **`changed_lines_between`** (`diffguard-lsp/src/text.rs:14`): Returns a newly constructed `BTreeSet<u32>` — ignoring it is almost certainly a bug.

The `clippy::must_use_candidate` lint flags these as functions whose return values should not be silently discarded. The `#[must_use]` attribute produces a compile-time warning if the return value is ignored.

## Decision
Add `#[must_use]` attributes to all three functions:
- `render_sensor_report` in `crates/diffguard-core/src/sensor.rs`
- `split_lines` in `crates/diffguard-lsp/src/text.rs`
- `changed_lines_between` in `crates/diffguard-lsp/src/text.rs`

This approach is consistent with existing patterns in the codebase:
- `build_synthetic_diff` (text.rs:32) already has `#[must_use]`
- `utf16_length` (text.rs:163) already has `#[must_use]`
- Many other functions across the diffguard workspace use `#[must_use]`

The fix is purely additive — no runtime behavior change, no API change, no new tests required.

## Consequences

### Benefits
- Compile-time enforcement that callers handle return values
- Prevents silent data loss (especially for `render_sensor_report`)
- Consistent with established Rust idioms and existing codebase patterns
- Zero runtime overhead (compile-time only)

### Tradeoffs / Risks
- If any existing caller deliberately ignores the return value (e.g., fire-and-forget telemetry), adding `#[must_use]` will produce a warning. This would actually be a bug catch, not a problem.
- The attribute only warns — it does not break compilation.
- There are 32 other `must_use_candidate` warnings in the codebase; this fix scope is limited to the 3 functions named in issue #398.

## Alternatives Considered

### Alternative 1: Do Nothing
Do not add `#[must_use]` attributes. Accept that callers may silently ignore return values.
- **Rejected because**: The issue explicitly identifies discarding `render_sensor_report` as a "serious data loss bug in production." The other two functions (`split_lines`, `changed_lines_between`) returning newly constructed collections where ignoring the result is almost certainly a bug.

### Alternative 2: Suppress the Clippy Warning
Add `#[allow(clippy::must_use_candidate)]` to silence the warnings without adding `#[must_use]`.
- **Rejected because**: Suppressing the warning does not solve the underlying problem — callers who ignore the return value are still buggy. `#[must_use]` provides compile-time enforcement; suppressing the lint only hides the diagnostic.

### Alternative 3: Add #[must_use] Only to render_sensor_report
Fix only the `render_sensor_report` function, citing the production data-loss risk as the primary motivation, and treat the other two as lower priority.
- **Rejected because**: All three functions are flagged by the same lint for the same reason. The issue explicitly names all three. Consistency across the codebase is valuable.
