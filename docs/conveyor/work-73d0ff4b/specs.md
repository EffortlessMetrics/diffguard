# Spec: Add #[must_use] to Three Public Functions

## Feature Description
Add `#[must_use]` Rust attributes to three public functions that currently trigger `clippy::must_use_candidate` warnings. The fix is purely mechanical — adding the attribute produces a compile-time warning if any caller ignores the return value. No runtime behavior changes.

## Functions to Modify

| Function | File | Line |
|----------|------|------|
| `render_sensor_report` | `crates/diffguard-core/src/sensor.rs` | 44 |
| `split_lines` | `crates/diffguard-lsp/src/text.rs` | 6 |
| `changed_lines_between` | `crates/diffguard-lsp/src/text.rs` | 14 |

## Acceptance Criteria

### AC1: Clippy Warning Resolved
Running `cargo clippy --all-features -- -W clippy::must_use_candidate` produces no warnings for `split_lines`, `changed_lines_between`, or `render_sensor_report`.

### AC2: Build Passes
`cargo build --all-features` completes successfully with no errors or warnings.

### AC3: Tests Pass
`cargo test --all-features` completes successfully — no test regressions introduced by the attribute additions.

### AC4: Attribute Placement
The `#[must_use]` attribute is placed directly above the function signature, matching the existing pattern used by `build_synthetic_diff` and `utf16_length` in the same file.

## Non-Goals
- This spec does NOT fix other `must_use_candidate` warnings beyond the 3 functions named in issue #398.
- This spec does NOT add `#[must_use]` to any types (the `SensorReport` type already has `#[must_use]`).
- This spec does NOT change any function signatures, return types, or behavior.
- This spec does NOT add new tests — the existing test coverage is sufficient for a purely additive attribute.

## Dependencies
- No external dependencies required.
- No changes to Cargo.toml or workspace configuration.
- No changes to any other files beyond the 3 functions listed above.

## Verification Steps
1. Apply the patch adding `#[must_use]` to the 3 functions
2. Run `cargo clippy --all-features -- -W clippy::must_use_candidate 2>&1 | grep -E "(split_lines|changed_lines_between|render_sensor_report)"` — should return empty
3. Run `cargo build --all-features` — should succeed with no warnings for these functions
4. Run `cargo test --all-features` — should pass
