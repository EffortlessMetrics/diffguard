# ADR-0013: Replace `unwrap()` with `expect()` in presets.rs Test Functions

## Status
Proposed

## Context
GitHub issue #564 reports that the `rust.no_unwrap` rule is self-defeating — the `presets.rs` file that defines and ships this rule uses `unwrap()` directly in its own inline test functions (4 occurrences at lines 478, 494, 510, 530).

The `rust.no_unwrap` rule prohibits `unwrap()` calls in production code with `exclude_paths = ["**/tests/**", "**/benches/**", "**/examples/**"]`. However, the inline `#[cfg(test)]` module in `presets.rs` is not excluded by this pattern, creating a credibility gap: the rule warns against `unwrap()` but its own implementation violates the rule.

The codebase already uses `.expect()` at line 550 in `test_all_presets_have_defaults`, establishing a precedent for the preferred pattern.

## Decision
Replace the 4 `unwrap()` calls in `presets.rs` test functions with `expect()` calls that provide descriptive error messages:

| Line | Function | Change |
|------|----------|--------|
| 478 | `test_rust_quality_preset_generates_valid_toml` | `result.unwrap()` → `result.expect("rust-quality preset should parse as valid TOML")` |
| 494 | `test_secrets_preset_generates_valid_toml` | `result.unwrap()` → `result.expect("secrets preset should parse as valid TOML")` |
| 510 | `test_js_console_preset_generates_valid_toml` | `result.unwrap()` → `result.expect("js-console preset should parse as valid TOML")` |
| 530 | `test_python_debug_preset_generates_valid_toml` | `result.unwrap()` → `result.expect("python-debug preset should parse as valid TOML")` |

## Consequences

### Benefits
- **Closes the credibility gap**: The `rust.no_unwrap` rule is no longer self-defeating
- **Improved error messages**: `expect()` provides context when failures occur, aiding debugging
- **Consistency**: Aligns with the existing pattern at line 550
- **Future-proofing**: Enables potential crate-wide `#[deny(unwrap)]` enforcement once the codebase is clean

### Tradeoffs
- **Risk of scope creep**: The issue mentions only 4 `unwrap()` calls; a 5th already uses `.expect()` at line 550 and should not be modified
- **Pre-existing test blocker**: A separate compilation error in `green_tests_work_d4a75f70.rs` (unrelated to this work item) prevents test verification on the current branch

## Alternatives Considered

1. **Remove the inline tests entirely** — Rejected because the tests provide valuable validation that preset TOML is parseable and contains expected rules.

2. **Use `?` operator with `anyhow`** — Rejected because it would change function signatures and add a dependency, disproportionate to the trivial nature of the fix.

3. **Add `presets.rs` to `exclude_paths`** — Rejected because it would paper over the problem rather than fix the underlying self-defeating rule behavior.

## References
- GitHub Issue: #564
- Work Item: work-1309c426
