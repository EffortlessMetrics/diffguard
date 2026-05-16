# Spec — work-1309c426: Fix `rust.no_unwrap` Rule Self-Defeat

## Feature/Behavior Description

Replace 4 `unwrap()` calls with `expect()` calls in the inline test module of `crates/diffguard/src/presets.rs`. This closes the credibility gap where the `rust.no_unwrap` rule prohibits `unwrap()` but the same file that defines the rule uses it 4 times.

## Acceptance Criteria

1. **File Change**: `crates/diffguard/src/presets.rs` is modified such that:
   - Line 478: `result.unwrap()` → `result.expect("rust-quality preset should parse as valid TOML")`
   - Line 494: `result.unwrap()` → `result.expect("secrets preset should parse as valid TOML")`
   - Line 510: `result.unwrap()` → `result.expect("js-console preset should parse as valid TOML")`
   - Line 530: `result.unwrap()` → `result.expect("python-debug preset should parse as valid TOML")`

2. **No Other Changes**: No other files are modified. The `generate()` methods (which use `.to_string()` on string literals) are not changed. The existing `.expect()` at line 550 is not modified.

3. **Code Quality**: The changes pass `cargo clippy -p diffguard -- -D warnings` with no new warnings.

4. **Consistency**: All new `expect()` calls follow the pattern established at line 550: `expect("descriptive message")`.

## Non-Goals

- This fix does NOT address the `rust.no_expect` rule, which is noted as similarly self-referential but is outside scope for this issue.
- This fix does NOT address any other `unwrap()` calls in other files.
- This fix does NOT modify the `rust.no_unwrap` rule definition itself.

## Dependencies

- **Pre-existing blocker**: The file `crates/diffguard/tests/green_tests_work_d4a75f70.rs` has format string compilation errors that block ALL tests on this branch. This is unrelated to work-1309c426 and should be fixed separately.
- **No new dependencies**: This change uses only existing stdlib functionality.
