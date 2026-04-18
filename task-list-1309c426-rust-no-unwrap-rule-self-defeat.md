# Task List — work-1309c426: Fix `rust.no_unwrap` Rule Self-Defeat

## Implementation Tasks

- [ ] Edit `crates/diffguard/src/presets.rs` line 478: Replace `result.unwrap()` with `result.expect("rust-quality preset should parse as valid TOML")`
- [ ] Edit `crates/diffguard/src/presets.rs` line 494: Replace `result.unwrap()` with `result.expect("secrets preset should parse as valid TOML")`
- [ ] Edit `crates/diffguard/src/presets.rs` line 510: Replace `result.unwrap()` with `result.expect("js-console preset should parse as valid TOML")`
- [ ] Edit `crates/diffguard/src/presets.rs` line 530: Replace `result.unwrap()` with `result.expect("python-debug preset should parse as valid TOML")`

## Verification Tasks

- [ ] Run `cargo clippy -p diffguard -- -D warnings` to verify no new warnings
- [ ] Verify tests pass (note: pre-existing compilation error in `green_tests_work_d4a75f70.rs` may block test verification)

## Notes

- Do NOT modify line 550 (already uses `.expect()`)
- Do NOT modify the `generate()` methods (they use `.to_string()` which is infallible)
- Do NOT modify the `rust.no_unwrap` rule definition itself
