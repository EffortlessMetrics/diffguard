# Task List — work-69571989

## Implementation Tasks

- [ ] Add `# Panics` section to `ConfigFile::built_in()` doc comment in `crates/diffguard-types/src/lib.rs`
- [ ] Verify `cargo build -p diffguard-types --lib` succeeds
- [ ] Verify `cargo doc -p diffguard-types --no-deps` renders correctly without warnings
- [ ] Verify `cargo test -p diffguard-types` passes all tests including `must_use_attribute_consistency`

## Verification Tasks

- [ ] Confirm the `# Panics` section is present in the rendered rustdoc
- [ ] Confirm no regressions in downstream crates that use `ConfigFile::built_in()`
