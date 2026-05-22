# Task List — work-73d0ff4b

## Implementation Tasks

- [ ] 1. Add `#[must_use]` to `split_lines` in `crates/diffguard-lsp/src/text.rs:6`
- [ ] 2. Add `#[must_use]` to `changed_lines_between` in `crates/diffguard-lsp/src/text.rs:14`
- [ ] 3. Add `#[must_use]` to `render_sensor_report` in `crates/diffguard-core/src/sensor.rs:44`
- [ ] 4. Run `cargo clippy --all-features -- -W clippy::must_use_candidate` to verify warnings resolved
- [ ] 5. Run `cargo build --all-features` to verify build passes
- [ ] 6. Run `cargo test --all-features` to verify tests pass
- [ ] 7. Commit changes to branch `feat/work-73d0ff4b/3-public-functions-lack-must-use-attribute`
- [ ] 8. Push changes to origin

## Verification Criteria
1. Clippy `must_use_candidate` warnings for `split_lines`, `changed_lines_between`, `render_sensor_report` are resolved
2. Build completes successfully with no errors
3. All tests pass
4. Attribute placement matches existing pattern (directly above function signature)
