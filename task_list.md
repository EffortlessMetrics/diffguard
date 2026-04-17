# Task List — work-f093d3fc

## Implementation Tasks

- [ ] 1. Edit `diff_builder.rs`: Add `#[must_use]` to `DiffBuilder::add_file()` (line 64)
- [ ] 2. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::binary()` (line 215)
- [ ] 3. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::deleted()` (line 221)
- [ ] 4. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::new_file()` (line 227)
- [ ] 5. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::mode_change()` (line 233)
- [ ] 6. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::rename_from()` (line 240)
- [ ] 7. Edit `diff_builder.rs`: Add `#[must_use]` to `FileBuilder::add_hunk()` (line 250)
- [ ] 8. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::context()` (line 364)
- [ ] 9. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::add_line()` (line 375)
- [ ] 10. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::remove()` (line 386)
- [ ] 11. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::add_lines()` (line 393)
- [ ] 12. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::remove_lines()` (line 401)
- [ ] 13. Edit `diff_builder.rs`: Add `#[must_use]` to `HunkBuilder::add_lines_from_slice()` (line 570)
- [ ] 14. Run `cargo check -p diffguard-testkit` to verify compilation
- [ ] 15. Run `cargo test -p diffguard-testkit` to verify tests pass
- [ ] 16. Commit changes with message: "feat(diffguard-testkit): add #[must_use] to builder methods"
- [ ] 17. Push branch to origin