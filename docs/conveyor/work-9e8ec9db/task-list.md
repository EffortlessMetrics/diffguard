# Task List — work-9e8ec9db

## Add #[must_use] to 8 builder methods in diff_builder.rs

### Implementation Tasks

- [ ] Add `#[must_use]` to `FileBuilderInProgress::binary()` — line ~113
- [ ] Add `#[must_use]` to `FileBuilderInProgress::deleted()` — line ~119
- [ ] Add `#[must_use]` to `FileBuilderInProgress::new_file()` — line ~125
- [ ] Add `#[must_use]` to `FileBuilderInProgress::mode_change()` — line ~131
- [ ] Add `#[must_use]` to `FileBuilderInProgress::rename_from()` — line ~137
- [ ] Add `#[must_use]` to `HunkBuilderInProgress::context()` — line ~159
- [ ] Add `#[must_use]` to `HunkBuilderInProgress::add_line()` — line ~165
- [ ] Add `#[must_use]` to `HunkBuilderInProgress::remove()` — line ~171

### Verification Tasks

- [ ] Run `cargo build -p diffguard-testkit` — must compile without errors
- [ ] Run `cargo test -p diffguard-testkit` — all existing tests must pass
- [ ] Run `cargo clippy -p diffguard-testkit -- -W clippy::return_self_not_must_use` — targeted methods should not warn (stretch goal)

### Out of Scope (do not modify)

- `FileBuilder` Self-returning methods (`binary`, `deleted`, `new_file`, `mode_change`, `rename_from`, `add_hunk`)
- `HunkBuilder` Self-returning methods (`context`, `add_line`, `remove`, `add_lines`, `remove_lines`, `add_lines_from_slice`)
- `FileBuilderInProgress::add_hunk_directly()` (extension trait)
- `HunkBuilderInProgress::add_lines_from_slice()` (extension trait)
