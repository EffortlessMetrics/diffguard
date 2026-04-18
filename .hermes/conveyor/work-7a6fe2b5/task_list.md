# Task List — work-7a6fe2b5: Decompose sanitize_line()

## Implementation Tasks

- [ ] **1. Verify baseline**: Run `cargo clippy -p diffguard-domain` to confirm the `too_many_lines` lint fires on `sanitize_line()`
- [ ] **2. Produce Normal-mode sketch**: Draw up annotated "after" sketch of `handle_mode_normal` showing the `Option<usize>` contract for `try_string_start`/`try_comment_start` — get sign-off before coding
- [ ] **3. Extract Mode handler methods**: Replace each `Mode::X => { ... }` arm in `sanitize_line` with a call to `self.handle_mode_x(...)`, keeping the dispatch loop compact
- [ ] **4. Extract Normal-mode helpers**: Create `try_string_start()` and `try_comment_start()` private methods on `Preprocessor` with `Option<usize>` return type
- [ ] **5. Run tests**: `cargo test -p diffguard-domain` — all 375+ tests must pass
- [ ] **6. Run clippy**: `cargo clippy -p diffguard-domain` — `too_many_lines` should be gone
- [ ] **7. Run fuzz**: `cargo +nightly fuzz run preprocess` — validate no regressions under fuzzing
- [ ] **8. Code review**: Verify refactored code is readable and consistent with crate conventions
