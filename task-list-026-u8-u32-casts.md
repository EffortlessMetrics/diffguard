# Task List — work-8a529be1

## Implementation Tasks

- [ ] Replace `(next - b'0') as u32` with `u32::from(next - b'0')` at line 546 in unified.rs
- [ ] Replace `(d - b'0') as u32` with `u32::from(d - b'0')` at line 550 in unified.rs
- [ ] Verify no `as u32` casts remain: `grep -n "as u32" unified.rs`
- [ ] Run tests: `cargo test -p diffguard-diff`
- [ ] Run clippy: `cargo clippy -p diffguard-diff -- -D warnings`
- [ ] Run fuzz tests: `cargo +nightly fuzz run unified_diff_parser` (30+ seconds)
- [ ] Commit the implementation changes
- [ ] Push the branch

## Closure Tasks

- [ ] Close GitHub issue #449
- [ ] Verify all checks pass on CI
