# Specification — work-ce74b044

## Feature / Behavior Description

Remove the duplicate `diffguard-core` entry from the `[dependencies]` section of `bench/Cargo.toml`. The entry in `[dev-dependencies]` remains unchanged.

This is a dependency hygiene fix that eliminates redundant compilation of `diffguard-core` without changing any functional behavior.

## Acceptance Criteria

1. **`bench/Cargo.toml` has exactly one `diffguard-core` entry**  
   After the fix, `diffguard-core` appears only in the `[dev-dependencies]` section, not in `[dependencies]`. This can be verified with:  
   ```bash
   grep -c 'diffguard-core' bench/Cargo.toml
   # Expected: 1
   ```

2. **Library compiles successfully**  
   `cargo check -p diffguard-bench --lib` passes without errors. The library target does not depend on `diffguard-core`, so removal from `[dependencies]` has no impact.

3. **Benchmarks compile successfully**  
   `cargo bench -p diffguard-bench --no-run` compiles all 5 benchmarks without errors. The benchmark code in `bench/benches/rendering.rs` still has access to `diffguard-core` via `[dev-dependencies]`.

4. **Tests compile successfully**  
   `cargo test -p diffguard-bench --no-run` compiles all tests without errors. The test code in `bench/tests/snapshot_tests.rs` still has access to `diffguard-core` via `[dev-dependencies]`.

## Non-Goals

- This fix does not modify any source code files (`.rs`)
- This fix does not add comments or documentation to `Cargo.toml`
- This fix does not address any other dependency issues in the workspace
- This fix does not change the version or path of any dependency

## Dependencies

- No new dependencies are introduced
- All existing dependency paths/versions remain unchanged
- The only change is removal of one line from `[dependencies]`
