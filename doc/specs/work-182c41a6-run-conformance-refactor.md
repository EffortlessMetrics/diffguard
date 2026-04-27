# Specification: Refactor `run_conformance()` to Eliminate `clippy::too_many_lines`

## Feature / Behavior Description

Refactor the `run_conformance(quick: bool) -> Result<()>` function in `xtask/src/conform_real.rs` from a 207-line function with 15 repetitive match-arm blocks into a ~15-line loop over a static descriptor list.

The refactored code must:
- Produce identical output format (PASS/FAIL/SKIP messages, `[N/15]` numbering)
- Preserve all test ordering and skip behavior
- Eliminate the `clippy::too_many_lines` lint violation
- Pass `cargo clippy -p xtask` and `cargo fmt --check`

## Acceptance Criteria

### AC1: `run_conformance()` reduced to ≤100 lines
After refactoring, `run_conformance()` (lines 14–221 in `conform_real.rs`) must have ≤100 non-blank/non-comment lines. Clippy's `clippy::too_many_lines` warning must not fire with `cargo clippy -p xtask -- -W clippy::too_many_lines`.

### AC2: Output format preserved
The refactored code must produce identical output for all 15 tests:
- Per-test header: `  [N/15] Test name... ` (including exactly two leading spaces)
- PASS: `  [N/15] Test name... PASS`
- FAIL: `  [N/15] Test name... FAIL: <error>`
- SKIP (quick mode): `  [N/15] Test name... SKIP (quick mode)`
- Summary line: `Results: <passed>/<total> tests passed` (or `X/15 tests passed, Y failed` on failure)

The denominator in `[N/15]` is always `15`, even in quick mode (matching current behavior).

### AC3: `quick` skip behavior preserved
When `quick: true`, `test_determinism` (test #2) must be skipped with the SKIP message. All other 14 tests must run normally. When `quick: false`, all 15 tests must run.

### AC4: All 15 tests included
The static descriptor list must include all 15 conformance tests in the original execution order:
1. `test_schema_validation`
2. `test_determinism`
3. `test_survivability`
4. `test_required_fields`
5. `test_vocabulary`
6. `test_json_schema_file`
7. `test_schema_drift`
8. `test_vocabulary_constants`
9. `test_tool_error_code`
10. `test_token_lint`
11. `test_path_hygiene`
12. `test_fingerprint_format`
13. `test_artifact_path_hygiene`
14. `test_cockpit_output_layout`
15. `test_data_diffguard_shape`

### AC5: `test_vocabulary_constants` handled correctly
`test_vocabulary_constants()` returns `()` (not `Result<()>`). It must be wrapped in a named module-level function `fn run_vocabulary_constants_test() -> Result<()>` that calls the test and returns `Ok(())`. The wrapper is stored as a function pointer in the descriptor list.

### AC6: `#[cfg(test)]` module unchanged
The test module at lines 1435–1486 (containing tests for `cargo_bin_path`, `setup_minimal_repo`, `setup_test_repo_with_finding`, `determinism_test_runs`) must not be modified.

### AC7: `cargo clippy` and `cargo fmt` pass
After refactoring:
- `cargo clippy -p xtask` must complete with zero warnings
- `cargo fmt --check` must pass (no formatting diffs)

## Non-Goals

- This refactor does NOT modify any of the 15 test functions themselves
- This refactor does NOT change `conform.rs`, `main.rs`, or any production crate code
- This refactor does NOT add a smoke test for `cargo xtask conform` output (out of scope)
- This refactor does NOT fix the `[N/15]` denominator inconsistency in quick mode (preserves as-is)

## Dependencies

- **Rust toolchain**: Standard Rust 2021 edition, no additional dependencies
- **Existing imports**: `anyhow`, `tempfile`, `serde`, `serde_json` already present in `conform_real.rs`
- **No new crates**: The refactor uses only stdlib and existing crate imports

## Technical Notes

### Type Signature for Descriptors
The `run` field of `ConformanceTest` must be `fn() -> Result<()>` to allow storing function pointers for all 15 tests uniformly. Closures cannot be stored in `fn()` fields — use a named wrapper function for `test_vocabulary_constants`.

### Explicit Position Field
`ConformanceTest.position` is an explicit `u8` field (not derived from array index via `enumerate()`). This prevents silent misnumbering if tests are reordered in the array.

### Static Descriptor List
```rust
static CONFORMANCE_TESTS: &[ConformanceTest] = &[
    // position, name, run fn, skip_in_quick
    ConformanceTest { position: 1, name: "Schema validation (serde)", run: test_schema_validation, skip_in_quick: false },
    ConformanceTest { position: 2, name: "Determinism", run: test_determinism, skip_in_quick: true },
    // ... etc
];
```
