# Plan Review Comment: Performance Benchmark Infrastructure

## Approach Assessment

**Verdict: Feasible with modifications required**

The plan correctly identifies criterion as the standard Rust benchmarking framework and appropriately leverages the existing workspace structure. However, three critical API realities from the verification comment are either missing or under-addressed in the implementation approach:

1. **Preprocessor mutable state** — The plan implies `Preprocessor::sanitize_line` can be called as a pure function. It cannot. It requires `&mut self` and tracks multi-line comment/string state across lines. This affects the preprocessing benchmark design fundamentally.

2. **DiffLine → InputLine conversion** — The plan benchmarks `evaluate_lines()` using synthetic `InputLine` iterators but does not address the conversion step from `DiffLine` (which has an extra `kind` field). The actual pipeline must do this conversion.

3. **testkit bounds are too small for benchmark sizes** — The testkit's `MAX_LINES_PER_HUNK=20` and `MAX_HUNKS_PER_FILE=5` mean it cannot generate 100K-line diffs. The plan's stated "benchmark sizes" (100, 1K, 10K, 100K lines) require custom generators for the large sizes, not testkit.

---

## Risk Analysis

### Risk 1: Preprocessor State Pollution Between Benchmark Iterations

**Severity: High**

The `Preprocessor` tracks multi-line comment/string state via its internal `mode: Mode` field. If the same instance is reused across iterations without calling `reset()`, state from one iteration leaks into the next, corrupting measurements.

**Specific failure mode**: Benchmarking Rust code with a multi-line comment at end-of-iteration triggers `Mode::BlockComment` state. Next iteration starts inside a block comment, causing `sanitize_line` to consume lines incorrectly.

**Mitigation in plan**: Not addressed. Implementation must either:
- Create fresh `Preprocessor` per iteration (safest, but may mask allocation costs)
- Call `preprocessor.reset()` between iterations (includes reset overhead in measurement if not careful)

**Recommendation**: Use `preprocessor.reset()` but measure carefully — ensure the measured code path includes the reset call to capture real pipeline behavior.

---

### Risk 2: DiffLine → InputLine Conversion Overhead Not Isolated

**Severity: Medium**

The plan creates synthetic `InputLine` iterators directly for evaluation benchmarks, bypassing the `DiffLine → InputLine` conversion that the real pipeline requires. This omission means:

- Evaluation benchmarks measure only regex/glob matching, not the full data transformation
- The conversion (cloning 3 fields per line) may not be negligible at scale

**Specific failure mode**: A performance "regression" in rule evaluation may actually be a regression in the conversion step, not the matching logic.

**Recommendation**: Add a separate benchmark group that measures `DiffLine → InputLine` conversion throughput, or include the conversion in the measured section of the evaluation benchmark.

---

### Risk 3: testkit Cannot Generate Benchmark-Scale Inputs

**Severity: Medium-High**

The plan states "Use synthetic unified diffs generated from `diffguard-testkit` fixtures" for parsing benchmarks at 100K lines. The testkit enforces `MAX_LINES_PER_HUNK=20` and `MAX_HUNKS_PER_FILE=5`, which caps synthetic diffs at ~100 lines regardless of strategy parameters.

**Specific failure mode**: Implementation agent attempts to use testkit for 100K-line diffs, hits strategy bounds, either gets truncated input or panics.

**Recommendation**: The plan's `bench/fixtures.rs` should own all generator code for sizes exceeding testkit bounds. Do not attempt to use testkit for sizes > ~500 lines. The plan is correct that `bench/fixtures.rs` is needed; it underestimates how much it needs to own.

---

### Risk 4: CI Runner Performance Variance Degrades Regression Detection

**Severity: Medium**

GitHub Actions runners experience non-trivial performance variance (typically ±10-30% for microbenchmarks) due to shared hardware, thermal throttling, and background processes.

**Specific failure mode**: A 15% performance regression is lost in noise, or a 10% improvement from noise triggers false confidence.

**Recommendation**: The plan's CSV artifact upload is correct for trend analysis. However, consider:
- Running benchmarks multiple times in CI and reporting medians
- Documenting in README that absolute numbers vary by hardware, and comparing only within the same runner class
- Using criterion's `--noplot` to reduce log verbosity while still collecting comparable data

---

### Risk 5: criterion = "0.5" Compatibility with Rust 1.92.0 / Edition 2024

**Severity: Low-Medium**

The plan specifies `criterion = "0.5"` but does not verify compatibility with:
- Rust 1.92.0 (from `rust-toolchain.toml`)
- Edition 2024

**Specific failure mode**: `cargo bench` compiles but produces incorrect measurements, or fails to compile.

**Recommendation**: The implementation agent should run a test compile with `cargo add criterion --dev` before finalizing the dependency version. Criterion 0.5 was released ~2024; Rust 1.92 is cutting-edge. If issues arise, criterion 0.6 or a git revision may be needed.

---

## Edge Cases Identified

### Edge Case 1: Zero Rules Evaluation

The plan tests "1, 10, 100, 500 rules" but not **zero rules**. Evaluating with zero rules is a valid (and fast) code path. Benchmarks should include this case to establish a baseline floor.

### Edge Case 2: Empty Diff (Zero Lines)

Parsing benchmarks start at "100 lines". A diff with zero lines (empty diff) or a diff with only headers (no hunks) is a valid input that should be benchmarked.

### Edge Case 3: Binary File Entries in Diff

`parse_unified_diff` handles binary files specially. If benchmark diffs contain binary file markers (`Binary files ... differ`), the parser behavior differs. Ensure synthetic diffs are explicitly text-only or test both.

### Edge Case 4: Preprocessor Language::Unknown Behavior

`Preprocessor::new(opts)` creates with `Language::Unknown`. Benchmarks using the "no language" case should verify that `sanitize_line` with `Language::Unknown` is a no-op or C-like fallback.

### Edge Case 5: Rule Compilation Time vs. Evaluation Time

The plan mentions "pre-compile rules once per benchmark group" for evaluation. However, rule compilation time varies by regex complexity. If compilation is slow (e.g., complex regex with backtracking), the one-time cost may dominate. Consider whether to measure compilation + evaluation together.

---

## Recommendations for Implementation Agent

### Must Fix Before Implementation

1. **Preprocessor benchmark design**: Use `Preprocessor::with_language()` with language set at construction. Call `reset()` between iterations or create fresh instance per iteration. Document which approach is used.

2. **Large diff generation**: Build a dedicated generator in `bench/fixtures.rs` for sizes > 1K lines. Do not attempt to use testkit beyond its bounds.

3. **DiffLine → InputLine conversion**: Add explicit conversion helper function. Consider including it in the measured evaluation benchmark path.

### Should Fix for Quality

4. **Zero-input cases**: Add benchmarks for 0 rules, 0 lines, 0 findings to establish baseline floors.

5. **CI stability**: Document runner variance in README. Consider median-of-3 runs in CI.

6. **Criterion version verification**: Test-compile criterion before committing to version.

### Optional Improvements

7. **Memory measurement**: Defer to follow-up issue. Wall-clock is sufficient for initial infrastructure.

8. **Rendering benchmark receipt construction**: Pre-generate `CheckReceipt` with findings offline and deserialize in benchmark to avoid constructing complex receipt structures in the measured path.

---

## Files Assessment

| File | Plan Status | Issues |
|------|-------------|--------|
| `Cargo.toml` | Correct | Add criterion, add [[bench]] targets |
| `bench/Cargo.toml` | Correct | New package; ensure `publish = false` |
| `bench/lib.rs` | Correct | Minimal; just re-export fixtures |
| `bench/fixtures.rs` | Under-specified | Must own ALL size generators, not just "beyond testkit bounds" |
| `bench/benches/parsing.rs` | Correct structure | Must use custom generators for large sizes |
| `bench/benches/evaluation.rs` | Missing conversion | Must include DiffLine→InputLine conversion or separate it |
| `bench/benches/rendering.rs` | Correct structure | Pre-generate receipts offline |
| `bench/benches/preprocessing.rs` | Incomplete | Must handle `&mut self` and `reset()` between iterations |
| `.github/workflows/ci.yml` | Correct | Consider multiple runs for stability |
| `README.md` | Correct | Document runner variance; baseline numbers as placeholder |

---

## Conclusion

The plan is fundamentally sound but under-specifies three critical areas: preprocessor mutable state handling, the DiffLine→InputLine conversion step, and the scope of fixture generation needed. The implementation agent should address the "Must Fix" items before proceeding to ensure benchmarks measure what they claim to measure.

**Confidence: Medium** — The approach is correct; implementation details need correction before coding begins.
