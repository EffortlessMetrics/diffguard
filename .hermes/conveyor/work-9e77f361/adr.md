# ADR 0013: Performance Benchmark Infrastructure

**Status:** Proposed  
**Date:** 2026-04-07  
**Work Item:** work-9e77f361  

---

## Context

Diffguard lacks benchmark infrastructure to prove or protect its "fast because diff-scoped" performance advantage. Currently:

- No criterion or benchmark framework exists in the workspace
- Performance regressions go undetected across PRs
- Cannot evaluate diffguard's speed on representative codebase sizes
- The project's existing test maturity (unit tests, snapshot tests, property-based tests, mutation tests, fuzz tests) is incomplete without benchmark coverage

The issue ([#36](https://github.com/EffortlessMetrics/diffguard/issues/36)) explicitly calls out this gap. The architecture supports isolated benchmarking: domain crates are I/O-free, allowing pure function measurement.

---

## Decision

We will add criterion-based benchmark infrastructure to the diffguard workspace with the following structure and constraints:

### 1. Framework: criterion 0.5

Use `criterion = "0.5"` as the benchmarking framework. It is the standard Rust framework with built-in statistical analysis, warmup, and comparison reporting. It integrates with `cargo bench` and requires no custom measurement infrastructure.

### 2. Package Location: `bench/` at workspace root

Create a new `bench/` package at the workspace root level as a `[bench]` binary crate (not a library). This follows Rust conventions and allows `cargo bench --workspace` to discover all benchmarks.

```
bench/
├── Cargo.toml                    # Package manifest
├── lib.rs                        # Re-exports for shared utilities
├── benches/
│   ├── parsing.rs               # Diff parsing benchmarks
│   ├── evaluation.rs            # Rule evaluation benchmarks
│   ├── rendering.rs             # Output rendering benchmarks
│   └── preprocessing.rs         # Comment/string masking benchmarks
└── fixtures.rs                  # Synthetic input generators (sizes beyond testkit bounds)
```

### 3. Four Benchmark Categories

| Category | Sizes Tested | Function Benchmarked |
|----------|-------------|---------------------|
| Parsing | 100, 1K, 10K, 100K lines | `parse_unified_diff()` |
| Evaluation | 0, 1, 10, 100, 500 rules | `evaluate_lines()` |
| Rendering | 0, 10, 100, 1000 findings | `render_*_for_receipt()` |
| Preprocessing | 0%, 25%, 50%, 75% comment density | `Preprocessor::sanitize_line()` |

**Note on sizes:** The existing `diffguard-testkit` enforces bounds (`MAX_LINES_PER_HUNK=20`, `MAX_HUNKS_PER_FILE=5`) unsuitable for 100K-line diffs. The `bench/fixtures.rs` module will own all generators for sizes exceeding testkit bounds. Testkit will be used for small/medium sizes only.

### 4. Preprocessor State Handling

`Preprocessor::sanitize_line()` requires `&mut self` and tracks multi-line comment/string state via internal `mode: Mode` field. Benchmarks must:

- Use `Preprocessor::with_language(opts, lang)` to set language at construction
- Call `preprocessor.reset()` between iterations to clear state
- **Alternative:** Create fresh instance per iteration (safest, but includes allocation cost)

The measured code path must include the `reset()` call or instance creation to capture real pipeline behavior.

### 5. DiffLine → InputLine Conversion

`DiffLine` (from `diffguard-diff`) and `InputLine` (from `diffguard-domain`) are distinct types:

```rust
// DiffLine has an extra `kind: ChangeKind` field
struct DiffLine { path, line, content, kind }

// InputLine has no kind field
struct InputLine { path, line, content }
```

Benchmarks measuring the full evaluation pipeline must include explicit `DiffLine → InputLine` conversion. A helper function `convert_diff_line_to_input_line()` will be added to `bench/fixtures.rs` to avoid repetition.

### 6. Zero-Input Edge Cases Included

Benchmarks will include zero-input cases as baseline floors:
- 0 rules (valid fast path for evaluation)
- 0 lines (empty diff)
- 0 findings (rendering baseline)

### 7. CI Integration

Add a `bench` job to `.github/workflows/ci.yml`:

```yaml
bench:
  name: Benchmarks
  runs-on: ubuntu-latest
  if: github.ref == 'refs/heads/main'  # Only on main, not PRs
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - run: cargo bench --workspace -- --output-format csv > bench_results.csv
    - uses: actions/upload-artifact@v4
      with:
        name: bench-results
        path: bench_results.csv
```

**Runner variance note:** GitHub Actions shared runners have ±10-30% microbenchmark variance. Absolute numbers will vary; focus on relative comparisons and trend analysis via artifact storage.

### 8. README Performance Section

Add a `## Performance` section to `README.md` documenting:
- Baseline timing numbers per category (with hardware context)
- Runner variance disclaimer
- How to run benchmarks locally
- How to interpret criterion comparison output

---

## Consequences

### Positive
- Enables data-driven performance claims ("100K-line parse is 3ms")
- Provides regression protection as the project scales
- Completes the testing maturity picture (units, snapshots, property-based, mutation, fuzz, benchmarks)
- Supports "dogfood its own governance" — benchmarks complement fuzz and mutation tests

### Negative / Tradeoffs
- **CI maintenance:** Additional job to maintain; may need adjustment if runner variance proves too noisy
- **Initial setup effort:** ~6 new files across bench/ directory structure
- **Benchmark hygiene burden:** Developers must ensure measured code paths don't include setup/teardown

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Preprocessor state pollution between iterations | High | Use `reset()` between iterations; document the approach |
| Testkit bounds too small for 100K lines | Medium | bench/fixtures.rs owns all large-size generators |
| CI runner variance degrades regression detection | Medium | Artifact storage for trend analysis; focus on relative comparisons |
| DiffLine→InputLine conversion overhead not isolated | Medium | Add conversion to measured path or separate benchmark group |
| criterion 0.5 + Rust 1.92.0 edition 2024 compatibility | Low | Verify via test compile before finalizing |

### Deferred (Non-Goals for This Work)
- Memory measurement infrastructure (use wall-clock time only initially)
- Performance regression thresholds (benches serve detection, thresholds are a follow-up policy decision)
- Self-hosted CI runners for reduced variance

---

## Alternatives Considered

### Alternative 1: Iai (iai-metrics)

**Rejected.** Iai uses Dhat/valgrind for allocation profiling and is more precise than criterion. However:
- Iai is unmaintained (last release 2022)
- Less community adoption than criterion
- Criterion is sufficient for wall-clock regression detection
- Memory profiling can be added as a follow-up using criterion's allocation tracking

### Alternative 2: Custom Benchmark Harness

**Rejected.** Building a custom harness would:
- Reinvent warmup, statistical analysis, and comparison reporting
- Add significant implementation effort with no competitive advantage
- Miss criterion's ecosystem integration (cargo bench, criterion mat)

### Alternative 3: No Benchmarks (Defer)

**Rejected.** The issue explicitly identifies benchmark infrastructure as a P1 gap. Without it, performance regressions go undetected and the "fast" value proposition cannot be demonstrated. The existing architectural cleanliness (I/O-free domain crates) makes benchmarking straightforward.

### Alternative 4: Fuzz + Benchmarks Combined via `cargo-fuzz`

**Rejected.** Fuzz targets (`fuzz/fuzz_targets/`) already exist separately. Benchmarks measure steady-state performance; fuzzing finds edge cases. They are complementary but serve different purposes.

---

## References

- Issue: [#36 - P1: Add performance benchmark infrastructure](https://github.com/EffortlessMetrics/diffguard/issues/36)
- Research Analysis: `.hermes/conveyor/work-9e77f361/research_analysis.md`
- Verification Comment: `.hermes/conveyor/work-9e77f361/verification_comment.md`
- Plan Review: `.hermes/conveyor/work-9e77f361/plan_review_comment.md`
- Vision Alignment: `.hermes/conveyor/work-9e77f361/vision_alignment_comment.md`
