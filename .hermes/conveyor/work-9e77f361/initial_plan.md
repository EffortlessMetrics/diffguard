# Initial Plan: Performance Benchmark Infrastructure

## Approach

We use `criterion = "0.5"` because it is the standard Rust benchmarking framework, integrates with `cargo bench`, and has built-in statistical analysis. We avoid custom benchmarking because criterion handles warmup, measurement, and comparison automatically—saving significant implementation effort.

### 1. Add criterion dependency to workspace

Add `criterion = "0.5"` to `[workspace.dependencies]` in `Cargo.toml`.

### 2. Create bench/ directory structure

```
bench/
├── benches/
│   ├── parsing.rs
│   ├── evaluation.rs
│   ├── rendering.rs
│   └── preprocessing.rs
├── fixtures.rs          # Shared generators for synthetic diffs/rules
└── lib.rs
```

### 3. Create benchmark files

#### `bench/benches/parsing.rs`
- Benchmark `parse_unified_diff()` with 4 input sizes: 100, 1K, 10K, 100K lines
- Use synthetic unified diffs generated from `diffguard-testkit` fixtures
- Measure wall-clock time; consider measuring allocations via `tracing`

#### `bench/benches/evaluation.rs`
- Benchmark `evaluate_lines()` with 4 rule counts: 1, 10, 100, 500 rules
- Pre-compile rules once per benchmark group; reuse across iterations
- Use `InputLine` iterator from synthetic diffs

#### `bench/benches/rendering.rs`
- Benchmark `render_markdown_for_receipt()` and `render_sarif_for_receipt()`
- Test with 4 finding counts: 0, 10, 100, 1000
- Pre-generate `CheckReceipt` with findings

#### `bench/benches/preprocessing.rs`
- Benchmark `Preprocessor::sanitize_line()` with 4 comment densities
- Test multiple languages (Rust, Python, JavaScript)
- Measure per-line processing time

### 4. Add `[[bench]]` targets to workspace Cargo.toml

```toml
[[bench]]
name = "parsing"
harness = false

[[bench]]
name = "evaluation"
harness = false

[[bench]]
name = "rendering"
harness = false

[[bench]]
name = "preprocessing"
harness = false
```

### 5. Add CI job to `.github/workflows/ci.yml`

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

### 6. Update README with baseline performance section

Add `## Performance` section with table of baseline numbers from `cargo bench`.

---

## Risks

### Risk 1: Benchmark input generation overhead dominates measurement
**Mitigation**: Generate inputs once per benchmark group via `criterion::Criterion::batch_with_inputs()` or lazy statics. Ensure input generation is not included in measured time.

### Risk 2: Domain crate I/O constraint violated by benchmark fixtures
**Mitigation**: All benchmark inputs are synthetic (no file I/O). Fixtures use in-memory string generation only. `diffguard-testkit` is a dev-dependency only.

### Risk 3: Criterion output is too verbose in CI logs
**Mitigation**: Use `-- --output-format csv` to redirect detailed output to artifact; CI log shows only summary.

### Risk 4: Memory measurement is complex to implement correctly
**Mitigation**: Start with wall-clock time only. Memory tracking via `tracing` or `allocator` instrumentation can be added as a follow-up if needed.

### Risk 5: Benchmark times vary significantly across hardware/CI runners
**Mitigation**: Focus on relative comparisons (e.g., "100 rules is 10x slower than 1 rule"). CI benchmarks track against previous runs for regression detection.

---

## Task Breakdown

### High-Level Tasks

1. **Add criterion to workspace dependencies**
   - Edit `Cargo.toml` workspace section

2. **Create bench/ directory with Cargo.toml**
   - New package at `bench/` with `bench = true` manifest
   - Depends on: `criterion`, `diffguard-*` crates, `diffguard-testkit`

3. **Create benchmark source files**
   - `bench/benches/parsing.rs` — 4 input sizes
   - `bench/benches/evaluation.rs` — 4 rule counts
   - `bench/benches/rendering.rs` — 4 finding counts
   - `bench/benches/preprocessing.rs` — 4 comment densities
   - `bench/fixtures.rs` — shared synthetic input generators

4. **Add CI job to `.github/workflows/ci.yml`**
   - New `bench` job
   - Runs on main push only
   - Uploads CSV artifact

5. **Update README with baseline numbers**
   - New `## Performance` section
   - Table with baseline timing per benchmark category

6. **Verify and iterate**
   - Run `cargo bench --workspace` locally
   - Ensure CI passes
   - Confirm no I/O violations in domain crates

---

## Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add criterion dependency, add [[bench]] targets |
| `bench/Cargo.toml` | New package manifest |
| `bench/benches/parsing.rs` | New file |
| `bench/benches/evaluation.rs` | New file |
| `bench/benches/rendering.rs` | New file |
| `bench/benches/preprocessing.rs` | New file |
| `bench/fixtures.rs` | New file |
| `bench/lib.rs` | New file |
| `.github/workflows/ci.yml` | Add bench job |
| `README.md` | Add Performance section |

---

## Files to Create

| File |
|------|
| `bench/Cargo.toml` |
| `bench/lib.rs` |
| `bench/benches/parsing.rs` |
| `bench/benches/evaluation.rs` |
| `bench/benches/rendering.rs` |
| `bench/benches/preprocessing.rs` |
| `bench/fixtures.rs` |
