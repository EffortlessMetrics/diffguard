# Specification: Performance Benchmark Infrastructure

**Work Item:** work-9e77f361  
**Date:** 2026-04-07  
**Repo:** /home/hermes/repos/diffguard  

---

## Feature Description

Add benchmark infrastructure to the diffguard workspace using criterion 0.5, enabling measurement and regression detection for diff parsing, rule evaluation, output rendering, and comment/string preprocessing performance.

Benchmarks run via `cargo bench --workspace` and are tracked in CI on pushes to `main`.

---

## Acceptance Criteria

### AC-1: Benchmark Framework Integration

- [ ] `cargo bench --workspace` completes without compilation errors
- [ ] `criterion = "0.5"` is declared in workspace `[dependencies]`
- [ ] Four `[[bench]]` targets are declared in workspace `Cargo.toml`: parsing, evaluation, rendering, preprocessing
- [ ] `bench/` package has `publish = false` in `Cargo.toml`

### AC-2: Parsing Benchmarks

- [ ] Benchmarks `parse_unified_diff()` from `diffguard_diff::unified`
- [ ] Tests 5 input sizes: 0 lines (empty), 100 lines, 1K lines, 10K lines, 100K lines
- [ ] Uses synthetic unified diff text generated in-memory (no file I/O)
- [ ] For sizes > 1K lines, uses generators in `bench/fixtures.rs` (not testkit)

### AC-3: Evaluation Benchmarks

- [ ] Benchmarks `evaluate_lines()` from `diffguard_domain::evaluate`
- [ ] Tests 5 rule counts: 0 rules, 1 rule, 10 rules, 100 rules, 500 rules
- [ ] Rules are pre-compiled once per benchmark group via `compile_rules()` (not included in measured time)
- [ ] Uses synthetic `InputLine` iterators; DiffLine → InputLine conversion is included in measured path
- [ ] Helper `convert_diff_line_to_input_line()` exists in `bench/fixtures.rs`

### AC-4: Rendering Benchmarks

- [ ] Benchmarks `render_markdown_for_receipt()` and `render_sarif_for_receipt()` from `diffguard_core::render`
- [ ] Tests 4 finding counts: 0 findings, 10 findings, 100 findings, 1000 findings
- [ ] `CheckReceipt` with findings is pre-constructed before measurement (not included in measured time)
- [ ] Both Markdown and SARIF renderers are benchmarked

### AC-5: Preprocessing Benchmarks

- [ ] Benchmarks `Preprocessor::sanitize_line()` from `diffguard_domain::preprocess`
- [ ] Tests 4 comment densities: 0% (plain code), 25%, 50%, 75%
- [ ] Tests 3 languages: Rust, Python, JavaScript
- [ ] Uses `Preprocessor::with_language(opts, lang)` for construction
- [ ] Calls `preprocessor.reset()` between iterations OR creates fresh instance per iteration
- [ ] Approach is documented in the benchmark file

### AC-6: Fixture Generation

- [ ] `bench/fixtures.rs` provides generators for all sizes beyond testkit bounds (especially 100K lines)
- [ ] All generators produce in-memory data (no file I/O)
- [ ] `DiffLine → InputLine` conversion helper is exported from `bench/fixtures.rs`

### AC-7: CI Integration

- [ ] `bench` job added to `.github/workflows/ci.yml`
- [ ] Job triggers only on `push` to `main` (not on pull requests)
- [ ] Job runs `cargo bench --workspace -- --output-format csv > bench_results.csv`
- [ ] Job uploads `bench_results.csv` as a GitHub Actions artifact

### AC-8: Documentation

- [ ] `README.md` updated with `## Performance` section
- [ ] Section includes:
  - Baseline timing numbers for each benchmark category
  - Hardware context for the baseline (e.g., "Measured on GitHub Actions ubuntu-latest-8c")
  - Runner variance disclaimer
  - Command to run benchmarks locally: `cargo bench --workspace`
  - Command to view HTML report: `cargo bench --workspace -- --html`

### AC-9: Domain Crate Invariants Preserved

- [ ] Benchmark code does not use `std::fs`, `std::process`, or `std::env` in domain crates
- [ ] All inputs are synthetic (generated in-memory)
- [ ] No file I/O operations in benchmark measurement paths

---

## Non-Goals

The following are explicitly **out of scope** for this work item:

1. **Memory measurement infrastructure** — Wall-clock time only for initial implementation. Memory profiling via criterion's allocation tracking or tracing can be added as a follow-up.

2. **Performance regression thresholds** — Benches detect regressions; threshold-based CI failure is a policy decision deferred to a follow-up.

3. **Stable benchmark artifact storage** — Initial implementation uploads CSV to GitHub Actions artifact. Long-term trend storage (database, benchmark-bot) is deferred.

4. **Self-hosted CI runners** — Shared GitHub Actions runners are accepted despite variance; dedicated hardware is a future consideration.

5. **Criterion HTML report in CI** — CSV artifact is sufficient for trend analysis. HTML report available locally.

---

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `criterion` | 0.5 | Benchmark framework |
| `diffguard-diff` | workspace | Diff parsing benchmarks |
| `diffguard-domain` | workspace | Evaluation and preprocessing benchmarks |
| `diffguard-core` | workspace | Rendering benchmarks |
| `diffguard-testkit` | workspace | Small/medium fixture generation (dev dependency) |

---

## File Inventory

### Files to Create

| File | Purpose |
|------|---------|
| `bench/Cargo.toml` | Package manifest with `bench = true` |
| `bench/lib.rs` | Re-exports shared utilities |
| `bench/fixtures.rs` | Synthetic input generators, DiffLine→InputLine converter |
| `bench/benches/parsing.rs` | Parsing benchmarks |
| `bench/benches/evaluation.rs` | Evaluation benchmarks |
| `bench/benches/rendering.rs` | Rendering benchmarks |
| `bench/benches/preprocessing.rs` | Preprocessing benchmarks |

### Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add `criterion = "0.5"` to workspace.dependencies; add 4 `[[bench]]` targets |
| `.github/workflows/ci.yml` | Add `bench` job |
| `README.md` | Add `## Performance` section |

---

## Verification Checklist

The following must be verified before closing this work item:

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo bench --workspace` completes without errors
- [ ] All four benchmark categories run (parsing, evaluation, rendering, preprocessing)
- [ ] Multiple sizes are tested per category (see AC-2 through AC-5)
- [ ] `cargo clippy --workspace` produces no warnings in bench/ crate
- [ ] `cargo fmt -- --check` passes for all bench/ files
- [ ] CI `bench` job appears in `.github/workflows/ci.yml` and triggers on main push
- [ ] `README.md` contains `## Performance` section with baseline numbers
- [ ] No `std::fs`, `std::process`, or `std::env` usage in domain benchmark paths

---

## API Accuracy Notes (from Verification)

These API details were verified and must be used correctly in implementation:

```rust
// diffguard-diff/src/unified.rs
pub fn parse_unified_diff(
    diff_text: &str,
    scope: Scope,
) -> Result<(Vec<DiffLine>, DiffStats), DiffParseError>

// diffguard-domain/src/evaluate.rs
pub fn evaluate_lines(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
) -> Evaluation

// diffguard-domain/src/preprocess.rs
pub fn Preprocessor::new(opts: PreprocessOptions) -> Self
pub fn Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self
pub fn sanitize_line(&mut self, line: &str) -> String  // NOTE: &mut self required
pub fn reset(&mut self)

// diffguard-domain/src/rules.rs
pub fn compile_rules(configs: &[RuleConfig]) -> Result<Vec<CompiledRule>, RuleCompileError>

// diffguard-core/src/render.rs
pub fn render_markdown_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_sarif_for_receipt(receipt: &CheckReceipt) -> SarifReport
pub fn render_junit_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_csv_for_receipt(receipt: &CheckReceipt) -> String

// Type conversion needed
struct DiffLine { path: String, line: u32, content: String, kind: ChangeKind }
struct InputLine { path: String, line: u32, content: String }  // NOTE: no `kind` field
```

---

## References

- Issue: [#36](https://github.com/EffortlessMetrics/diffguard/issues/36)
- ADR: `.hermes/conveyor/work-9e77f361/adr.md`
