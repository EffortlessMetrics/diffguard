# Task List: Performance Benchmark Infrastructure

## work-9e77f361

---

## Task 1: Add criterion dependency and bench targets to workspace Cargo.toml
- **Description:** Add `criterion = "0.5"` to `[workspace.dependencies]`, add `bench/` to workspace `members`, and declare four `[[bench]]` targets in workspace `Cargo.toml`.
- **Inputs:** `/home/hermes/repos/diffguard/Cargo.toml`
- **Outputs:** Modified `/home/hermes/repos/diffguard/Cargo.toml` with criterion dependency and bench targets
- **Depends on:** None
- **Complexity:** Small
- **Notes:** This must be done before any bench/ file compiles. The four bench targets are: `parsing`, `evaluation`, `rendering`, `preprocessing`.

---

## Task 2: Create bench/ directory structure and package manifest
- **Description:** Create `bench/`, `bench/benches/` directories and write `bench/Cargo.toml` with `bench = true`, `publish = false`, and workspace dependencies (criterion, diffguard-diff, diffguard-domain, diffguard-core as dev-dependencies; diffguard-testkit as dev dependency).
- **Inputs:** `/home/hermes/repos/diffguard/Cargo.toml` (for workspace deps)
- **Outputs:** `bench/Cargo.toml`
- **Depends on:** Task 1
- **Complexity:** Small

---

## Task 3: Create bench/lib.rs
- **Description:** Create `bench/lib.rs` that re-exports shared utilities (fixture generators) for benchmark modules. Initially this may be a placeholder if fixtures.rs is the main utility module.
- **Inputs:** None
- **Outputs:** `bench/lib.rs`
- **Depends on:** Task 2
- **Complexity:** Small

---

## Task 4: Create bench/fixtures.rs with generators and helpers
- **Description:** Create `bench/fixtures.rs` containing:
  - Synthetic unified diff text generators for 100K-line diffs (beyond testkit bounds)
  - `DiffLine → InputLine` conversion helper
  - All generators produce in-memory data (no file I/O)
- **Inputs:** Specs AC-2, AC-3, AC-6 for API signatures (`parse_unified_diff`, `evaluate_lines`, `compile_rules`, `Preprocessor`, `DiffLine`, `InputLine`)
- **Outputs:** `bench/fixtures.rs`
- **Depends on:** Task 2
- **Complexity:** Medium
- **Notes:** Must not use `std::fs`, `std::process`, or `std::env`. All data generated in-memory. Key API note: `Preprocessor::sanitize_line()` requires `&mut self` and tracks multi-line comment state; use `reset()` between iterations.

---

## Task 5: Create bench/benches/parsing.rs
- **Description:** Create parsing benchmarks benchmarking `parse_unified_diff()` from `diffguard_diff::unified`. Test 5 sizes: 0 lines (empty), 100, 1K, 10K, 100K lines. For sizes > 1K use fixtures from `bench/fixtures.rs`.
- **Inputs:** `bench/fixtures.rs`, `diffguard_diff::unified::parse_unified_diff`
- **Outputs:** `bench/benches/parsing.rs`
- **Depends on:** Task 4
- **Complexity:** Small
- **Notes:** Include warmup and measured iteration via criterion API. Use synthetic unified diff text only.

---

## Task 6: Create bench/benches/evaluation.rs
- **Description:** Create evaluation benchmarks benchmarking `evaluate_lines()` from `diffguard_domain::evaluate`. Test 5 rule counts: 0, 1, 10, 100, 500 rules. Rules compiled once per group via `compile_rules()` (outside measured time). DiffLine → InputLine conversion included in measured path via helper from fixtures.rs.
- **Inputs:** `bench/fixtures.rs`, `diffguard_domain::evaluate::evaluate_lines`, `diffguard_domain::rules::compile_rules`
- **Outputs:** `bench/benches/evaluation.rs`
- **Depends on:** Task 4
- **Complexity:** Small
- **Notes:** DiffLine → InputLine conversion must be in measured path.

---

## Task 7: Create bench/benches/rendering.rs
- **Description:** Create rendering benchmarks benchmarking `render_markdown_for_receipt()` and `render_sarif_for_receipt()` from `diffguard_core::render`. Test 4 finding counts: 0, 10, 100, 1000. Pre-construct `CheckReceipt` with findings before measurement (outside measured time).
- **Inputs:** `bench/fixtures.rs`, `diffguard_core::render::{render_markdown_for_receipt, render_sarif_for_receipt}`, `diffguard_core::CheckReceipt`
- **Outputs:** `bench/benches/rendering.rs`
- **Depends on:** Task 4
- **Complexity:** Small

---

## Task 8: Create bench/benches/preprocessing.rs
- **Description:** Create preprocessing benchmarks benchmarking `Preprocessor::sanitize_line()` from `diffguard_domain::preprocess`. Test 4 comment densities (0%, 25%, 50%, 75%) across 3 languages (Rust, Python, JavaScript). Use `Preprocessor::with_language(opts, lang)`. Document whether using `reset()` between iterations or fresh instance per iteration.
- **Inputs:** `bench/fixtures.rs`, `diffguard_domain::preprocess::{Preprocessor, PreprocessOptions, Language}`
- **Outputs:** `bench/benches/preprocessing.rs`
- **Depends on:** Task 4
- **Complexity:** Small
- **Notes:** CRITICAL: `sanitize_line` requires `&mut self`. State must be reset between iterations or fresh instance created per iteration. Document the approach used.

---

## Task 9: Add bench job to CI workflow
- **Description:** Add `bench` job to `.github/workflows/ci.yml` that: runs on `push` to `main` only (not PRs), checks out code, installs Rust, runs `cargo bench --workspace -- --output-format csv > bench_results.csv`, and uploads artifact.
- **Inputs:** `.github/workflows/ci.yml`
- **Outputs:** Modified `.github/workflows/ci.yml`
- **Depends on:** Task 1 (criterion must be in workspace to avoid compile failure)
- **Complexity:** Small
- **Notes:** Use `if: github.ref == 'refs/heads/main'` condition. Use `actions/upload-artifact@v4`.

---

## Task 10: Add Performance section to README.md
- **Description:** Add `## Performance` section to `README.md` documenting: baseline timing numbers per category, hardware context (GitHub Actions ubuntu-latest-8c), runner variance disclaimer, commands to run benchmarks locally (`cargo bench --workspace`) and view HTML report (`cargo bench --workspace -- --html`).
- **Inputs:** `README.md`
- **Outputs:** Modified `README.md`
- **Depends on:** Task 5, 6, 7, 8 (needs benchmark output to populate baseline numbers)
- **Complexity:** Small
- **Notes:** Can be done in parallel with Tasks 5-8 since it requires running benchmarks to get actual numbers. Baseline numbers should be placeholders if actual runs aren't available at writing time.

---

## Verification Run (post-all-tasks)
- **Description:** Run `cargo bench --workspace` to verify all benchmarks compile and execute.
- **Depends on:** Tasks 1-10 complete
- **Complexity:** Medium
- **Notes:** This is a verification step, not a separate implementation task.

---

## Dependency Graph (ordered)

```
[Task 1] ──────────────────────────────────────────────────────────┐
   │                                                              │
   ▼                                                              ▼
[Task 2]                                                       [Task 9]
   │                                                              │
   ▼                                                              │
[Task 3]                                                         │
   │                                                              │
   ▼                                                              │
[Task 4] ────┬────────────────┬────────────────┐                  │
   │          │                │                │                  │
   ▼          ▼                ▼                ▼                  │
[Task 5] [Task 6]        [Task 7]        [Task 8]                  │
   │          │                │                │                  │
   └──────────┴────────────────┴────────────────┘                  │
   │                                                              │
   ▼                                                              ▼
[Task 10]                                    [VERIFICATION RUN]
```
