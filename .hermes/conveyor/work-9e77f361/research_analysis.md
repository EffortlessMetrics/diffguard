# Research Analysis: Performance Benchmark Infrastructure

## Issue Summary

**Issue**: [#36 - P1: Add performance benchmark infrastructure](https://github.com/EffortlessMetrics/diffguard/issues/36)

Diffguard lacks benchmark infrastructure to prove or protect its "fast because diff-scoped" performance advantage. Currently:
- No criterion or benchmark framework exists
- Performance regressions go undetected
- Cannot evaluate diffguard's speed on real codebase sizes

**Acceptance Criteria**:
1. `cargo bench` runs from workspace root
2. Benchmarks cover parsing, evaluation, rendering
3. Results include timing and memory for representative sizes
4. README documents baseline performance numbers

---

## Relevant Codebase Areas

### 1. Diff Parsing (`diffguard-diff` crate)

**Key file**: `crates/diffguard-diff/src/unified.rs`

**Primary API**:
```rust
pub fn parse_unified_diff(
    diff_text: &str,
    scope: Scope,
) -> Result<(Vec<DiffLine>, DiffStats), DiffParseError>
```

**Key types**:
- `DiffLine { path, line, content, kind }` — single parsed line
- `DiffStats { files, lines }` — aggregate counts
- `ChangeKind` — Added, Changed, Deleted

**Parser characteristics**:
- Line-by-line iteration over diff text
- Hunk header parsing (`@@ -X,Y +X,Y @@`)
- Handles: binary files, submodules, renames, mode-only changes
- Returns scoped lines based on `Scope` parameter

### 2. Rule Evaluation (`diffguard-domain` crate)

**Key files**:
- `crates/diffguard-domain/src/evaluate.rs` — main evaluation engine
- `crates/diffguard-domain/src/rules.rs` — rule compilation
- `crates/diffguard-domain/src/preprocess.rs` — comment/string masking

**Primary API**:
```rust
pub fn evaluate_lines(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
) -> Evaluation
```

Returns `Evaluation` with findings, counts, and per-rule hit statistics.

**Preprocessing**:
```rust
Preprocessor::sanitize_line(&self, line: &str) -> String
```
Supports 11+ languages (Rust, Python, JS, TS, Go, Ruby, C, C++, C#, Java, Kotlin, Shell)

### 3. Rendering (`diffguard-core` crate)

**Key file**: `crates/diffguard-core/src/render.rs`

**Rendering functions**:
```rust
pub fn render_markdown_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_sarif_for_receipt(receipt: &CheckReceipt) -> SarifReport
pub fn render_junit_for_receipt(receipt: &CheckReceipt) -> String
pub fn render_csv_for_receipt(receipt: &CheckReceipt) -> String
```

### 4. Full Pipeline (`diffguard-core` crate)

**Key file**: `crates/diffguard-core/src/check.rs`

```rust
pub fn run_check(plan: &CheckPlan, config: &ConfigFile, diff_text: &str) -> Result<CheckRun>
```

This orchestrates: diff parsing → rule evaluation → output rendering.

---

## Dependencies & Constraints

### Existing Dependencies (from workspace Cargo.toml)
- `proptest = "1.10.0"` — already available for property-based testing
- `insta = "1.46.3"` — snapshot testing
- `tempfile = "3.25.0"` — test file generation

### Rust Toolchain
- Rust 1.92.0 (per `rust-toolchain.toml`)
- Edition 2024

### Key Constraints
1. **I/O-free domain crates** — `diffguard-diff`, `diffguard-domain`, `diffguard-types` must not use `std::fs`, `std::process`, or `std::env`
2. **Workspace structure** — benchmarks must run from workspace root
3. **Existing CI** — GitHub Actions (`.github/workflows/ci.yml`) already runs fmt, clippy, test

---

## Benchmark Categories (per issue)

### 1. Diff Parsing Benchmarks
- **Sizes**: 100 lines, 1K lines, 10K lines, 100K lines
- **Function**: `parse_unified_diff()`
- **Input**: Synthetically generated unified diff text

### 2. Rule Evaluation Benchmarks
- **Sizes**: 1 rule, 10 rules, 100 rules, 500 rules
- **Function**: `evaluate_lines()`
- **Input**: Pre-generated `InputLine` iterators + compiled rules

### 3. Output Rendering Benchmarks
- **Sizes**: Various finding counts (0, 10, 100, 1000 findings)
- **Functions**: `render_markdown_for_receipt()`, `render_sarif_for_receipt()`, etc.
- **Input**: `CheckReceipt` with pre-generated findings

### 4. Preprocessing Benchmarks
- **Sizes**: Files with different comment densities (0%, 25%, 50%, 75%)
- **Function**: `Preprocessor::sanitize_line()`
- **Input**: Representative code snippets per language

---

## Implementation Approach

### Framework: criterion (standard Rust)
- Use `criterion = "0.5"` with cargo bench
- Add to workspace dependencies
- Create `bench/` directory at workspace root

### Structure
```
bench/
├── benches/
│   ├── parsing.rs      # Diff parsing benchmarks
│   ├── evaluation.rs   # Rule evaluation benchmarks  
│   ├── rendering.rs    # Output rendering benchmarks
│   └── preprocessing.rs # Comment/string masking benchmarks
├── fixtures/
│   └── generate.rs     # Synthetic diff/rule generators
└── lib.rs              # Shared benchmark utilities
```

### CI Integration
- Add `bench` job to `.github/workflows/ci.yml`
- Run on push to `main` (not PRs to avoid noise)
- Use `criterion` CSV output + GitHub Actions artifact upload
- Track memory via `memory_stats()` or `tracing`

### Key Design Decisions
1. **Synthetic inputs** — No need for real repo diffs; use proptest-style generators
2. **Isolate benchmarks** — Each category separate to enable targeted runs
3. **Warmup + measurement** — criterion handles this; focus on realistic inputs
4. **Memory tracking** — Use `分配` (allocator) instrumentation or `tracing` spans

---

## What's Missing (for Implementation Agent)

1. **criterion dependency** not in workspace
2. **No bench/ directory** exists
3. **No benchmark tests** in CI
4. **No README section** for baseline numbers
5. **No memory measurement** infrastructure

## Verification Checklist (for Verification Agent)

- [ ] `cargo bench` completes without error
- [ ] All four benchmark categories present (parsing, evaluation, rendering, preprocessing)
- [ ] Multiple input sizes tested per category
- [ ] CI job added to `.github/workflows/ci.yml`
- [ ] README updated with baseline numbers
- [ ] No I/O operations in benchmark code (domain crate constraint)
