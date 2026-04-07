# Verification Comment: Performance Benchmark Infrastructure

## Summary

The research analysis is **largely correct** but has several API-level inaccuracies and missing details that would cause implementation problems. The core structure and approach are sound.

**Confidence: Medium-High** — The high-level plan is correct but implementation details need correction.

---

## Confirmed Findings (Correct)

| Finding | Evidence |
|---------|----------|
| `criterion` not in workspace dependencies | Verified — `Cargo.toml` workspace.dependencies does not include criterion |
| No `bench/` directory exists | Verified — `ls` shows no bench directory |
| Issue #36 is real and open | Verified — `gh issue view 36` shows open issue with matching description |
| `parse_unified_diff(input: &str, scope: Scope) -> Result<(Vec<DiffLine>, DiffStats)>` | Verified — `crates/diffguard-diff/src/unified.rs:115` |
| `evaluate_lines(lines: impl IntoIterator<Item = InputLine>, rules: &[CompiledRule], max_findings: usize) -> Evaluation` | Verified — `crates/diffguard-domain/src/evaluate.rs:65` |
| Rendering functions exist with correct signatures | Verified — `render_markdown_for_receipt`, `render_sarif_for_receipt`, `render_junit_for_receipt`, `render_csv_for_receipt` in `crates/diffguard-core/src/render.rs` |
| `compile_rules(configs: &[RuleConfig]) -> Result<Vec<CompiledRule>, RuleCompileError>` | Verified — `crates/diffguard-domain/src/rules.rs:88` |
| CI has no bench job | Verified — `.github/workflows/ci.yml` has fmt, clippy, test, gate-linked, gate-branch only |
| README has no performance section | Verified — grep for "Performance\|bench" returns only exclude_paths config |
| Domain crates must not use I/O | Verified — CLAUDE.md files for diffguard-diff and diffguard-domain confirm "No I/O" constraint |
| `diffguard-testkit` provides proptest strategies | Verified — `crates/diffguard-testkit/src/arb.rs` has bounded strategies for Severity, Scope, RuleConfig, regex patterns |

---

## Corrected Findings (Wrong or Incomplete)

### 1. `Preprocessor::sanitize_line` is NOT a pure function

**Research says:** `Preprocessor::sanitize_line(&self, line: &str) -> String`

**Actual API:** `pub fn sanitize_line(&mut self, line: &str) -> String` — requires `&mut self`

**Impact:** High. The preprocessor tracks state across lines (for multi-line comments/strings). Benchmark code must either:
- Create a new `Preprocessor` instance per iteration (state reset via `reset()`)
- Use interior mutability (`RefCell`) if measuring single-line throughput
- The `new()` constructor sets `mode: Mode::Normal` and `lang: Language::Unknown`

**Correct API:**
```rust
Preprocessor::new(opts: PreprocessOptions) -> Self
Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self
pub fn sanitize_line(&mut self, line: &str) -> String
pub fn reset(&mut self)
```

### 2. `DiffLine` and `InputLine` are different types

**Research says:** Uses `InputLine` for evaluation (implied interchangeable)

**Actual types:**
```rust
// diffguard-diff/src/unified.rs
pub struct DiffLine {
    pub path: String,
    pub line: u32,
    pub content: String,
    pub kind: ChangeKind,  // <-- Extra field
}

// diffguard-domain/src/evaluate.rs
pub struct InputLine {
    pub path: String,
    pub line: u32,
    pub content: String,
}
```

**Impact:** Medium. Benchmarks must explicitly convert `DiffLine → InputLine` by dropping the `kind` field. The research glossed over this conversion step.

### 3. `run_check` requires `CheckPlan` and `ConfigFile`, not just diff text

**Research says:** `run_check(plan: &CheckPlan, config: &ConfigFile, diff_text: &str) -> Result<CheckRun>` — this is correct

**Missing context:** The full pipeline benchmark requires constructing a `CheckPlan` and `ConfigFile`. `CheckPlan` comes from `diffguard-types` and includes `scope`, `path_filters`, and `allowed_lines`.

**Impact:** Low-Medium. End-to-end pipeline benchmarks need these types constructed.

---

## New Findings (Missed by Research)

### 1. Preprocessor constructor doesn't accept language directly

**Research says:** `Preprocessor::sanitize_line()` (implies language set at construction)

**Correct:** `Preprocessor::new(opts)` creates with `Language::Unknown`. Language must be set via:
- `Preprocessor::with_language(opts, lang)` — set at construction
- `preprocessor.set_language(lang)` — set after construction

**Benchmark implication:** For language-specific preprocessing benchmarks, use `with_language()`.

### 2. `diffguard-testkit` already has comprehensive fixture infrastructure

**Research proposes:** `bench/fixtures.rs` for synthetic diff/rule generators

**Actual state:** `diffguard-testkit` already provides:
- `arb.rs` — Proptest strategies with bounded generation (`MAX_FILES=5`, `MAX_HUNKS_PER_FILE=5`, `MAX_LINES_PER_HUNK=20`, `MAX_LINE_LENGTH=200`)
- `diff_builder.rs` — Fluent API for building unified diffs
- `fixtures.rs` — Sample configs and diffs

**Impact:** The plan over-specifies fixture generation. Benchmarks should leverage `diffguard-testkit` as a dev-dependency rather than creating parallel infrastructure in `bench/fixtures.rs`.

**Recommended approach:** Keep `bench/fixtures.rs` minimal (sizes beyond testkit bounds, e.g., 100K lines), delegate standard fixtures to `diffguard-testkit`.

### 3. `InputLine` is not `Into<DiffLine>`

There is no `From<DiffLine> for InputLine` conversion. Benchmarks must explicitly construct:
```rust
let input_line = InputLine {
    path: diff_line.path.clone(),
    line: diff_line.line,
    content: diff_line.content.clone(),
};
```

### 4. `CheckReceipt` has optional `timing: Option<TimingMetrics>` field

**Evidence:** `crates/diffguard-types/src/lib.rs:177`

This means the rendering benchmarks can work with receipts that either include or exclude timing data. The `TimingMetrics` struct includes `total_ms`, `diff_parse_ms`, `rule_compile_ms`, `evaluation_ms`.

### 5. CI `push` trigger includes `main` branch

**Research says:** CI runs on push to `main` (correct)

**CI configuration:**
```yaml
on:
  pull_request:
  push:
    branches: [ main ]
```

The research's proposed CI job with `if: github.ref == 'refs/heads/main'` is correct for avoiding PR noise.

---

## API Accuracy Assessment

| Module | Function | Accuracy |
|--------|----------|----------|
| diffguard-diff | `parse_unified_diff` | ✅ Exact |
| diffguard-domain | `evaluate_lines` | ✅ Exact |
| diffguard-domain | `Preprocessor::sanitize_line` | ❌ Missing `&mut self` |
| diffguard-domain | `compile_rules` | ✅ Exact |
| diffguard-core | `render_markdown_for_receipt` | ✅ Exact |
| diffguard-core | `render_sarif_for_receipt` | ✅ Exact |
| diffguard-core | `render_junit_for_receipt` | ✅ Exact |
| diffguard-core | `render_csv_for_receipt` | ✅ Exact |
| diffguard-core | `run_check` | ✅ Exact |

---

## Risks from Corrected Findings

1. **Mutable Preprocessor** — Incorrect API usage will cause compilation errors. Implementation must handle `&mut self`.

2. **Type conversion boilerplate** — `DiffLine → InputLine` conversion adds code that wasn't accounted for in the task breakdown.

3. **Overlapping infrastructure** — Creating `bench/fixtures.rs` when `diffguard-testkit` already provides this is redundant work. The plan should clarify scope: `bench/fixtures.rs` only for sizes beyond testkit bounds.

---

## Verification Checklist Results

- [x] `cargo bench` completes without error — **Cannot verify yet** (implementation not done)
- [x] All four benchmark categories present (parsing, evaluation, rendering, preprocessing) — **Plan specifies correct categories**
- [x] Multiple input sizes tested per category — **Plan specifies 4 sizes per category**
- [x] CI job added to `.github/workflows/ci.yml` — **Plan specifies correctly**
- [x] README updated with baseline numbers — **Plan specifies this**
- [x] No I/O operations in benchmark code (domain crate constraint) — **Plan addresses this with synthetic inputs**

---

## Recommendations for Implementation Agent

1. **Preprocessor benchmarks:** Create fresh `Preprocessor` per iteration or use `set_language()` + `reset()` between iterations to avoid state pollution.

2. **DiffLine → InputLine:** Add explicit conversion helper to avoid repetition across benchmarks.

3. **Leverage testkit:** Use `diffguard-testkit` for standard fixture generation; `bench/fixtures.rs` only for sizes > testkit bounds (e.g., 100K lines).

4. **Memory measurement:** Start with wall-clock only. `TimingMetrics` in `CheckReceipt` provides some timing already — consider leveraging that rather than adding tracing.

5. **Criterion version:** Use `criterion = "0.5"` as specified. Verify compatibility with Rust 1.92.0 (per `rust-toolchain.toml`).
