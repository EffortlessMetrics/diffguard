# Test Coverage Review: Performance Benchmark Infrastructure

**Work Item:** work-9e77f361  
**Reviewer Role:** test-reviewer  
**Date:** 2026-04-07  
**Artifact:** test_coverage_review.md

---

## Sufficiency Assessment

**Status:** INSUFFICIENT

The benchmark code exists structurally but **does not compile**. All 4 benchmark files and fixtures.rs contain API calls that don't match the actual crate interfaces. Before any test can run, critical API mismatches must be fixed.

---

## Compilation Status

```bash
$ cargo check -p diffguard-bench --benches 2>&1
error: could not compile `diffguard-bench` (lib) due to 8 previous errors
```

The `lib.rs` depends on `fixtures.rs` which uses workspace crates as dependencies. The Cargo.toml correctly declares them under `[dev-dependencies]`, but the imports in `fixtures.rs` use external crate paths that the lib cannot resolve.

---

## Critical API Mismatches

### 1. fixtures.rs: Import failures (E0432/E0433)
- `use diffguard_diff::ChangeKind;` — module not found
- `use diffguard_diff::DiffLine;` — module not found
- `use diffguard_domain::InputLine;` — module not found
- `use diffguard_types::Finding;` — module not found

**Root cause:** `fixtures.rs` is included via `pub mod fixtures;` in `lib.rs`. The lib cannot access dev-dependencies.

### 2. fixtures.rs: DiffMeta structure mismatch
```rust
// WRONG (used in fixtures.rs:206-208):
DiffMeta {
    before_sha: "abc123".to_string(),
    after_sha: "def456".to_string(),
    scope: "added".to_string(),
}

// CORRECT (actual API, crates/diffguard-types/src/lib.rs:113-120):
DiffMeta {
    base: String,
    head: String,
    context_lines: u32,
    scope: Scope,  // NOT a String
    files_scanned: u32,
    lines_scanned: u32,
}
```

### 3. fixtures.rs: ToolMeta structure mismatch
```rust
// WRONG (fixtures.rs:203):
ToolMeta {
    name: "diffguard".to_string(),
    version: "0.2.0".to_string(),
    homepage: Some("...".to_string()),  // homepage field doesn't exist
}

// CORRECT (crates/diffguard-types/src/lib.rs:110-112):
ToolMeta {
    name: String,
    version: String,
    // No homepage field
}
```

### 4. fixtures.rs: VerdictCounts missing field
```rust
// WRONG (fixtures.rs:213):
VerdictCounts {
    info: 0,
    warn: 0,
    error: 0,
    // MISSING: suppressed: u32
}

// CORRECT (crates/diffguard-types/src/lib.rs:149-158):
VerdictCounts {
    info: u32,
    warn: u32,
    error: u32,
    suppressed: u32,  // Required, has serde(skip_serializing_if) but still required at construction
}
```

### 5. fixtures.rs:115 - Type inference failure
```rust
// Line 115:
diff_lines.iter().map(|dl| convert_diff_line_to_input_line(dl.clone())).collect()
//                    ^^ -- type must be known at this point
```
Needs explicit type annotation: `|dl: &DiffLine|`

---

## Missing Test Coverage by Acceptance Criterion

### AC-2: Parsing Benchmarks
**Coverage:** Partial  
**Issues:**
- Benchmark file exists at `bench/benches/parsing.rs` ✓
- Tests sizes 0, 100, 1K, 10K, 100K ✓  
- BUT `generate_unified_diff()` lives in `fixtures.rs` which doesn't compile ✗

### AC-3: Evaluation Benchmarks
**Coverage:** Partial  
**Issues:**
- Benchmark file exists at `bench/benches/evaluation.rs` ✓
- Tests rule counts 0, 1, 10, 100, 500 ✓
- BUT `compile_benchmark_rules()` uses `RuleConfig` fields that may not match actual API ✗
- `DiffLine → InputLine` conversion helper exists but type-checks incorrectly ✗

### AC-4: Rendering Benchmarks
**Coverage:** Partial  
**Issues:**
- Benchmark file exists at `bench/benches/rendering.rs` ✓
- Tests finding counts 0, 10, 100, 1000 ✓
- Tests both Markdown and SARIF renderers ✓
- BUT `generate_receipt()` uses `ToolMeta` and `DiffMeta` fields that don't exist ✗
- `VerdictCounts` missing `suppressed` field ✗

### AC-5: Preprocessing Benchmarks
**Coverage:** Partial  
**Issues:**
- Benchmark file exists at `bench/benches/preprocessing.rs` ✓
- Tests 4 densities (0%, 25%, 50%, 75%) ✓
- Tests 3 languages (Rust, Python, JavaScript) ✓
- State management documented ✓
- BUT `fixtures.rs` doesn't compile, so `generate_lines_with_comment_density()` unavailable ✗

### AC-6: Fixture Generation
**Coverage:** INSUFFICIENT  
- `fixtures.rs` exists but doesn't compile ✗
- `convert_diff_line_to_input_line()` exists but type-checks incorrectly ✗
- All generators are in a file that cannot be compiled ✗

### AC-7: CI Integration
**Coverage:** NOT REVIEWABLE (CI config not in red_tests directory)  
- CI workflow changes are not part of the benchmark code review

### AC-8: Documentation
**Coverage:** NOT REVIEWABLE  
- README changes are not part of the benchmark code review

### AC-9: Domain Crate Invariants
**Coverage:** NOT VERIFIABLE (code doesn't compile)  
- Cannot verify no `std::fs`/`std::process`/`std::env` usage when code won't compile

---

## Structural Observations

### Strengths
1. **Benchmark organization is correct** — 4 separate bench files, criterion pattern followed
2. **Size/density matrices are appropriate** — covers spec ranges
3. **State management documented** — preprocessor reset behavior described
4. **Both renderer types tested** — Markdown and SARIF both present
5. **Zero-input baselines included** — 0 rules, 0 lines, 0 findings all tested

### Critical Gaps
1. **All imports fail** — lib cannot resolve workspace crate imports
2. **API shapes don't match** — ToolMeta, DiffMeta, VerdictCounts all wrong
3. **Type inference broken** — closure type annotation missing
4. **Code non-functional** — no benchmark can run in current state

---

## Required Fixes (for implementer)

These are issues in the test code that must be resolved before tests can run:

| File | Issue | Fix |
|------|-------|-----|
| `bench/Cargo.toml` | `lib.rs` exposes `fixtures` but lib can't link dev-deps | Move fixtures to a bench-only module OR add crates as regular deps |
| `bench/fixtures.rs:12-14` | Cannot import workspace crates from lib | Fix dependency graph or move fixtures |
| `bench/fixtures.rs:203` | `ToolMeta` has no `homepage` field | Remove `homepage` field |
| `bench/fixtures.rs:206-208` | `DiffMeta` uses wrong fields | Use `base`, `head`, `scope: Scope::Added`, etc. |
| `bench/fixtures.rs:213` | `VerdictCounts` missing `suppressed` | Add `suppressed: 0` |
| `bench/fixtures.rs:115` | Type inference failure | Add `|dl: &DiffLine|` annotation |

---

## Conclusion

The benchmark **structure** is sound — correct frameworks, correct size matrices, correct categories. However, the code **cannot compile** due to fundamental API mismatches and dependency linking issues. 

As test-reviewer, I cannot verify that tests fail as expected (or pass, or measure anything) because the tests cannot be executed. The red tests are **insufficient** — they represent the right test shape but are non-functional.

**Recommendation:** Return to red-test-builder with these API mismatch issues documented. The test code needs corrections to API usage before it can serve as a verification mechanism.
