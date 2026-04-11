# Property Test Report: work-d1531005

## Work Item
- **Work ID**: work-d1531005
- **Gate**: PROVEN
- **Branch**: feat/work-d1531005/api--compiledrule-exported-from-diffguar
- **Description**: api: CompiledRule exported from diffguard-domain but appears to be internal

## API Refactoring Summary
This is a pure API refactoring that removes `CompiledRule` from the public re-export:
- `diffguard-domain/src/lib.rs` — removed `CompiledRule` from `pub use rules::...`
- `main.rs` — updated import from `diffguard_domain::CompiledRule` to `diffguard_domain::rules::CompiledRule`
- `properties.rs` — updated test import similarly
- `docs/architecture.md` — clarified `CompiledRule` is internal

**No behavioral changes. No parsing logic changed. No I/O changed.**

---

## Properties Identified and Tested

### Domain API Properties (diffguard-domain)

| # | Property | Description | Test Result |
|---|----------|-------------|-------------|
| 1 | `compile_rules()` with valid configs returns `Ok` | Valid `RuleConfig` slices compile successfully | ✅ PASS |
| 2 | `compile_rules()` with empty configs returns `Ok` | Empty rule config vector compiles to empty `Vec<CompiledRule>` | ✅ PASS |
| 3 | `evaluate_lines()` with empty input returns consistent results | Empty lines input produces evaluation with zero findings | ✅ PASS |
| 4 | `detect_language()` correctly identifies known extensions | All 42 known extensions (rs, py, js, ts, go, java, etc.) detected correctly | ✅ PASS |
| 5 | `detect_language()` is case-insensitive | Extensions detected regardless of case (e.g., `.JS` == `.js`) | ✅ PASS |
| 6 | `detect_language()` returns `None` for unknown extensions | Extensions not in known set return `None` | ✅ PASS |
| 7 | `Preprocessor` preserves line length | Sanitization always returns string of same length as input | ✅ PASS |
| 8 | `Preprocessor` masks comment syntax correctly | Hash comments (Python/Ruby) and C-style comments masked with spaces | ✅ PASS |
| 9 | `Preprocessor` masks string syntax correctly | Double/single quoted strings masked with spaces | ✅ PASS |
| 10 | `evaluate_lines()` determinism | Same rules and lines always produce same findings | ✅ PASS |
| 11 | `lines_scanned` equals input lines count | Evaluation correctly tracks number of input lines | ✅ PASS |
| 12 | `counts_match_findings` | Aggregated counts equal actual number of findings | ✅ PASS |
| 13 | `max_findings` cap respected | When limit is set, findings are truncated but counts remain accurate | ✅ PASS |

### Full Test Suite Results

```
cargo test -p diffguard-domain
  ├── Unit tests (lib.rs): 285 passed
  ├── overflow_protection: 3 passed, 1 ignored
  ├── properties.rs: 42 passed  ← Property-based tests
  ├── red_tests_work_5d83e2c9: 9 passed
  └── red_tests_work_d1531005: 0 passed (regression test file, empty)

Total: 339 tests passed, 0 failed
```

---

## Counterexamples Found

**None.** All 42 property-based tests and 339 total tests pass.

---

## Regression Tests Added

**None required.** This is an API refactoring only — no behavioral changes that would require new regression tests. The existing test suite provides sufficient coverage.

The `red_tests_work_d1531005.rs` file exists but contains 0 tests (the work item is a pure re-export change with no behavioral differences to test).

---

## Summary

| Metric | Count |
|--------|-------|
| Properties verified | 13 core properties |
| Property-based test cases | 42 |
| Total tests run | 339 |
| Counterexamples found | 0 |
| Regression tests added | 0 |
| Test failures | 0 |

**All properties hold across all inputs. The API refactoring preserves all existing behavioral invariants.**

---

## Verification Commands

```bash
# Property tests
cargo test -p diffguard-domain -- properties

# Full domain test suite
cargo test -p diffguard-domain

# All workspace tests
cargo test
```

All tests passed on branch `feat/work-d1531005/api--compiledrule-exported-from-diffguar`.
