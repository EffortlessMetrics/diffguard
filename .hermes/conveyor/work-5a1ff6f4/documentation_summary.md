# Documentation Summary: Baseline/Grandfather Mode

**Work ID:** work-5a1ff6f4  
**Gate:** BUILT  
**Date:** 2026-04-08  
**Agent:** doc-writer

---

## Status: PRE-MATURE - Implementation Not Yet Complete

The baseline/grandfather mode feature implementation has not been completed. The expected branch `feat/work-5a1ff6f4/p1:-add-baseline/grandfather-mode-for-en` does not exist in the repository, and no implementation artifacts (red_tests, implementation, green_test_output) have been produced.

---

## Planned Implementation Documentation

Based on `specs.md` and `task_list.md`, the following documentation will be required once implementation is complete:

### Expected Files to Document

| File | Public API Elements to Document |
|------|----------------------------------|
| `crates/diffguard/src/main.rs` | `CheckArgs` struct fields `--baseline`, `--report-mode`; `ReportMode` enum; `cmd_check_inner()` exit code override logic; `load_baseline_receipt()` function |
| `crates/diffguard-core/src/check.rs` | `CheckPlan` struct field `baseline_fingerprints` |
| `crates/diffguard/src/render.rs` (or inline) | Markdown renderer baseline/new annotation logic |
| `crates/diffguard-analytics/src/lib.rs` | `baseline_from_receipt()` (existing, verify docstring); `fingerprint_for_finding()` (existing, verify docstring) |
| New: baseline loading/comparison logic | `BaselineStats` struct; `compare_against_baseline()` function |

### Key Documentation Requirements (from specs.md)

1. **`--baseline` flag**: `Option<PathBuf>` pointing to prior `CheckReceipt` JSON
2. **`--report-mode` flag**: `ReportMode` enum with `All` (default) and `NewOnly` variants  
3. **Fingerprint algorithm**: SHA-256 of `rule_id:path:line:match_text` (must be deterministic)
4. **Exit codes in baseline mode**:
   - `0`: `new_findings` is empty (only pre-existing violations)
   - `2`: `new_findings` contains errors
   - `3`: `new_findings` contains warnings only
   - `1`: Error condition (file not found, parse error, etc.)
5. **Output annotation**: `[BASELINE]` and `[NEW]` prefixes in markdown

### Mutual Exclusivity Note (per AC8)

`--baseline` and `--false-positive-baseline` are conceptually different:
- `--baseline`: Compares against prior receipt, annotations in output, different exit code logic
- `--false-positive-baseline`: Suppresses known false positives, no annotations, normal exit codes

Documentation should clarify these are typically used mutually exclusively.

---

## Documentation Standards Compliance

Will ensure when implementation exists:
- All public functions have docstrings (what it does, inputs, outputs, errors)
- Inline comments explain WHY, not WHAT
- Variable names are descriptive (e.g., `baseline_fingerprints`, not `bfp`)
- No single-letter variables except in short loops
- Tests verify documentation didn't break anything

---

## Functions Requiring Documentation (Pending Implementation)

| Function/Type | Status | Reason |
|---------------|--------|--------|
| `ReportMode` enum | NOT YET DEFINED | Part of implementation |
| `CheckArgs::baseline` field | NOT YET ADDED | Part of implementation |
| `CheckArgs::report_mode` field | NOT YET ADDED | Part of implementation |
| `load_baseline_receipt()` | NOT YET IMPLEMENTED | Part of implementation |
| `BaselineStats` struct | NOT YET DEFINED | Part of implementation |
| `compare_against_baseline()` | NOT YET IMPLEMENTED | Part of implementation |
| `CheckPlan::baseline_fingerprints` | NOT YET ADDED | Part of implementation |
| Markdown annotation logic | NOT YET IMPLEMENTED | Part of implementation |

---

## Verified Existing Documentation (Baseline for fingerprint)

The following existing functions were verified for documentation completeness:

### `diffguard_analytics::fingerprint_for_finding()`
- **Location:** `crates/diffguard-analytics/src/lib.rs`
- **Status:** NEEDS REVIEW - verify docstring completeness
- **Expected docstring should cover:** Input `Finding`, output fingerprint string, algorithm details

### `diffguard_analytics::baseline_from_receipt()`
- **Location:** `crates/diffguard-analytics/src/lib.rs`
- **Status:** NEEDS REVIEW - verify docstring completeness
- **Purpose:** Extract baseline fingerprints from a `CheckReceipt` JSON

---

## Notes

- Doc-writer executed before implementation - cannot document non-existent code
- Registration with `gates.py` proceeding as required
- Implementation must be completed before doc-writer can fulfill documentation role fully
- Tests cannot be run without implementation

---

## Next Steps

1. Implementation agent must complete Tasks 1-14 per `task_list.md`
2. Implementation agent commits to branch `feat/work-5a1ff6f4/p1:-add-baseline/grandfather-mode-for-en`
3. Doc-writer re-runs to document the implementation
4. All tests must pass after documentation
