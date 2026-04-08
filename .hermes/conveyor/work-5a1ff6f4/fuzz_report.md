# Fuzz Report: Baseline Mode (work-5a1ff6f4)

**Date:** 2026-04-08
**Fuzz Target:** `baseline_receipt`
**Iterations:** ~1M+ (ran with max_total_time=30s)
**Tool:** libFuzzer

---

## Fuzz Target: `baseline_receipt`

### Purpose
Fuzz testing for the baseline/grandfather mode feature (--baseline CLI flag) introduced in work-5a1ff6f4.

### What Was Tested
1. **CheckReceipt JSON parsing** - Valid and malformed JSON inputs
2. **Schema version validation** - Compatibility checking against CHECK_SCHEMA_V1
3. **Finding fingerprint computation** - SHA-256 of `rule_id:path:line:match_text`
4. **Baseline from receipt** - Converting CheckReceipt to FalsePositiveBaseline
5. **Exit code computation** - Baseline mode exit code logic (0/2/3)
6. **Deduplication** - Duplicate findings with same fingerprint

### Input Generation
- **Structured fuzzing**: Arbitrary-based generation of StructuredReceipt with problematic values
- **Unstructured fuzzing**: Raw bytes as JSON

---

## Crashes Found

### Crash 1: Assertion Failure (Schema Version)
- **Type:** ASSERT failure (not a memory safety issue)
- **Input:** Raw bytes `\x92\x92\x92\x92\x54\x92\x92\x0b\x0a`
- **Description:** Fuzz target had incorrect expected value for baseline schema
  - Expected: `"diffguard.false_positive.v1"` (incorrect)
  - Actual: `"diffguard.false_positive_baseline.v1"` (correct)
- **Root Cause:** Fuzz target assertion was incorrect, not an implementation bug
- **Status:** Fixed - assertion corrected to use correct schema constant
- **Regression Test:** Added to corpus at `fuzz/corpus/baseline_receipt/crash-input`

### No Other Crashes
After fixing the assertion, no additional crashes or panics were found during fuzzing.

---

## Code Coverage
The fuzz target exercises these key functions:
- `serde_json::from_str::<CheckReceipt>()` - JSON parsing
- `fingerprint_for_finding()` - SHA-256 fingerprint computation  
- `baseline_from_receipt()` - Baseline creation
- `normalize_false_positive_baseline()` - Deduplication

---

## Files Created

### New Fuzz Target
- `fuzz/fuzz_targets/baseline_receipt.rs` - Fuzz target for baseline receipt parsing

### Modified Files
- `fuzz/Cargo.toml` - Added `baseline_receipt` binary and dependencies (serde_json, diffguard-analytics)

### Crash Corpus
- `fuzz/corpus/baseline_receipt/crash-input` - Regression test input

---

## Summary

| Metric | Value |
|--------|-------|
| Fuzz targets written | 1 |
| Fuzz iterations | ~1M+ |
| Crashes found | 1 (assertion error - fixed) |
| Memory safety issues | 0 |
| Regression tests added | 1 |

**Result:** No crashes in the implementation itself. The single "crash" was due to an incorrect assertion in the fuzz target itself (wrong schema version expected). This has been fixed and the crash input saved as a regression test.