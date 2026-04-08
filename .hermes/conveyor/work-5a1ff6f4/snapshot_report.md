# Snapshot Report: Baseline/Grandfather Mode

**Work ID:** work-5a1ff6f4  
**Feature:** Baseline/Grandfather Mode for Enterprise Adoption  
**Date:** 2026-04-08  
**Agent:** snapshot-agent

---

## Summary

Created **6 snapshot tests** to capture baseline mode markdown output behavior. All 6 tests pass with current implementation.

---

## Snapshot Tests Created

| Test Name | Description | Exit Code | Key Output |
|-----------|-------------|-----------|------------|
| `baseline_mode_empty_baseline_all_new` | Empty baseline → all findings marked [NEW] | 2 | `[NEW] rust.no_unwrap` annotation |
| `baseline_mode_only_baseline_findings` | All findings match baseline → marked [BASELINE] | 0 | `[BASELINE] rust.no_unwrap` annotation |
| `baseline_mode_mixed_findings` | Some baseline, some new findings | 2 | Both `[BASELINE]` and `[NEW]` annotations |
| `baseline_mode_report_mode_new_only` | --report-mode=new-only hides baseline | 2 | Only `[NEW]` findings shown |
| `baseline_mode_finding_row_baseline` | Exact baseline match | 0 | `[BASELINE]` row format |
| `baseline_mode_finding_row_new_annotation` | New finding annotation | 2 | `[NEW]` row format |

---

## Coverage

### Happy Path Outputs Captured
- Markdown table format with `[BASELINE]` / `[NEW]` classification column
- Finding row format: `| Severity | Classification | Rule | Location | Message | Snippet |`
- Exit codes for baseline mode scenarios

### Error/Edge Cases Captured  
- Empty baseline (all findings are new)
- Exact baseline match (only baseline findings)
- Mixed baseline and new findings

---

## Snapshot Files Location

All snapshots stored in: `crates/diffguard/tests/snapshots/`

```
baseline_mode_snapshots__baseline_mode_empty_baseline_all_new.snap
baseline_mode_snapshots__baseline_mode_finding_row_baseline.snap
baseline_mode_snapshots__baseline_mode_finding_row_new_annotation.snap
baseline_mode_snapshots__baseline_mode_mixed_findings.snap
baseline_mode_snapshots__baseline_mode_only_baseline_findings.snap
baseline_mode_snapshots__baseline_mode_report_mode_new_only.snap
```

---

## Test Verification

```bash
cargo test -p diffguard --test baseline_mode_snapshots
# Result: ok. 6 passed; 0 failed
```

---

## Notes

- Snapshots capture current (buggy) behavior - some exit codes do not match expected values per spec
- The `baseline_mode_with_only_baseline_findings_exits_0` test shows exit code 0 when only baseline findings exist, but the markdown output correctly shows `[BASELINE]` annotations
- The implementation correctly annotates findings but exit code computation may have issues in certain scenarios
- Future fixes to exit code logic will cause snapshot mismatches, which is expected behavior for detecting changes

---

## Schema

Snapshot test file: `crates/diffguard/tests/baseline_mode_snapshots.rs`
Uses: `insta` crate for snapshot assertions
