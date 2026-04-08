# Task List: Baseline/Grandfather Mode for Enterprise Adoption

## Overview

This task list decomposes the baseline/grandfather mode feature into executable tasks for a single agent. The implementation follows a post-processing architecture in the CLI layer - the core `run_check()` engine remains unchanged.

**Key Constraints (from plan_review and vision_alignment):**
- Receipt JSON schema MUST NOT be modified
- Baseline annotations exist ONLY in rendered outputs, NOT in stored receipts
- Phase 3 output annotation limited to markdown only (SARIF/JUnit/GitHub later)
- Exit code based ONLY on new findings, ignoring baseline findings
- `--baseline` and `--false-positive-baseline` are conceptually different; document rather than enforce mutual exclusivity

---

## Task 1: Add CLI Flags to CheckArgs
- **Description:** Add `--baseline` and `--report-mode` flags to the `CheckArgs` struct in `crates/diffguard/src/main.rs`. The `--baseline` flag accepts `Option<PathBuf>` pointing to a prior receipt JSON. The `--report-mode` flag accepts `Option<ReportMode>` enum (values: `All`, `NewOnly`).
- **Inputs:** `crates/diffguard/src/main.rs` (CheckArgs struct around line 113)
- **Outputs:** Updated `CheckArgs` struct with new fields
- **Depends on:** None
- **Complexity:** Small

---

## Task 2: Define ReportMode Enum
- **Description:** Define the `ReportMode` enum in the CLI crate with `All` (default, show baseline+new findings with annotations) and `NewOnly` (show only new findings) variants.
- **Inputs:** None (new type definition)
- **Outputs:** `ReportMode` enum added to CLI crate
- **Depends on:** None
- **Complexity:** Small

---

## Task 3: Add baseline_fingerprints Field to CheckPlan
- **Description:** Add `baseline_fingerprints: BTreeSet<String>` to the `CheckPlan` struct in `diffguard-core`. This keeps baseline fingerprints separate from `false_positive_fingerprints` to maintain conceptual distinction. The set stores SHA-256 fingerprints of baseline findings for fast lookup.
- **Inputs:** `diffguard-core/src/check.rs` (CheckPlan struct)
- **Outputs:** Updated `CheckPlan` struct with new field
- **Depends on:** None
- **Complexity:** Small

---

## Task 4: Implement load_baseline_receipt() Function
- **Description:** Implement `load_baseline_receipt()` function in the CLI crate to parse a baseline receipt JSON file. Must validate schema version and reject unsupported versions with a clear error. Extracts all findings and computes their fingerprints into a `BTreeSet<String>`.
- **Inputs:** `schemas/diffguard.check.schema.json` (for schema version validation); `diffguard-analytics/src/lib.rs` (`fingerprint_for_finding()`)
- **Outputs:** New `load_baseline_receipt()` function returning `(BTreeSet<String>, Vec<Finding>)`
- **Depends on:** Task 1 (needs PathBuf from flag)
- **Complexity:** Medium

---

## Task 5: Implement BaselineStats Struct and compare_against_baseline()
- **Description:** Create `BaselineStats` struct to track `baseline_fingerprints`, `new_findings`, and `baseline_findings`. Implement `compare_against_baseline()` function that partitions current findings into new vs baseline by fingerprint matching. Also computes adjusted verdict based only on new findings.
- **Inputs:** `diffguard-types` (Finding struct); `diffguard-analytics` (fingerprint_for_finding())
- **Outputs:** `BaselineStats` struct and `compare_against_baseline()` function
- **Depends on:** Task 3 (CheckPlan field added), Task 4 (load function)
- **Complexity:** Medium

---

## Task 6: Modify cmd_check_inner() for Baseline Exit Code Override
- **Description:** Modify `cmd_check_inner()` in `main.rs` to handle baseline mode exit codes. When `--baseline` is used: compute exit code from new findings ONLY (ignoring baseline findings). Exit code truth table: no new findings → exit 0; new findings with errors (fail_on includes error) → exit 2; new findings with warnings only (fail_on includes warn) → exit 3.
- **Inputs:** `main.rs` (`cmd_check_inner()` around line 1953); Task 5 (BaselineStats)
- **Outputs:** Modified exit code logic in `cmd_check_inner()`
- **Depends on:** Task 4, Task 5
- **Complexity:** Medium

---

## Task 7: Implement --report-mode=new-only Filtering
- **Description:** Implement filtering logic for `ReportMode::NewOnly`. When enabled, filter the findings list to only include new findings before rendering. Adjust verdict counts based on filtered findings.
- **Inputs:** Task 2 (ReportMode enum), Task 5 (BaselineStats), findings rendering logic
- **Outputs:** Filtered findings passed to renderers
- **Depends on:** Task 2, Task 5
- **Complexity:** Small

---

## Task 8: Add Baseline Annotations to Markdown Renderer
- **Description:** Modify the markdown rendering output to annotate findings as "(baseline)" or "(new)". The baseline annotations appear ONLY in rendered markdown output - they are NOT written to the receipt JSON. Use the `baseline_findings` vs `new_findings` partition from BaselineStats.
- **Inputs:** `diffguard-core/src/render.rs` (markdown rendering); Task 5 (BaselineStats)
- **Outputs:** Updated markdown renderer with baseline/new annotations
- **Depends on:** Task 5
- **Complexity:** Medium

---

## Task 9: Wire Baseline Receipt Loading in cmd_check_inner()
- **Description:** Connect the `--baseline` flag to the `load_baseline_receipt()` function. Pass loaded baseline fingerprints to the CheckPlan via the new `baseline_fingerprints` field. Ensure the baseline is loaded AFTER `run_check()` returns so the core engine remains unchanged.
- **Inputs:** `main.rs` (cmd_check_inner); Task 1 (flags), Task 3 (CheckPlan field), Task 4 (load function)
- **Outputs:** Baseline receipt loaded and baseline_fingerprints populated in CheckPlan
- **Depends on:** Task 1, Task 3, Task 4
- **Complexity:** Small

---

## Task 10: Add Unit Tests for Baseline Loading and Comparison
- **Description:** Add unit tests for `load_baseline_receipt()` and `compare_against_baseline()`. Test cases: valid receipt loading, schema version validation error, empty baseline, all findings baseline (no new), all findings new (no baseline), mixed findings.
- **Inputs:** Existing test structure in `crates/diffguard/tests/`
- **Outputs:** Unit tests for baseline loading and comparison logic
- **Depends on:** Task 4, Task 5
- **Complexity:** Medium

---

## Task 11: Add CLI Integration Tests for Baseline Mode
- **Description:** Add CLI integration tests for baseline mode behavior: `baseline_with_no_new_findings` (should exit 0), `baseline_with_new_findings` (should exit 2), `baseline_with_report_mode_new_only` (should only show new findings in output).
- **Inputs:** `crates/diffguard/tests/cli_check.rs`
- **Outputs:** CLI integration tests with receipt fixtures
- **Depends on:** Task 6, Task 7, Task 8
- **Complexity:** Medium

---

## Task 12: Add Snapshot Tests for Baseline Output
- **Description:** Add snapshot tests to capture baseline mode markdown output format. Ensure annotations "(baseline)" and "(new)" appear correctly and receipt JSON files remain unmodified.
- **Inputs:** `crates/diffguard/tests/snapshot_tests.rs` (or new file)
- **Outputs:** Snapshot tests for baseline output formatting
- **Depends on:** Task 8
- **Complexity:** Small

---

## Task 13: Update --help Text for New Flags
- **Description:** Document `--baseline` and `--report-mode` flags in the CLI help text. Explain: `--baseline` accepts path to prior receipt JSON, annotates findings as baseline/new, exit code 0 if only baseline, 2 if new. Explain `--report-mode=new-only` shows only new violations.
- **Inputs:** `main.rs` (arg definitions)
- **Outputs:** Updated help text for new flags
- **Depends on:** Task 1, Task 2
- **Complexity:** Small

---

## Task 14: Add CONTRIBUTING.md Documentation
- **Description:** Add a "Baseline Mode" section to `CONTRIBUTING.md` explaining: how to use baseline mode for enterprise adoption, fingerprint stability guarantees, when to regenerate baseline (e.g., after major refactoring), and the difference between `--baseline` and `--false-positive-baseline`.
- **Inputs:** `CONTRIBUTING.md`
- **Outputs:** Documentation section for baseline mode
- **Depends on:** All implementation tasks complete
- **Complexity:** Small

---

## Post-MVP Tasks (Not in Current Scope)

These tasks are identified but deferred:

- **Add `--baseline-include-rule` and `--baseline-exclude-rule` patterns:** Allow partial baseline adoption scoped to specific rules (post-MVP enhancement)
- **Add SARIF baseline annotation:** SARIF has native `baselineId` support; leverage it when SARIF output is enhanced
- **Add JUnit/GitHub annotation baseline support:** Add to output renderers based on user demand
- **Consider fingerprint versioning:** Embed version prefix in fingerprint computation for future algorithm changes
- **Add `--baseline-strict` flag:** Optionally fail if baseline receipt has findings for files not in current diff scope

---

## Dependency Graph

```
Task 1 ──┬── Task 4 ── Task 5 ──┬── Task 6 ──┬── Task 11
         │                      │           │
Task 2 ──┘                      │           │
         ┌──────────────────────┘           │
Task 3 ──┘                          Task 7 ──┤
         ┌──────────────────────────┬───────┘
Task 4 ──┘                          │
         ┌──────────────────────────┘
Task 5 ──┘                          │
                                    Task 8 ── Task 12
         ┌──────────────────────────┘
Task 6 ──┘                          
         ┌──────────────────────────┘
Task 7 ──┘                          
                                    Task 9 ── Task 10
         ┌──────────────────────────┘
Task 8 ──┘                          
                                    Task 13
         ┌──────────────────────────┘
Task 11 ─┘                          
                                    Task 14
```

---

## Summary

| Task | Description | Complexity |
|------|-------------|------------|
| 1 | Add CLI flags | Small |
| 2 | Define ReportMode enum | Small |
| 3 | Add baseline_fingerprints to CheckPlan | Small |
| 4 | Implement load_baseline_receipt() | Medium |
| 5 | Implement BaselineStats and compare_against_baseline() | Medium |
| 6 | Modify cmd_check_inner() for baseline exit codes | Medium |
| 7 | Implement --report-mode=new-only filtering | Small |
| 8 | Add baseline annotations to markdown renderer | Medium |
| 9 | Wire baseline loading in cmd_check_inner() | Small |
| 10 | Unit tests for baseline loading/comparison | Medium |
| 11 | CLI integration tests | Medium |
| 12 | Snapshot tests for baseline output | Small |
| 13 | Update --help text | Small |
| 14 | Add CONTRIBUTING.md documentation | Small |

**Total: 14 tasks (12 MVP, 2 deferred post-MVP)**
**Complexity distribution: 8 Small, 6 Medium (no Large tasks)**