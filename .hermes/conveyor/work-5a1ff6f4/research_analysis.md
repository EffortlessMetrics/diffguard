# Research Analysis: Baseline/Grandfather Mode for Enterprise Adoption

## Issue Summary

**GitHub Issue**: https://github.com/EffortlessMetrics/diffguard/issues/35

**Problem**: Diffguard has no baseline mode. Teams with existing codebases cannot adopt without immediately failing on all pre-existing violations. This is the #1 enterprise adoption blocker.

**Proposed Solution**: Add `--baseline` flag to the `check` command that:
1. Accepts path to a previous receipt JSON file
2. Compares findings against the baseline receipt fingerprint
3. Exit code 0 if only pre-existing violations found
4. Exit code 2 if NEW violations found (only new violations in output)
5. Optional `--report-mode=new-only` to ONLY report new findings

## Relevant Codebase Areas

### Key Files

| File | Purpose |
|------|---------|
| `crates/diffguard/src/main.rs` | CLI entry point, `CheckArgs` struct, `cmd_check_inner()` function |
| `crates/diffguard-core/src/check.rs` | `run_check()` function, `CheckPlan` struct, verdict computation |
| `crates/diffguard-core/src/fingerprint.rs` | `compute_fingerprint()` for findings |
| `crates/diffguard-analytics/src/lib.rs` | `baseline_from_receipt()`, `fingerprint_for_finding()`, `FalsePositiveBaseline` |
| `schemas/diffguard.check.schema.json` | `CheckReceipt` JSON schema with `findings` array |
| `schemas/diffguard.false-positive-baseline.v1.schema.json` | `FalsePositiveBaseline` schema |

### Existing Infrastructure (Can Be Reused)

1. **`fingerprint_for_finding()`** in `diffguard-analytics`:
   - Computes SHA-256 fingerprint of `rule_id:path:line:match_text`
   - Already deterministic and stable

2. **`baseline_from_receipt()`** in `diffguard-analytics`:
   - Converts a `CheckReceipt` to a `FalsePositiveBaseline`
   - Already exists but for false-positive use case

3. **`false_positive_fingerprint_set()`** in `diffguard-analytics`:
   - Returns a `BTreeSet<String>` of fingerprints for fast lookup
   - Can be reused for baseline fingerprint set

### Key Data Structures

**Finding** (from `diffguard-types`):
```rust
struct Finding {
    rule_id: String,
    severity: Severity,
    message: String,
    path: String,
    line: u32,
    column: Option<u32>,
    match_text: String,
    snippet: String,
    // NOTE: fingerprint is computed, not stored
}
```

**CheckReceipt** (from `diffguard-types`):
```rust
struct CheckReceipt {
    schema: String,
    tool: ToolMeta,
    diff: DiffMeta,
    findings: Vec<Finding>,
    verdict: Verdict,
    timing: Option<TimingMetrics>,
}
```

## Key Findings

### 1. Baseline Mode is Different from False-Positive Baseline

The existing `--false-positive-baseline` flag **suppresses** known false positives (they don't appear in output at all). The new `--baseline` flag is **grandfather mode** - it:

- Shows ALL findings (both pre-existing and new)
- Marks pre-existing ones differently in output
- Only fails the check if NEW violations are introduced
- Allows enterprises to adopt incrementally

### 2. Fingerprint Computation Location

The fingerprint is computed in `diffguard-core/src/fingerprint.rs` via `compute_fingerprint()`, which is called in `check.rs` during evaluation. The analytics crate has a separate `fingerprint_for_finding()` that uses the same algorithm.

### 3. Verdict Computation Flow

1. `cmd_check_inner()` loads config and builds `CheckPlan`
2. `run_check()` evaluates rules against diff and produces `CheckRun`
3. Findings with fingerprints in `false_positive_fingerprints` set are filtered out
4. Verdict is computed from remaining findings
5. Exit code is derived from verdict counts

### 4. Entry Point for New Flag

The `CheckArgs` struct in `main.rs` (around line 200) is where new CLI flags should be added. The flag would then need to be:
1. Parsed and passed through `CheckPlan`
2. Used in `cmd_check_inner()` to load baseline receipt
3. Applied AFTER `run_check()` returns, modifying the receipt and verdict before output

### 5. No Changes Needed to Core Engine

The baseline comparison logic should happen at the CLI layer (post-check), not in the core `run_check()` function. This keeps the core engine unchanged and focused on its single responsibility.

## Dependencies and Constraints

### Constraints

1. **Exit code stability**: Must maintain existing exit codes (0=pass, 1=error, 2=fail, 3=warn-fail)
2. **Schema compatibility**: Cannot change the `CheckReceipt` schema
3. **Backward compatibility**: All existing behavior must remain unchanged when `--baseline` is not used
4. **No I/O in domain crates**: The baseline comparison should happen in the CLI crate

### Dependencies

- `diffguard-types` for `CheckReceipt`, `Finding` types
- `diffguard-analytics` for `fingerprint_for_finding()` and `baseline_from_receipt()`
- `serde_json` for parsing receipt JSON files

## Summary

The baseline/grandfather mode feature is well-scoped and leverages existing infrastructure. The key insight is that this is a **post-processing step** at the CLI layer - the core `run_check()` engine remains unchanged. The fingerprint computation and baseline extraction already exist in `diffguard-analytics`, so the main work is:

1. Adding the CLI flag
2. Loading and parsing a baseline receipt JSON
3. Computing fingerprints for current findings
4. Comparing against baseline fingerprints
5. Modifying output to distinguish new vs pre-existing findings
6. Adjusting exit codes appropriately