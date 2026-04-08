# Implementation: Baseline/Grandfather Mode

## Feature: `--baseline` CLI Flag

### Files Modified
- `crates/diffguard/src/main.rs` (+301 lines)

### Implementation Summary

**Approach**: Post-processing in CLI layer (core engine unchanged).

### CLI Flags Added

#### `--baseline <PATH>`
Loads a baseline `CheckReceipt` JSON and annotates findings as `[BASELINE]` or `[NEW]`.

Exit codes under baseline mode:
- `0`: Only pre-existing (baseline) violations found
- `2`: NEW error violations found (CI should fail)
- `3`: Only new warnings found (when fail_on includes warn)

#### `--report-mode <all|new-only>`
- `all` (default): Show all findings with baseline/new annotations
- `new-only`: Only show NEW findings (baseline findings hidden)

### Key Functions Added

1. **`load_baseline_receipt(path)`** - Loads and validates baseline receipt JSON
2. **`compare_against_baseline(findings, baseline_fps)`** - Partitions findings into baseline vs new
3. **`compute_baseline_exit_code(fail_on, new_counts)`** - Computes exit code from new findings only
4. **`render_markdown_with_baseline_annotations(...)`** - Renders markdown with `[BASELINE]`/`[NEW]` prefixes
5. **`escape_md(s)`** - Escapes special markdown characters

### Integration in `cmd_check_inner()`

The baseline logic is applied as a post-processing step after `run_check()` returns:
1. Load baseline receipt if `--baseline` flag provided
2. Partition findings into baseline vs new using `fingerprint_for_finding()`
3. Compute adjusted exit code based only on new findings
4. Re-render markdown with annotations
5. Override exit code for the run

### Schema Compatibility

Baseline receipt schema version is validated against `CHECK_SCHEMA_V1`. Compatible receipts can be any valid `CheckReceipt` from prior diffguard runs.

### Relationship to `--false-positive-baseline`

- `--false-positive-baseline`: **Suppresses** findings (they don't appear in output)
- `--baseline`: **Annotates** all findings (baseline ones marked `[BASELINE]`, new as `[NEW]`)

These are mutually exclusive in intent and behavior.
