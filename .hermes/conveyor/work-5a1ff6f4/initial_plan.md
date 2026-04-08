# Initial Plan: Baseline/Grandfather Mode for Enterprise Adoption

## Approach

The baseline mode is implemented as a **post-processing step** in the CLI layer. The core `run_check()` function remains unchanged because changing core engine behavior would risk introducing bugs in the existing functionality. Instead, the baseline comparison happens after the check completes, allowing us to modify the output and exit code without touching the well-tested core logic.

### Key Design Decisions

1. **Baseline Receipt Format**: Reuse the existing `CheckReceipt` JSON schema (from `schemas/diffguard.check.schema.json`). We do this because enterprises already have receipt files from their initial adoption run, and requiring a separate baseline file format would add unnecessary friction.

2. **Fingerprint Matching**: Use the existing `fingerprint_for_finding()` from `diffguard-analytics` which computes SHA-256 of `rule_id:path:line:match_text`. We leverage this because it is already deterministic and stable, providing a consistent way to identify findings across runs.

3. **Output Modes**:
   - Default: Show all findings with "baseline" vs "new" annotation (because users need visibility into what was grandfathered)
   - `--report-mode=new-only`: Only show new findings (because some workflows want a clean view of just new violations)

4. **Exit Codes**:
   - `0`: Only pre-existing (baseline) violations found (because the point of baseline mode is to allow existing violations)
   - `2`: NEW violations found (because we want to fail CI/CD when new violations are introduced, which is the core value proposition)

## Task Breakdown

### Phase 1: CLI Flag and Receipt Loading

- [ ] Add `--baseline` flag to `CheckArgs` struct in `main.rs`
  - Type: `Option<PathBuf>`
  - Accepts path to previous receipt JSON
- [ ] Add `--report-mode` flag to `CheckArgs` struct
  - Type: `Option<ReportMode>` enum (all, new-only)
- [ ] Implement `load_baseline_receipt()` function
  - Parse JSON receipt file
  - Validate schema version
  - Extract findings and compute fingerprint set

### Phase 2: Baseline Comparison Logic

- [ ] Create `BaselineStats` struct to track:
  - `baseline_fingerprints: BTreeSet<String>`
  - `new_findings: Vec<Finding>`
  - `baseline_findings: Vec<Finding>`
- [ ] Implement `compare_against_baseline()` function
  - Compute fingerprints for all current findings
  - Partition into new vs baseline
  - Calculate adjusted verdict (only based on new findings)

### Phase 3: Output Modification

- [ ] Modify receipt rendering to annotate findings as "new" or "baseline"
  - Update markdown rendering in `render.rs`
  - Update GitHub annotations
  - Update SARIF/JUnit/CSV outputs if needed
- [ ] Implement `--report-mode=new-only` filtering
  - Filter findings list in receipt before rendering
  - Adjust verdict counts based on filtered findings

### Phase 4: Exit Code Adjustment

- [ ] Modify exit code logic in `cmd_check_inner()`
  - When `--baseline` is used:
    - If `new_findings` is empty: exit 0
    - If `new_findings` has errors (and fail_on includes error): exit 2
    - If `new_findings` has warnings (and fail_on includes warn): exit 3

### Phase 5: Testing

- [ ] Add unit tests for `load_baseline_receipt()`
- [ ] Add unit tests for `compare_against_baseline()`
- [ ] Add CLI integration tests:
  - `baseline_with_no_new_findings`: Should exit 0
  - `baseline_with_new_findings`: Should exit 2
  - `baseline_with_report_mode_new_only`: Should only show new findings
- [ ] Add snapshot tests for output formats

## File Changes

| File | Changes |
|------|---------|
| `crates/diffguard/src/main.rs` | Add `--baseline` and `--report-mode` flags, modify `cmd_check_inner()` |
| `crates/diffguard/src/render.rs` (or new) | Add "baseline" vs "new" annotation to findings |
| `crates/diffguard/tests/cli_check.rs` | Add baseline mode tests |
| `crates/diffguard/tests/snapshot_tests.rs` | Add baseline output snapshots |

## Risks

### 1. Fingerprint Stability Risk

**Risk**: If the fingerprint algorithm changes, baseline comparisons will break silently.

**Mitigation**: Document the fingerprint format (`rule_id:path:line:match_text`, SHA-256) and add a schema version to the baseline file. Validate version on load.

### 2. Schema Version Mismatch

**Risk**: Loading an old receipt with a different schema version could cause issues.

**Mitigation**: Validate `schema` field in `CheckReceipt`. Require minimum supported version.

### 3. Exit Code Confusion

**Risk**: Users might expect `--baseline` to change how `fail_on` works, causing confusion.

**Mitigation**: Document clearly that `--baseline` only affects what counts as a "new" violation. `fail_on` still applies to new violations only.

### 4. Output Format Proliferation

**Risk**: Adding baseline annotations to multiple output formats could be error-prone.

**Mitigation**: Start with markdown output only. Add to other formats based on user demand.

### 5. Memory Usage with Large Baselines

**Risk**: Loading large receipt files with many findings could consume significant memory.

**Mitigation**: Use streaming JSON parsing if needed. The fingerprint set should be memory-efficient.

## Open Questions

1. **Should baseline fingerprints expire?**
   - If code is refactored and a finding's path/line changes, should it be considered "new"?
   - Current design: Yes, fingerprint is based on path:line:rule_id:match_text

2. **Should we support multiple baselines?**
   - Current design: No, just one baseline file
   - Could extend later to merge multiple baselines

3. **What happens if baseline diff scope differs from current?**
   - e.g., baseline was `added` scope, current is `changed`
   - Should compare findings, not scope - this is an enterprise adoption concern, not a correctness concern