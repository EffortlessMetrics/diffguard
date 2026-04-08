# Specs: Baseline/Grandfather Mode for Enterprise Adoption

**Work ID:** work-5a1ff6f4

**Date:** 2026-04-08

---

## Feature Description

Baseline mode (grandfather mode) allows teams with existing codebases to adopt diffguard incrementally. When `--baseline` is provided with a path to a previous receipt JSON, diffguard:

1. Compares current findings against the baseline receipt using fingerprint matching
2. Annotates findings as "baseline" (pre-existing) or "new"
3. Returns exit code 0 if only pre-existing violations found
4. Returns exit code 2 if NEW violations are introduced (only new violations affect exit code)
5. Optionally filters output to show only new findings via `--report-mode=new-only`

### Use Case Example

A team has 500 pre-existing violations. They want to adopt diffguard such that:
- Existing violations are grandfathered (allowed)
- NEW violations introduced after adoption fail the build

```bash
# Initial adoption run - create baseline
diffguard check --output receipt.json
# Team reviews receipt.json, decides which rules to enforce

# Subsequent runs - use baseline
diffguard check --baseline receipt.json
# Exit 0 if only pre-existing violations
# Exit 2 if new violations introduced since baseline
```

---

## Functionality Specification

### Core Features

#### F1: `--baseline` Flag
- **Type**: `Option<PathBuf>`
- **Behavior**: Accepts path to a previous `CheckReceipt` JSON file
- **Error handling**: If file doesn't exist or is invalid JSON, exit 1 with error message
- **Validation**: If schema version is incompatible, exit 1 with clear error

#### F2: `--report-mode` Flag
- **Type**: `Option<ReportMode>` enum with variants:
  - `All` (default): Show ALL findings with "baseline"/"new" annotation
  - `NewOnly`: Only show NEW findings (baseline findings hidden)
- **Behavior**: Only affects output, not exit code logic

#### F3: Fingerprint Computation
- **Algorithm**: SHA-256 of `rule_id:path:line:match_text`
- **Location**: Use existing `fingerprint_for_finding()` from `diffguard-analytics`
- **Stability**: Fingerprint must be deterministic across runs

#### F4: Baseline Receipt Loading
- **Input**: Path to JSON file (validated as `CheckReceipt` schema)
- **Process**:
  1. Parse JSON
  2. Validate schema version field
  3. Extract findings
  4. Compute fingerprint set from baseline findings
- **Output**: `BTreeSet<String>` of baseline fingerprints

#### F5: Finding Classification
- **Baseline finding**: A finding whose fingerprint exists in the baseline fingerprint set
- **New finding**: A finding whose fingerprint does NOT exist in the baseline fingerprint set

#### F6: Exit Code Logic (Baseline Mode)
When `--baseline` is provided:
- `0`: `new_findings` is empty (only pre-existing violations)
- `2`: `new_findings` contains errors (and `fail_on` includes error)
- `3`: `new_findings` contains warnings only (and `fail_on` includes warn)
- `1`: Error condition (file not found, parse error, etc.)

#### F7: Output Annotation (Markdown)
Findings in markdown output are annotated:
- `[BASELINE]` prefix for pre-existing violations
- `[NEW]` prefix for new violations

Example output:
```
## Findings

[NEW] security:sql-injection - src/db.rs:42 - "SELECT * FROM ..."
[BASELINE] style:line-length - src/main.rs:120 - "line exceeds 100 chars"
```

---

## User Interactions and Flows

### Flow 1: Initial Baseline Creation
```
1. User runs: diffguard check --output receipt.json
2. User reviews receipt.json
3. User stores receipt.json as baseline (e.g., commit to repo)
```

### Flow 2: Check Against Baseline
```
1. CI/CD runs: diffguard check --baseline receipt.json
2. Diffguard loads baseline, compares against current findings
3. Output shows all findings with [BASELINE]/[NEW] annotations
4. Exit code reflects only new findings
```

### Flow 3: New-Only Reporting
```
1. CI/CD runs: diffguard check --baseline receipt.json --report-mode=new-only
2. Output shows only NEW findings
3. Exit code still reflects only new findings
```

---

## Data Handling

### Baseline Receipt Format
Reuses existing `CheckReceipt` JSON schema:
```json
{
  "schema": "diffguard.check.v1",
  "tool": { ... },
  "diff": { ... },
  "findings": [
    {
      "rule_id": "security:sql-injection",
      "severity": "error",
      "message": "...",
      "path": "src/db.rs",
      "line": 42,
      "match_text": "SELECT * FROM ...",
      ...
    }
  ],
  "verdict": { ... }
}
```

### Fingerprint Set
Stored in memory as `BTreeSet<String>` for efficient lookup:
- Key: SHA-256 fingerprint string
- Value: None (set membership only)

---

## Edge Cases

### EC1: Empty Baseline Receipt
If baseline receipt has no findings:
- All current findings are classified as NEW
- Exit code based on all current findings

### EC2: Empty Current Findings
If current run has no findings but baseline had findings:
- `new_findings` is empty
- Exit code 0 (baseline findings are grandfathered)

### EC3: Schema Version Mismatch
If baseline receipt has incompatible schema version:
- Exit 1 with error: "Incompatible baseline schema version"
- Error message should list expected and actual versions

### EC4: Invalid JSON File
If baseline file is not valid JSON:
- Exit 1 with error: "Failed to parse baseline receipt: {details}"

### EC5: Baseline File Not Found
If baseline path does not exist:
- Exit 1 with error: "Baseline receipt not found: {path}"

### EC6: Missing Fingerprint Fields
If a finding in baseline lacks fields needed for fingerprint:
- Skip that finding (log warning in debug mode)

### EC7: File Permissions
If baseline file exists but cannot be read:
- Exit 1 with error: "Failed to read baseline receipt: {details}"

---

## Non-Goals (Out of Scope for MVP)

### NG1: Rule-Pattern Scoping
MVP uses global baseline only. Not included:
- `--baseline-include-rule` pattern
- `--baseline-exclude-rule` pattern

Post-MVP enhancement.

### NG2: Multiple Baselines
MVP supports single baseline only. Not included:
- Merging multiple baseline files
- Baseline precedence ordering

### NG3: Baseline Modification Commands
MVP does not include:
- `diffguard accept` command
- `diffguard baseline-update` command

### NG4: Streaming JSON Parsing
MVP loads entire baseline into memory. Not included:
- Streaming parser for very large baseline files

### NG5: SARIF/GitHub/JUnit/CSV Annotation
MVP annotation only in markdown output. Not included:
- Annotations in SARIF format
- Annotations in GitHub annotations
- Annotations in JUnit XML
- Annotations in CSV

---

## Dependencies

### Internal Crates
| Crate | Usage |
|-------|-------|
| `diffguard-types` | `CheckReceipt`, `Finding` types |
| `diffguard-analytics` | `fingerprint_for_finding()`, `baseline_from_receipt()` |
| `diffguard-core` | `run_check()` (unchanged), `render_markdown_for_receipt()` |

### External
| Dependency | Usage |
|------------|-------|
| `serde_json` | Parsing receipt JSON files |

### No New Dependencies Required
All necessary functions (`fingerprint_for_finding()`, `baseline_from_receipt()`, `false_positive_fingerprint_set()`) already exist in `diffguard-analytics`.

---

## Acceptance Criteria

### AC1: Baseline Flag
- [ ] `CheckArgs` struct includes `--baseline` flag of type `Option<PathBuf>`
- [ ] Running `diffguard check --baseline /nonexistent/path.json` exits with code 1 and error message

### AC2: Baseline Receipt Loading
- [ ] Valid baseline receipt JSON is parsed without error
- [ ] Invalid JSON produces exit 1 with parse error message
- [ ] Missing file produces exit 1 with "not found" error
- [ ] Schema version validation rejects incompatible versions

### AC3: Finding Classification
- [ ] Findings with fingerprints matching baseline are classified as BASELINE
- [ ] Findings with fingerprints NOT in baseline are classified as NEW
- [ ] Fingerprint computation is deterministic (same input = same fingerprint)

### AC4: Exit Code - No New Findings
- [ ] When `--baseline` provided and only baseline findings exist, exit code is 0
- [ ] When `--baseline` provided and no findings at all, exit code is 0

### AC5: Exit Code - New Findings
- [ ] When `--baseline` provided and new errors exist, exit code is 2
- [ ] When `--baseline` provided and only new warnings exist (no errors), exit code is 3

### AC6: Output Annotation
- [ ] Markdown output shows `[BASELINE]` prefix for baseline findings
- [ ] Markdown output shows `[NEW]` prefix for new findings
- [ ] When `--report-mode=new-only`, baseline findings are not shown

### AC7: Backward Compatibility
- [ ] Running `diffguard check` WITHOUT `--baseline` behaves identically to before
- [ ] No changes to `run_check()` function or core engine
- [ ] All existing exit codes remain unchanged without baseline flag

### AC8: Mutual Exclusivity Documentation
- [ ] `--help` text clarifies that `--baseline` and `--false-positive-baseline` are different concepts
- [ ] Documentation notes they are typically used mutually exclusively

---

## File Changes

| File | Changes |
|------|---------|
| `crates/diffguard/src/main.rs` | Add `--baseline` and `--report-mode` flags to `CheckArgs`; modify `cmd_check_inner()` for baseline comparison and exit code override |
| `crates/diffguard/src/render.rs` (or inline) | Add `[BASELINE]`/`[NEW]` annotation to markdown rendering |
| `crates/diffguard/tests/cli_check.rs` | Add baseline mode CLI integration tests |
| `crates/diffguard/tests/snapshot_tests.rs` | Add baseline output snapshots |

---

## Verification

### Unit Tests
1. `load_baseline_receipt()` - valid/invalid JSON, missing file, schema version
2. `compare_against_baseline()` - classification correctness, edge cases

### Integration Tests
1. `baseline_with_no_new_findings`: Should exit 0
2. `baseline_with_new_findings`: Should exit 2
3. `baseline_with_report_mode_new_only`: Should only show new findings
4. `baseline_preserves_existing_behavior`: Without `--baseline`, behavior unchanged

### Snapshot Tests
1. Markdown output format with annotations
2. JSON receipt output (unmodified by baseline annotations - annotations only in rendered output)
