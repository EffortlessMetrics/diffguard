# Verification Comment: Baseline/Grandfather Mode for Enterprise Adoption

**Work ID:** work-5a1ff6f4
**Verification Date:** 2026-04-08
**Research Confidence:** Medium-High

---

## Executive Summary

The research analysis is **largely correct** but has **significant gaps** around the interaction between baseline mode and the existing false-positive baseline mechanism. The core infrastructure exists as described, but the plan does not address architectural conflicts.

---

## Confirmed Findings

### Infrastructure Confirmed
| Claim | Status | Evidence |
|-------|--------|----------|
| `fingerprint_for_finding()` exists | CONFIRMED | `diffguard-analytics/src/lib.rs:67` - uses SHA-256 of `rule_id:path:line:match_text` |
| `baseline_from_receipt()` exists | CONFIRMED | `diffguard-analytics/src/lib.rs:77` |
| `false_positive_fingerprint_set()` exists | CONFIRMED | `diffguard-analytics/src/lib.rs:136` |
| `compute_fingerprint()` in core | CONFIRMED | `diffguard-core/src/fingerprint.rs:13` - same algorithm |
| `run_check()` function | CONFIRMED | `diffguard-core/src/check.rs:84` |
| `cmd_check_inner()` function | CONFIRMED | `crates/diffguard/src/main.rs:1953` |
| Schemas exist | CONFIRMED | Both `schemas/diffguard.check.schema.json` and `schemas/diffguard.false-positive-baseline.v1.schema.json` exist |
| Finding struct | CONFIRMED | `diffguard-types/src/lib.rs:126` - has `rule_id`, `path`, `line`, `match_text`, etc. |
| Exit codes | CONFIRMED | 0=pass, 1=error, 2=fail, 3=warn-fail - stable API |

### Key Architecture Claims Confirmed
1. **Baseline comparison is post-processing**: Verified - `cmd_check_inner()` at line 2335 returns `run.exit_code` directly from `run_check()`. Baseline comparison would need to happen AFTER this call.

2. **No I/O in domain crates**: Confirmed - `diffguard-core` has no file system access. All I/O is in the CLI crate (`diffguard`).

3. **Fingerprint algorithm**: Confirmed stable - both `compute_fingerprint()` in core and `fingerprint_for_finding()` in analytics use SHA-256 of `rule_id:path:line:match_text`.

---

## Corrected Findings

### 1. CheckArgs Location (Minor)
**Research said:** "around line 200"
**Actually:** Line 113 in `crates/diffguard/src/main.rs`

The research was approximately correct but off by ~90 lines. Not a critical error.

### 2. False-Positive Baseline is Already Integrated
**Research said:** Baseline mode is a "post-processing step"
**Correction:** The FALSE-POSITIVE baseline filtering is NOT post-processing - it happens INSIDE `run_check()` at `check.rs:144`:

```rust
if plan.false_positive_fingerprints.contains(&fingerprint) {
    // filtered out before verdict computation
    continue;
}
```

This means the current architecture already has fingerprint-based filtering in the core engine. Baseline mode (grandfather mode) is architecturally different - it should NOT filter findings, only annotate them.

---

## New Findings (Missing from Research)

### 1. Critical Gap: Interaction with False-Positive Baseline
The research does NOT address how `--baseline` (grandfather mode) would interact with the existing `--false-positive-baseline` flag. These are two different concepts:

| Feature | Behavior | Exit on Pre-existing |
|---------|----------|----------------------|
| `--false-positive-baseline` | Filters OUT known violations | Not applicable (filtered out) |
| `--baseline` (grandfather) | Annotates but SHOWS all findings | Exit 0 (only pre-existing) |

**Risk:** If a user provides `--baseline`, the existing `false_positive_fingerprints` would also be applied (if `--false-positive-baseline` is used too), leading to confusing behavior.

### 2. CheckPlan Already Contains Fingerprint Set
**Research said:** "Add to `CheckPlan` if needed"
**Reality:** `CheckPlan` already has:
```rust
pub false_positive_fingerprints: BTreeSet<String>,  // line 44
```

The baseline mode needs its own separate field because the semantics are different.

### 3. Verdict Computation Location
The verdict is computed INSIDE `run_check()` at `check.rs:169-175` based on filtered findings. For baseline mode, the verdict must be RE-COMPUTED after partitioning findings into "new" vs "baseline" - this cannot reuse the existing verdict from `run_check()`.

### 4. No `--baseline` Flag Exists
Verified: `CheckArgs` struct (lines 113-5210) has NO `--baseline` flag. Only:
- `--false-positive-baseline` (line 198)
- `--write-false-positive-baseline` (line 248)

### 5. Output Rendering is Scattered
The plan mentions updating "markdown rendering in render.rs". However, findings are rendered in multiple places:
- `render_markdown_for_receipt()` in `diffguard-core/src/render.rs`
- GitHub annotations (inline at `main.rs:2179`)
- SARIF, JUnit, CSV outputs

Baseline annotations would need to be added to ALL these renderers.

---

## Issues and Concerns

### High Priority

#### 1. Exit Code Logic Conflict
The plan states:
- Exit 0 if only pre-existing (baseline) violations found
- Exit 2 if NEW violations found

But `run.exit_code` is computed inside `run_check()` based on ALL findings (after false-positive filtering). For baseline mode, the exit code must be OVERRIDDEN after computing new vs baseline findings. This requires modifying `cmd_check_inner()` to compute a separate exit code when baseline mode is active.

#### 2. Receipt Modification
The plan says "modify receipt rendering to annotate findings". But the receipt (`CheckReceipt`) is already written to JSON at line 2169. If baseline annotations are needed, they must either:
- Be added to the receipt (schema change - not allowed per constraints)
- Be computed at render time without modifying the stored receipt

The plan doesn't address this.

### Medium Priority

#### 3. `--report-mode` Flag
The plan proposes `--report-mode=new-only` but doesn't specify how this interacts with `--baseline` (which shows ALL findings with annotations). These could conflict.

#### 4. Memory Usage
Loading a large baseline receipt with many findings creates a `BTreeSet<String>` of fingerprints. For enterprise repos with thousands of violations, this could be significant. The plan mentions "use streaming JSON parsing if needed" but doesn't implement it.

---

## Friction History Relevance

Prior friction entries show:
- "gates.py" friction (5 entries) - be careful with artifact registration
- "branch" friction (7 entries) - ensure correct branch usage
- "red_tests" confusion about benchmark files - the plan's Phase 5 testing should be clear about what's being tested

---

## Confidence Assessment

| Aspect | Confidence | Notes |
|--------|------------|-------|
| Infrastructure exists | HIGH | All functions, schemas confirmed present |
| Architecture approach | MEDIUM | Post-processing is correct, but interaction with existing FP baseline unclear |
| Exit code logic | MEDIUM | Needs careful handling to override core's exit code |
| Output annotations | LOW | Multiple renderers affected, not fully scoped |
| Testing plan | LOW | Doesn't address how to test baseline without modifying existing FP tests |

---

## Recommendations for Plan Revision

1. **Clarify `--baseline` vs `--false-positive-baseline` interaction**: Can they be used together? Should they be mutually exclusive?

2. **Add baseline-specific exit code override logic**: The override must happen in `cmd_check_inner()` AFTER `run_check()` returns.

3. **Scope output format changes**: Start with markdown only, as the plan suggests, but explicitly call out that other formats need separate work.

4. **Consider baseline receipt format**: If users need to compare against a baseline, maybe a dedicated baseline file format (not full CheckReceipt) would be cleaner.

---

## Verification Conclusion

**Status:** Research is CORRECT but INCOMPLETE

The fundamental approach (post-processing in CLI layer using existing fingerprint infrastructure) is sound. However, the plan underestimates:
1. The complexity of exit code override
2. The interaction with existing false-positive baseline
3. The scope of output rendering changes needed

The implementation is FEASIBLE but requires more detailed architectural planning around how baseline mode modifies the exit code and output WITHOUT changing the core engine or receipt schema.
