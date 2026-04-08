# ADR-035: Baseline/Grandfather Mode for Enterprise Adoption

**Status:** Proposed

**Date:** 2026-04-08

**Work ID:** work-5a1ff6f4

---

## Context

Diffguard currently has no baseline mode. Teams with existing codebases cannot adopt diffguard without immediately failing on all pre-existing violations. This is identified as the **#1 enterprise adoption blocker** (GitHub Issue #35).

The existing `--false-positive-baseline` flag suppresses known false positives (they don't appear in output), but provides no mechanism for teams to adopt incrementally while tracking new violations separately.

### The Problem

When a team with an existing codebase tries to adopt diffguard:
1. Running `diffguard check` finds hundreds or thousands of pre-existing violations
2. Exit code is non-zero, failing CI/CD
3. The team cannot adopt without either:
   - Fixing ALL violations simultaneously (impractical for large codebases)
   - Ignoring all violations (defeats the purpose of the tool)

### Constraints

1. **Exit code stability**: Must maintain existing exit codes (0=pass, 1=error, 2=fail, 3=warn-fail)
2. **Schema compatibility**: Cannot change the `CheckReceipt` JSON schema
3. **Backward compatibility**: All existing behavior must remain unchanged when `--baseline` is not used
4. **No I/O in domain crates**: The baseline comparison must happen in the CLI crate, not core/domain

### Existing Infrastructure

The codebase already provides necessary building blocks:
- `fingerprint_for_finding()` in `diffguard-analytics`: SHA-256 of `rule_id:path:line:match_text`
- `baseline_from_receipt()` in `diffguard-analytics`: Converts `CheckReceipt` to `FalsePositiveBaseline`
- `false_positive_fingerprint_set()`: Returns `BTreeSet<String>` for fast fingerprint lookup
- `run_check()` returns findings with fingerprints already computed

---

## Decision

We implement **baseline mode** (grandfather mode) as a **post-processing step** in the CLI layer, reusing the existing receipt JSON format and fingerprint infrastructure.

### Key Design Decisions

#### 1. Baseline Receipt Format
Reuse the existing `CheckReceipt` JSON schema. Enterprises already have receipt files from their initial adoption run. A separate baseline file format would add unnecessary friction.

#### 2. Fingerprint Matching
Use the existing `fingerprint_for_finding()` function which computes SHA-256 of `rule_id:path:line:match_text`. This is deterministic and stable, providing consistent identification across runs.

#### 3. Baseline Comparison is Post-Processing
The baseline comparison happens **after** `run_check()` returns, in `cmd_check_inner()`. This keeps the core engine unchanged and focused on its single responsibility. The `run_check()` function remains untouched.

#### 4. Output Modes
- **Default**: Show ALL findings with "baseline" vs "new" annotation (users need visibility into what was grandfathered)
- **`--report-mode=new-only`**: Only show new findings (clean view of just new violations)

#### 5. Exit Codes Under Baseline Mode
- `0`: Only pre-existing (baseline) violations found (grandfathered)
- `2`: NEW violations found (fail CI/CD when new violations are introduced)
- `1`: Error condition (unchanged from current behavior)
- `3`: Warning-only failures (unchanged)

#### 6. Mutual Exclusivity with False-Positive Baseline
`--baseline` and `--false-positive-baseline` serve different purposes:
- `--false-positive-baseline`: Filters OUT findings (they don't appear in output)
- `--baseline`: Annotates findings (all appear, marked as "baseline" or "new")

These flags are documented as **mutually exclusive in intent** - users should choose one workflow, not combine them.

---

## Implementation Approach

### Entry Point
Add `--baseline` flag (`Option<PathBuf>`) and `--report-mode` flag (`Option<ReportMode>`) to `CheckArgs` struct in `main.rs` (around line 113).

### Baseline Loading
1. Parse JSON receipt file at the path provided to `--baseline`
2. Validate schema version
3. Extract findings and compute fingerprint set using `fingerprint_for_finding()`

### Comparison Logic
1. Compute fingerprints for all current findings
2. Partition findings into:
   - `baseline_findings`: Fingerprints match baseline
   - `new_findings`: Fingerprints do NOT match baseline
3. Re-compute verdict from `new_findings` only

### Exit Code Override
In `cmd_check_inner()`, when `--baseline` is used:
- If `new_findings` is empty: exit 0
- If `new_findings` has errors: exit 2
- If `new_findings` has warnings only: exit 3

### Output Annotation
Modify markdown rendering to annotate findings:
- Prefix baseline findings with `[BASELINE]`
- Prefix new findings with `[NEW]`

---

## Consequences

### Positive
1. **Unblocks enterprise adoption**: Removes the #1 adoption blocker
2. **Incremental adoption path**: Teams can adopt diffguard rule-by-rule, baselining violations for rules still being configured
3. **Foundation for analytics**: Baseline fingerprints enable tracking "findings introduced since baseline"
4. **Establishes post-processing pattern**: CLI-layer post-processing for future features that need to modify behavior without changing core engine

### Negative / Tradeoffs
1. **Fingerprint instability across code changes**: If code around a violation changes, the fingerprint changes even if the violation is semantically the same. This may cause legitimate violations to appear as "new."

2. **All-or-nothing baseline scope**: Currently, baseline mode is global. An enterprise cannot baseline violations for some rules while strictly enforcing others. (Post-MVP enhancement: `--baseline-include-rule` and `--baseline-exclude-rule` patterns)

3. **Memory usage at scale**: Large enterprise repos with thousands of violations load the entire baseline fingerprint set into memory. (Streaming JSON parsing can be added if needed)

### Risks
1. **Fingerprint algorithm change**: If SHA-256 format changes, baseline comparisons break silently. Must document format explicitly.

2. **Exit code confusion**: Users may expect `--baseline` to change `fail_on` behavior. Documentation must clarify that `fail_on` applies to new violations only.

---

## Alternatives Considered

### Alternative 1: "Negative Baseline" (Acceptance Workflow)
**Instead of providing a historical receipt, use a two-step acceptance workflow:**
1. Phase 1 - Discovery: Run `diffguard check` with output but exit 0
2. Phase 2 - Acceptance: Run `diffguard accept --current` to mark current violations as baseline

**Why we rejected it**: Requires new "accept" command and state management. The receipt-based approach is simpler and leverages existing artifacts.

### Alternative 2: "Delta Scope Control" (Per-Rule/Directory Baseline)
Allow baseline to be scoped to specific rules or directories:
- `--baseline-rule=sensitive-*` only applies baseline to rules matching pattern

**Why we rejected for MVP**: Valid concern but adds complexity. MVP should provide foundational value first; rule-pattern scoping can be layered later.

### Alternative 3: "Baseline as Infrastructure" (Push-based State)
Maintain a lightweight baseline service:
- `diffguard check --baseline-push` - Push to central baseline store
- `diffguard check --baseline-pull` - Pull from central store

**Why we rejected it**: Adds infrastructure dependency. Not all enterprises have such services. File-based baseline works everywhere.

### Alternative 4: Separate Baseline Schema
Create a dedicated `.diffguard/baseline.json` format instead of reusing `CheckReceipt`.

**Why we rejected it**: Enterprises already have receipt files. Requiring a separate format adds friction and confusion about which file to use.

---

## References

- GitHub Issue: https://github.com/EffortlessMetrics/diffguard/issues/35
- Research Analysis: `/work-5a1ff6f4/research_analysis.md`
- Verification Comment: `/work-5a1ff6f4/verification_comment.md`
- Plan Review: `/work-5a1ff6f4/plan_review_comment.md`
- Vision Alignment: `/work-5a1ff6f4/vision_alignment_comment.md`
