# Plan Review: Baseline/Grandfather Mode for Enterprise Adoption

## Approach Assessment

**Verdict: CONDITIONALLY FEASIBLE** - The high-level approach is sound, but the plan has significant gaps that could lead to implementation problems, schema violations, and user confusion.

### What Works

1. **Post-processing architecture is correct**: Implementing baseline comparison after `run_check()` is the right call. The core engine stays unchanged, reducing risk to existing functionality.

2. **Fingerprint infrastructure is solid**: `fingerprint_for_finding()` already exists and produces stable SHA-256 fingerprints using `rule_id:path:line:match_text`. This is reusable for baseline tracking.

3. **Exit code modification point is clear**: `cmd_check_inner()` returns `run.exit_code` directly, so modifying exit codes for baseline mode is straightforward.

4. **False-positive baseline infrastructure is a good model**: The existing `--false-positive-baseline` flow shows how to load a baseline file and use fingerprints for filtering.

### What Doesn't Work / Needs Clarification

1. **Finding annotation requires new data structure**: The `Finding` struct has no field for "baseline" vs "new" annotation. You cannot simply annotate existing findings without either:
   - Adding a new optional field to `Finding` (schema change)
   - Creating a separate "annotated finding" wrapper type for rendering only
   - Carrying baseline info in a separate parallel structure

2. **Receipt JSON schema constraint may be violated**: The plan says "Cannot change the CheckReceipt schema" but then proposes annotating findings. If you annotate findings and write them to the receipt file, the JSON will have extra fields not in the schema. This is a contradiction.

3. **The plan underestimates Phase 3 scope**: "Update markdown rendering, GitHub annotations, SARIF/JUnit/CSV outputs" is listed as a single bullet but represents 5+ distinct output formats with different data models. Each will need careful consideration.

---

## Risk Analysis

### Risk 1: Schema Violation from Annotated Findings (HIGH)

**Problem**: If baseline mode annotates findings (adding "baseline" or "new" tags) and writes them to the receipt JSON file, the output violates the `diffguard.check.schema.json` schema. This breaks:
- JSON schema validation
- downstream tools consuming the receipt
- the "Schema compatibility" constraint explicitly stated in the plan

**Likelihood**: High - the plan explicitly requires annotation in outputs

**Mitigation needed**: Define a clear boundary:
- The receipt JSON file should contain **only** raw findings (unchanged from current behavior)
- Baseline annotations should exist **only** in rendered outputs (markdown, GitHub annotations, etc.)
- OR: Add a separate `baseline_info` field to the receipt that's optional and backward-compatible

---

### Risk 2: Exit Code Logic Doesn't Account for Mixed Severity (MEDIUM)

**Problem**: The plan states:
- `exit 0` if only baseline violations found
- `exit 2` if NEW errors found
- `exit 3` if NEW warnings found

But what if you have:
- 5 baseline errors (should be ignored)
- 1 new warning (should exit 3)

The plan doesn't address what happens when baseline has errors AND new warnings. Should the exit code reflect only new findings?

**Likelihood**: Medium - this is a real-world scenario

**Mitigation**: The exit code should be computed **only from new findings**, ignoring baseline findings entirely. Document this clearly.

---

### Risk 3: Output Format Proliferation Bug Risk (MEDIUM)

**Problem**: Phase 3 lists markdown, GitHub annotations, SARIF, JUnit, and CSV as needing baseline annotation updates. Each format has different data models:
- SARIF has `baselineId` support built-in
- JUnit has no standard baseline concept
- GitHub annotations are just strings

**Likelihood**: Medium - implementing for all formats correctly is complex

**Mitigation**: Start with **markdown output only** for baseline annotations. Add other formats based on user demand. SARIF has native `baselineId` support which should be leveraged rather than reimplemented.

---

### Risk 4: Fingerprint Stability Over Time (LOW-MEDIUM)

**Problem**: If the fingerprint algorithm ever changes (e.g., adding new fields), existing baseline comparisons will break silently. A baseline from last year won't match findings today.

**Likelihood**: Low - the algorithm has been stable, but no formal versioning exists

**Mitigation**: 
- Document the fingerprint format explicitly
- Add schema version validation when loading baseline receipts
- Consider embedding a fingerprint version in baseline files

---

### Risk 5: match_text Fragility (LOW)

**Problem**: Fingerprints include `match_text`. If the same logical violation exists but with slightly different whitespace or context (e.g., code reformatted), it will be considered "new" even though it's the same rule violation.

**Likelihood**: Low - in practice, match_text is the matched rule pattern, not arbitrary code

**Mitigation**: Accept as-is; this is actually conservative (treating reformatting as potentially new violations is safer).

---

## Edge Cases Identified

### 1. Baseline file has findings not in current diff
When loading a baseline receipt with findings for files/lines that aren't in the current diff scope, those baseline fingerprints simply won't match any current findings. This is fine and expected - the plan handles this naturally.

### 2. Same path:line but different match_text
If code is refactored at the same line (same file, same line number) but triggers a different rule match, the fingerprint will differ and it will be marked as new. The plan accepts this but doesn't explicitly discuss whether this is the desired behavior.

### 3. Baseline created with different rule set
If baseline was created with different `--only-tags`, `--disable-tags`, or different config, the findings may not be comparable. The plan acknowledges this as "an enterprise adoption concern, not a correctness concern" but users may be confused.

### 4. Mixed severity in baseline vs current
What if a baseline finding was `warn` severity but the same finding in current is `error`? The fingerprint matches (same rule_id:path:line:match_text) so it should be treated as baseline, not new. **But** the severity in the current finding should be used for verdict computation. This needs explicit handling.

### 5. Inline suppressions in baseline
If baseline was created with inline suppressions (`# diffguard: skip`) that are now removed, those findings become "new". This is correct behavior but should be tested.

---

## Recommendations (Changes Before Proceeding)

### MUST FIX (Blocking Issues)

1. **Clarify annotation architecture**: Decide and document:
   - Will annotated findings be written to receipt JSON? If yes, schema needs version bump or optional fields
   - OR: Annotations exist only in rendered outputs (recommended)
   
2. **Add `baseline_fingerprints: BTreeSet<String>` to CheckArgs/CheckPlan**: This should be a separate field from `false_positive_fingerprints` to keep the concepts distinct. The plan says to create `BaselineStats` but doesn't show where this data flows.

3. **Define `ReportMode` enum clearly**:
   ```rust
   enum ReportMode {
       All,        // Show baseline + new findings (default)
       NewOnly,    // Show only new findings
   }
   ```

### SHOULD FIX (Strongly Advised)

4. **Restrict initial baseline annotation to markdown output only**: Add SARIF/JUnit/GitHub annotations later based on user need. SARIF's native `baselineId` support should be leveraged when that time comes.

5. **Add schema version validation**: When loading a baseline receipt, validate the `schema` field and reject unsupported versions with a clear error message.

6. **Document exit code behavior explicitly**: Write out the truth table for exit codes with baseline mode:
   - No new findings → exit 0 (regardless of baseline findings)
   - New findings with errors (and fail_on includes error) → exit 2
   - New findings with warnings only (and fail_on includes warn) → exit 3

### NICE TO HAVE (Post-MVP)

7. **Consider fingerprint versioning**: Embed a version prefix in fingerprint computation to allow future algorithm changes without silent breakage.

8. **Add `--baseline-strict` flag**: Optionally fail if baseline receipt has findings for files not in current diff scope (catches config drift).

---

## Open Questions Not Addressed

1. **What happens to the verdict in the receipt JSON?**
   - If baseline mode changes the effective verdict, should the receipt reflect the adjusted verdict (based on new findings only) or the raw verdict?
   - Recommendation: Receipt should show raw findings and raw verdict. Adjusted verdict should be computed at output-render time for exit codes.

2. **Should baseline be allowed with `--false-positive-baseline`?**
   - These are conceptually different but could be used together. The plan should address whether they're mutually exclusive or additive.

3. **What is the lifecycle of a baseline?**
   - When should teams regenerate their baseline? The plan doesn't guide users on this.

---

## Summary

The plan is **structurally sound** but **incomplete** in critical areas. The post-processing approach is correct and leverages existing infrastructure well. However:

- **Blocking**: The annotation/schema contradiction must be resolved
- **Blocking**: The data flow for baseline fingerprints must be clearly defined
- **Advisory**: Scope Phase 3 to markdown-only initially
- **Advisory**: Add explicit exit code truth table

**Recommended next step**: Author a brief "Baseline Mode Technical Note" clarifying the annotation architecture and data flow before implementation begins.
