# Vision Alignment Comment: Baseline/Grandfather Mode for Enterprise Adoption

**Work ID:** work-5a1ff6f4
**Date:** 2026-04-08
**Agent:** maintainer-vision-agent

---

## Alignment Assessment

**Status: ALIGNED**

The proposed baseline/grandfather mode feature is **well-aligned** with diffguard's architecture, design goals, and enterprise adoption strategy.

---

## Reasoning

### 1. Architecture Consistency

The post-processing approach is the **correct architectural pattern** for diffguard:

- **Existing precedent**: The `--false-positive-baseline` flag already uses fingerprint-based filtering after `run_check()`. The baseline mode extends this pattern rather than inventing a new one.

- **Clean separation**: Keeping baseline comparison in the CLI layer (post-processing) preserves the **I/O-free domain crates** invariant from agent-context.md. The core engine (`run_check()`) remains unchanged.

- **Exit code override point is clear**: `cmd_check_inner()` returns `run.exit_code` directly, so baseline mode can compute its own exit code from new findings only.

### 2. Design Goals Preserved

| Design Goal | How Baseline Mode Supports It |
|-------------|-------------------------------|
| Diff-only scope | Baseline comparisons work only on findings within current diff scope |
| Deterministic | SHA-256 fingerprint matching is deterministic across runs |
| Clean architecture | I/O in CLI layer, pure logic in core/domain crates |

### 3. Addresses Stated Enterprise Need

The GitHub issue identifies **"no baseline mode"** as the #1 enterprise adoption blocker. This feature directly addresses that blocker by:
- Allowing incremental adoption (existing violations grandfathered, new violations fail)
- Exit code 0 when only pre-existing violations exist
- Exit code 2 when new violations are introduced

### 4. Leverages Existing Infrastructure

Rather than inventing new mechanisms, the feature reuses:
- `fingerprint_for_finding()` (SHA-256 of `rule_id:path:line:match_text`)
- `baseline_from_receipt()` for parsing existing receipts
- `false_positive_fingerprint_set()` pattern for fast fingerprint lookup

This is consistent with how diffguard typically extends functionality—building on existing foundations.

### 5. Constraints Are Respected

| Constraint | How It's Honored |
|------------|------------------|
| Exit code stability | Exit codes unchanged (0, 1, 2, 3 maintained) |
| Schema compatibility | Receipt JSON unchanged; annotations only in rendered outputs |
| Backward compatibility | All existing behavior unchanged when `--baseline` not used |
| No I/O in domain crates | Baseline loading and comparison happen in CLI crate |

---

## Concerns (Minor, Not Blocking)

### Concern 1: Rule-Pattern Scoping (Advisory)

The adversarial challenge correctly identifies that **all-or-nothing baseline is limiting** for enterprise adoption. Teams may want to grandfather violations for some rules while strictly enforcing others.

**Assessment**: This is a valid concern but should be **post-MVP enhancement**. The MVP provides foundational value (incremental adoption from day 1 state). Rule-pattern scoping can be layered on top using `--baseline-include-rule` and `--baseline-exclude-rule` flags later.

**Recommendation**: Acknowledge in documentation that future versions may add rule-pattern scoping.

### Concern 2: Output Format Scope (Advisory)

The plan proposes updating multiple output formats (markdown, GitHub annotations, SARIF, JUnit, CSV). The plan review correctly identifies this as under-scoped.

**Assessment**: The plan review recommendation to **start with markdown only** is correct.

**Recommendation**: Limit baseline annotations to markdown output for MVP. SARIF has native `baselineId` support that should be leveraged when SARIF output is enhanced.

### Concern 3: `--baseline` + `--false-positive-baseline` Interaction

Both flags can theoretically be used together, but they serve different purposes:
- `--false-positive-baseline`: Filters findings (they don't appear in output)
- `--baseline`: Annotates findings (all appear, marked as "baseline" or "new")

**Assessment**: This is a **legitimate concern** but not blocking. The user experience is confusing if both are used together.

**Recommendation**: Document clearly that `--baseline` and `--false-positive-baseline` are **different concepts** and typically used **mutually exclusively**. The baseline mode shows all findings with annotations; false-positive baseline suppresses them.

---

## Long-Term Impact Assessment

### Positive Impacts

1. **Unblocks enterprise adoption**: Removes the #1 adoption blocker, opening diffguard to teams with existing codebases.

2. **Creates upgrade path**: Teams can adopt diffguard incrementally, building confidence before enabling strict enforcement.

3. **Foundation for analytics**: Baseline fingerprints enable tracking "findings introduced since baseline" which powers trend analytics.

4. **Precedent for post-processing patterns**: The CLI-layer post-processing architecture establishes a pattern for future features that need to modify behavior without changing core engine.

### Risks to Monitor

1. **Fingerprint stability**: If the fingerprint algorithm ever changes, baseline comparisons will break silently. Document the algorithm format explicitly.

2. **Exit code expectations**: Users familiar with non-baseline mode may expect errors from baseline findings. Clear documentation is essential.

---

## Recommendations

### Before Implementation (Advisory)

1. **Document fingerprint format** explicitly in code comments: `rule_id:path:line:match_text`, SHA-256.

2. **Add schema version validation** when loading baseline receipts.

3. **Scope Phase 3 to markdown only** for MVP.

4. **Add mutual exclusivity check** for `--baseline` and `--false-positive-baseline` (or document behavior clearly if they're allowed together).

### Documentation Additions

1. Update `--help` text for `--baseline` flag to explain:
   - Accepts path to a previous receipt JSON
   - Annotates findings as "baseline" (pre-existing) vs "new"
   - Exit code 0 if only baseline findings, exit 2 if new findings

2. Add a "Baseline Mode" section to `CONTRIBUTING.md` explaining:
   - How to use baseline mode for enterprise adoption
   - How fingerprint stability ensures consistent baseline comparisons
   - When to regenerate the baseline (e.g., after major refactoring)

---

## Conclusion

The baseline/grandfather mode feature is **architecturally sound, design-goal aligned, and addresses a genuine enterprise need**. The implementation approach (post-processing in CLI layer using existing fingerprint infrastructure) is the correct pattern for diffguard.

The concerns raised by verification and plan review are valid but are either:
- **Scope limitations** that should be addressed in Phase 3 (markdown-only output)
- **Future enhancements** that don't block MVP (rule-pattern scoping)
- **Documentation needs** that should be addressed before implementation

**Recommended next step**: Proceed with implementation, addressing the advisory concerns as noted above.
