# ADR-007: Extract Helper Functions from `evaluate_lines_with_overrides_and_language`

## Status
Proposed

## Context
The function `evaluate_lines_with_overrides_and_language` in `crates/diffguard-domain/src/evaluate.rs` has 201 lines and violates `clippy::pedantic::too_many_lines` (limit: 100). This function is the core evaluation engine that matches input lines against compiled rules, handling language-aware preprocessing, override resolution, dependency gating, severity escalation, and findings generation.

The function naturally decomposes into three distinct phases with minimal shared state:
1. **Phase 1 (lines 95–164)**: Line preparation — language detection, preprocessor setup, masking, suppression tracking
2. **Phase 2 (lines 166–251)**: Match event generation — rule evaluation per file with closure-heavy state
3. **Phase 3 (lines 253–312)**: Findings collection — event processing into structured findings

The file already has 6+ extracted helpers (e.g., `resolve_dependency_gated_rule_ids`, `find_positive_matches_for_rule`, `maybe_escalate_severity`), establishing a decomposition pattern.

## Decision
Extract three private helper functions from `evaluate_lines_with_overrides_and_language` to bring its line count under 100:

1. **`prepare_lines()`** — Extracts Phase 1 (line preparation loop). Returns `Vec<PreparedLine>` along with `files_seen` (count of distinct files). The three preprocessors and `SuppressionTracker` are passed as mutable references since they accumulate state.

2. **`generate_match_events()`** — Extracts Phase 2 (match event generation). Takes `prepared_lines`, `by_file` grouping, `rules`, and `overrides`. Returns `Vec<MatchEvent>` along with `active_rule_ids` (updated). This phase is complex due to closure interactions with `per_rule_events`, but must be extracted to meet the 100-line limit.

3. **`collect_findings()`** — Extracts Phase 3 (findings collection loop). Takes sorted `events`, `rules`, `prepared_lines`, `max_findings`, and mutable `per_rule_hits`. Returns `(Vec<Finding>, VerdictCounts, u32, BTreeMap<String, RuleHitStat>)`.

The main function signature remains unchanged (preserving public API compatibility). Only private (`fn`) helpers are extracted.

## Consequences

### Tradeoffs
- **Benefit**: Function drops from ~201 lines to ~80–90 lines, passing clippy's `too_many_lines` check
- **Benefit**: Each phase becomes independently testable
- **Benefit**: Follows existing decomposition pattern already established in the file
- **Risk**: Phase 2 extraction is complex due to closure interactions with `per_rule_events` and inline dependency resolution
- **Risk**: The three-helper approach requires careful handling of mutable state (preprocessors, suppression tracker)

### Alternatives Considered

1. **Extract only 2 helpers (Phase 1 + Phase 3)** — Rejected because Phase 2 (~80 lines) would remain, leaving the function at ~115 lines, still exceeding the 100-line limit.

2. **Extract Phase 2 into a struct with methods** — Considered but adds unnecessary abstraction. The closure-heavy nature of Phase 2 makes this refactoring high-effort without proportional benefit.

3. **Do nothing (accept the violation)** — Rejected because the clippy lint fails CI, blocking merges.

## Alternatives

| Alternative | Rejected Because |
|-------------|-----------------|
| Extract only phases 1 & 3 | Leaves ~115 lines, still over limit |
| Phase 2 as struct with methods | Adds complexity without proportional benefit |
| Accept clippy violation | Fails CI, blocks merges |
