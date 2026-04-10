# Plan: Fix Security Issues in diffguard v0.2

## Goal

Fix three security issues filed as v0.2 post-PR #5 work items:
1. **#115** — User-supplied regex patterns lack complexity/timing attack protection
2. **#114** — Environment variable expansion in config files lacks output sanitization
3. **#112** — Config path traversal: relative override paths with `..` components are not validated

## Current Context / Assumptions

- PR #5 (feat/v0.2-enhancements-v2) merged 2026-04-09
- Branch: `feat/work-8d7001a2/verify-parallel-pipeline` (currently on stack, not the v0.2 branch)
- Build passes, all tests pass (59 unit + integration tests)
- All phases 1-9 of ROADMAP.md marked complete
- These security issues are new findings from post-merge review

## Security Analysis

### #115 — Regex Complexity/Timing Attack

**Issue:** User-supplied regex patterns in `diffguard.toml` are compiled and run against diff lines. Malicious patterns (e.g., `(a+)+`) can cause catastrophic backtracking, causing CPU exhaustion.

**Affected code:** Pattern compilation in `diffguard-domain/src/rules.rs` and `diffguard-domain/src/evaluate.rs`

**Fix approach:** Use `regex-syntax` to analyze patterns for known-bad constructs (nested quantifiers, overlapping alternatives) at rule compile time. Alternatively, use the `nfadfa` crate or a timeout-wrapped regex executor.

### #114 — Env Var Expansion Output Sanitization

**Issue:** Config env expansion (`${VAR}`) outputs raw values into command arguments, file paths, or regex patterns. If a var contains special characters (`";`, newlines, `$()`), it could cause injection.

**Affected code:** Environment variable expansion in config loading (`diffguard/src/config.rs` or similar)

**Fix approach:** Sanitize expansion output — escape or reject special shell characters when env vars are used in contexts that could trigger injection.

### #112 — Path Traversal in Override Paths

**Issue:** Directory override paths with `..` components are not validated. A config could reference `../../../etc/passwd` or similar.

**Affected code:** `diffguard-domain/src/overrides.rs` (new in PR #5) — path resolution for per-directory `.diffguard.toml` lookup

**Fix approach:** Validate override paths: canonicalize and confirm the result is under the repo root. Reject any `..` traversal that escapes the intended scope.

## Proposed Approach

### Common Pattern
1. For each issue, add a test that reproduces the vulnerability (failing case)
2. Implement the fix
3. Verify fix with the test + existing test suite

### Step-by-Step Plan

**For #115 (Regex):**
1. Add `regex-syntax` crate as dependency (already a transitive dep via `regex`)
2. Write a regex safety checker in `diffguard-domain/src/rules.rs` that runs at compile time
3. Check for: nested quantifiers (`+*+`, `*+`), overlapping alternatives (`(a|a)+`), empty alternatives
4. Return a `RuleCompileError` with actionable message if unsafe pattern detected
5. Add fuzz target case + unit test

**For #114 (Env Sanitization):**
1. Identify all expansion sites in config loading
2. Add a sanitizer function that strips/escapes shell metacharacters: backtick, `$()`, `;`, `|`, `&`, `<`, `>`, newlines, null
3. Apply sanitization to expansion output
4. Add integration test with malicious env var values

**For #112 (Path Traversal):**
1. In `overrides.rs`, use `std::fs::canonicalize` or equivalent to resolve paths
2. Verify resolved path is under the repo root (prevent `..` escape)
3. Reject config files that reference paths outside allowed scope
4. Add unit test with `..` path attempts

## Files Likely to Change

| File | Change |
|------|--------|
| `diffguard-domain/src/rules.rs` | Add regex safety checker at compile time |
| `diffguard-domain/src/evaluate.rs` | Wire regex timeout/depth limits |
| `diffguard/src/config.rs` | Add env var sanitization |
| `diffguard-domain/src/overrides.rs` | Add path traversal validation |
| `Cargo.toml` (diffguard-domain) | Add `regex-syntax` dep |
| Test files | Add security regression tests |

## Tests / Validation

1. **Unit tests** for each fix (co-located in source files)
2. **Property tests** via existing fuzz targets
3. **Regression test** for each original issue report
4. `cargo test --workspace` passes
5. `cargo clippy --workspace --all-targets -- -D warnings` clean

## Risks and Tradeoffs

- **Regex safety checker** may have false positives (rejecting some valid but complex patterns). Can make it a warning instead of hard error, or allow a config flag to opt out.
- **Path canonicalization** requires filesystem access — but this is acceptable since overrides already load files from disk.
- **Env sanitization** may break legitimate use cases (e.g., a regex containing `$`). Need to be context-aware: different sanitization for file paths vs. regex patterns vs. CLI args.

## Open Questions

1. Should regex safety be a hard error (fail compilation) or a warning + allow-unsafe config flag?
2. Should env var sanitization be applied universally or only in specific contexts (CLI output vs. config processing)?
3. Should the path traversal fix be applied retroactively to existing configs, or only new override configs?
