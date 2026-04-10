# Plan: Security Fixes — Input Validation & Glob Panic Prevention

## Goal

Address the four security issues filed against v0.2 code:
- Issue #81: Unchecked `.expect()` in `compile_globs` → panic on malformed glob
- Issue #82: No input length limits on diff lines / preprocessed content
- Issue #83: Unbounded memory growth in environment variable expansion
- Issue #84: Include path resolution lacks traversal guard / info leak on canonicalize() error

## Current Context / Assumptions

- All four issues were filed by EffortlessSteven on 2026-04-10 against the current `feat/v0.2-enhancements-v2` branch (which corresponds to PR #5, now merged)
- Build passes, tests pass (504+ tests), clippy passes
- These are pre-existing security debt in the v0.2 release code, not new regressions
- No VISION.md exists — the ROADMAP.md shows v2.0 as "Advanced Features" milestone; these security fixes align with production-readiness hardening

## Proposed Approach

Fix all four in a single security-hardening PR. Each fix is self-contained and low-risk.

### #81 — Replace unchecked `.expect()` in `compile_globs`

**File:** `crates/diffguard-domain/src/rules.rs`
**Line:** ~190

```rust
// Change from:
Ok(Some(builder.build().expect("globset build should succeed")))

// To:
// (compile_globs returns Result<Option<GlobSet>, RuleCompileError> already — the .expect() is the problem)
Ok(Some(builder.build().map_err(|e| RuleCompileError::InvalidGlob {
    rule_id: rule_id.to_string(),
    glob: g.clone(),
    source: e,
})?))
```

Verify `RuleCompileError::InvalidGlob` variant exists and handles `globset::Error`.

### #82 — Add input length limits on diff lines

**Files:** 
- `crates/diffguard/src/main.rs` — CLI boundary (input entry point)
- `crates/diffguard-core/src/lib.rs` — engine entry
- `crates/diffguard-domain/src/preprocess.rs` — `sanitize_line` 
- `crates/diffguard-domain/src/evaluate.rs` — multiline candidate joining

**Approach:**
1. Add a `--max-line-length` CLI flag (default 100KB = 102_400)
2. At the CLI boundary, reject diff lines exceeding the limit before they enter the engine
3. The preprocessor and evaluator already assume reasonable input; add an early bounds check

### #83 — Add bounds to environment variable expansion

**File:** `crates/diffguard/src/env_expand.rs`

**Approach:**
1. Add constants: `MAX_EXPANSION_TOTAL` (1MB), `MAX_VAR_REFS` (1000), `MAX_VAR_VALUE_SIZE` (64KB)
2. Track cumulative expanded length; if exceeded, return `EnvExpandError::ExpansionLimitExceeded`
3. Count variable references per document; if exceeded, return same error
4. Add `EnvExpandError` variant to the enum if not present

### #84 — Include path traversal guard

**File:** `crates/diffguard/src/config_loader.rs`

**Approach:**
1. After `canonicalize()` succeeds, verify the resolved path starts with the expected config root directory
2. If not, return `ConfigError::IncludePathTraversal { included: resolved, root }` — do not expose full path in error
3. Wrap `canonicalize()` errors to avoid leaking full filesystem paths in error messages

## Step-by-Step Plan

1. **Audit `RuleCompileError`** — confirm `#81` fix path (enum variant exists)
2. **Implement `#81`** — replace `.expect()` with proper error mapping
3. **Implement `#82`** — add `MAX_LINE_LENGTH` constant, CLI flag `--max-line-length`, length check at CLI boundary
4. **Implement `#83`** — add bounds constants and counters in `env_expand.rs`, return proper errors
5. **Implement `#84`** — add path traversal check in `config_loader.rs` after canonicalize
6. **Add tests** — for each fix:
   - `#81`: property test with invalid glob
   - `#82`: fuzz test with oversized line
   - `#83`: test with large env var / many refs
   - `#84`: test with symlink traversal attempt
7. **Run** `cargo test --workspace` and `cargo clippy --all-targets` — all must pass
8. **Update CHANGELOG.md** — add under `[Unreleased]` → `### Security`

## Files Likely to Change

| File | Change |
|------|--------|
| `crates/diffguard-domain/src/rules.rs` | `#81` — replace `.expect()` |
| `crates/diffguard/src/main.rs` | `#82` — add `--max-line-length` flag |
| `crates/diffguard-domain/src/preprocess.rs` | `#82` — add length check in `sanitize_line` |
| `crates/diffguard-domain/src/evaluate.rs` | `#82` — bounds on multiline join |
| `crates/diffguard/src/env_expand.rs` | `#83` — add bounds constants and checks |
| `crates/diffguard/src/config_loader.rs` | `#84` — traversal guard + error sanitization |
| `crates/diffguard-types/src/lib.rs` | Add `EnvExpandError` enum variant if needed |
| `CHANGELOG.md` | Document security fixes |

## Tests / Validation

- `cargo test --workspace` — all 504+ tests pass
- `cargo clippy --all-targets --all-features` — zero warnings (existing state)
- New unit tests for each error path:
  - Invalid glob → `RuleCompileError::InvalidGlob`
  - Oversized line → rejection at CLI boundary
  - Unbounded env expansion → `EnvExpandError`
  - Traversal attempt → `ConfigError::IncludePathTraversal`
- Fuzz regression: `cargo +nightly fuzz run preprocess` and `cargo +nightly fuzz run evaluate_lines`

## Risks, Tradeoffs, and Open Questions

- **Risk:** `#82` and `#83` introduce limits that could break existing users with legitimately large diffs or env vars. Mitigation: defaults are generous (100KB line, 1MB total expansion) and can be overridden via CLI flags.
- **Risk:** `#84` path canonicalization happens after reading the file reference; need to ensure the guard check is after canonicalization, not before.
- **Open question:** Should `#82` line length limit be configurable or fixed? Recommendation: fixed with `--max-line-length` override (safer defaults for CI).
- **Tradeoff:** Error message clarity vs. security — for `#84`, avoid leaking full paths in errors even when canonicalize() fails.

## Success Criteria

- All four security issues resolved with tests
- `cargo test --workspace` passes
- `cargo clippy --all-targets --all-features` passes with zero warnings
- CHANGELOG.md updated
- PR created against `main` with all four fixes
