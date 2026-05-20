# ADR — work-fd603479: Redundant Match Arm in string_syntax()

## Title
Keep YAML/TOML Explicit in string_syntax(); JSON Already Removed via Wildcard

## Status
Accepted

## Context

GitHub issue #470 reported a `clippy::identical_match_arms` lint warning at `preprocess.rs:107`, claiming the match arm `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` was redundant because the wildcard arm `_ => StringSyntax::CStyle` already covered these cases.

However, investigation revealed:
1. **JSON was already removed** from the explicit arm (commit `9826fd3` on `main`)
2. **YAML and TOML must remain explicit** per regression tests in `red_tests_work_5d83e2c9.rs`
3. The issue title ("wildcard already covers Yaml/Toml/Json") was **stale** — it no longer matched the codebase state

## Decision

The codebase has already resolved the original issue:
- `Language::Json` is handled by the wildcard `_ => StringSyntax::CStyle` (no explicit arm)
- `Language::Yaml | Language::Toml` remain as an explicit match arm

The explicit arm for YAML/TOML is **intentionally preserved** because:
1. Regression test `yaml_and_toml_have_explicit_arms_not_wildcard()` explicitly validates YAML/TOML have explicit handling
2. Semantic grouping in `comment_syntax()` (`Language::Yaml | Language::Toml => CommentSyntax::Hash`) suggests architectural intent
3. Explicit arms document language-specific grouping even when values are identical to wildcard

**No code change is required.** The issue is effectively already resolved.

## Consequences

### Benefits
- No behavioral changes to production code
- Regression tests pass without modification
- Semantic grouping preserved for maintainability

### Tradeoffs
- The lint warning in the issue title cannot be fully addressed for YAML/TOML without breaking regression tests
- If lint fires in strict mode (`cargo clippy -- -W clippy::restriction`), YAML/TOML would still trigger it

## Alternatives Considered

### 1. Remove YAML/TOML explicit arm (REJECTED)
- Would eliminate the lint warning entirely
- **Rejected because**: Regression test `yaml_and_toml_have_explicit_arms_not_wildcard` explicitly forbids this, and maintaining symmetry with `comment_syntax()` grouping is architecturally meaningful

### 2. Close as "works as intended" (CHOSEN)
- JSON removed, YAML/TOML kept explicit
- **Chosen because**: Matches existing codebase state, regression tests validate this behavior, and architectural intent is preserved

## References
- Issue: #470 (stale — title no longer matches reality)
- Regression tests: `crates/diffguard-domain/tests/red_tests_work_5d83e2c9.rs`
- Related: `comment_syntax()` uses same `Yaml | Toml` grouping pattern
