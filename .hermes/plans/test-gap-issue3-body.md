## Problem

The `DirectoryRuleOverride` system (`crates/diffguard-domain/src/overrides.rs`) and suppression directives (`crates/diffguard-domain/src/suppression.rs`) are core diffguard features, but they lack property-based test coverage. The existing tests in `crates/diffguard-domain/tests/properties.rs` cover error-chain propagation for these modules but not the actual evaluation logic.

## Scope

**In scope:**
- `crates/diffguard-domain/src/overrides.rs` — DirectoryRuleOverride, OverrideCompiler
- `crates/diffguard-domain/src/suppression.rs` — SuppressionEngine, parse_suppression

**Out of scope:**
- No production code changes — purely test gap

## Missing Tests

### DirectoryRuleOverride property tests

The overrides system has ~310 lines and multiple complex behaviors:
- Path normalization and directory matching
- Include/exclude glob interaction
- Priority/precedence when multiple overrides match
- Root directory override applying everywhere

**What tests should cover:**
- Generator: arbitrary (override spec, path to resolve)
- Property: override resolves to correct ResolvedRuleOverride for matching paths
- Property: exclude_paths correctly excludes within override directory
- Property: non-matching paths get `OverrideDecision::None`
- Property: priority order: more-specific directory overrides take precedence
- Edge: path normalization handles `..`, `.`, double slashes, trailing slashes
- Edge: empty directory spec in override

### SuppressionEngine property tests

The suppression system parses `diffguard: ignore <rule_id>` directives from both clean lines and masked comment content.

**What tests should cover:**
- Generator: arbitrary (line content, language, rule_id to test)
- Property: `is_suppressed(rule_id)` returns true when directive present, false otherwise
- Property: wildcard `*` suppresses all rules
- Property: suppression resets at file boundary
- Property: directive in comment is detected when `ignore_comments=true`
- Property: directive NOT in comment is NOT detected when `ignore_comments=false`
- Edge: `diffguard:ignore rust.no_unwrap` with extra whitespace
- Edge: multiple rule IDs in single directive

## Acceptance Criteria

- [ ] Property tests for DirectoryRuleOverride resolution with path normalization
- [ ] Property tests for override precedence/priority ordering
- [ ] Property tests for SuppressionEngine.is_suppressed across languages
- [ ] Property tests for wildcard suppression
- [ ] Tests use `proptest!` with 100+ cases

## Affected Crate
- diffguard-domain