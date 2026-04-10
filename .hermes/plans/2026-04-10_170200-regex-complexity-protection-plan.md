# Plan: User-Supplied Regex Complexity Protection (Issue #115)

## Goal
Protect against regex complexity/timing attacks from user-supplied patterns.

## Context
- Issue: `User-supplied regex patterns lack complexity/timing attack protection` (#115)
- Risk: Malicious regex can cause catastrophic backtracking (ReDoS)
- User provides patterns via `diffguard.toml` config

## Approach
1. Implement regex complexity limits using `fanout` crate or custom solution
2. Add configurable timeout/depth limits for user regex evaluation
3. Document safe pattern guidelines

## Steps
1. Research existing solutions (`re2` crate, `fanout`, regex crate features)
2. Implement complexity-limiter wrapper for user regex
3. Add compile-time and runtime checks
4. Add tests with pathological regex patterns

## Files Likely to Change
- `diffguard-domain/src/rules.rs` (rule compilation)
- New utility module for regex safety

## Tests
- Test with known catastrophic backtracking patterns
- Verify timeout/limit enforcement

## Risk
Medium — may affect performance for complex legitimate patterns. Need graceful degradation.

## Open Questions
- Should this be configurable or always-on?
- What limits are reasonable?
