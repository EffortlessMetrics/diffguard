# Plan: Fix Env Var Expansion Output Sanitization (Issue #114)

## Goal
Sanitize output when environment variable expansion is used in config.

## Context
- Issue: `Environment variable expansion in config files lacks output sanitization` (#114)
- Currently: `${VAR}` or `${VAR:-default}` expanded in config values
- Risk: Expanded values containing special characters could cause injection issues in output

## Approach
1. Review where env var expansion happens (config parsing in diffguard-domain or diffguard CLI)
2. Sanitize expanded values before they enter rule engine
3. Add tests for injection attempts via env vars

## Steps
1. Trace env var expansion flow through codebase
2. Identify injection points (output formats that render user data)
3. Add sanitization layer
4. Add test cases for injection attempts

## Files Likely to Change
- Config parsing/loading code (likely in diffguard CLI or domain)
- Output rendering (markdown, SARIF, etc.)

## Tests
- Env var with newlines, control chars, XML special chars
- Verify sanitized output

## Risk
Medium — must ensure legitimate special chars in env vars are handled gracefully.

## Open Questions
- What characters need sanitization?
- Should we warn or strip?
