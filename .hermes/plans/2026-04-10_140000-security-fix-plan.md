# Plan: Security Fixes — ReDoS + Env Injection + Path Traversal

## Goal
Fix three security issues identified in the v0.2 branch scanning:
1. ReDoS vulnerability in user-supplied regex patterns (#115)
2. Env var expansion injection in config files (#114)
3. Config path traversal via `..` components (#112)

## Context / Assumptions
- v0.2 roadmap is effectively complete (all phases marked complete)
- Branch `feat/v0.2-enhancements-v2` was already merged (PR #5)
- These are pre-existing security gaps that should be addressed before release
- Security fixes are quick wins with high impact

## Approach
Fix each issue in the appropriate crate, add tests, run full CI

## Step-by-Step

### 1. ReDoS Protection (#115)
**File:** `crates/diffguard-domain/src/rules.rs`
**Change:** Wrap regex compilation with complexity analysis using `regex-syntax`
- Pre-validate patterns for known dangerous constructs (nested quantifiers, etc.)
- Add `fanroy` crate for time-limited regex matching in `first_match`
- Add max input length check before applying regex

### 2. Env Var Injection (#114)
**Files:** 
- `crates/diffguard/src/main.rs` (`expand_env_vars`)
- `crates/diffguard-lsp/src/config.rs` (`expand_env_vars`)
**Change:** Escape TOML-special characters in env var values before substitution
- Only allow safe characters, or escape `\"`, `\n`, `${`, etc.
- Validate expanded output before TOML parse

### 3. Config Path Traversal (#112)
**File:** `crates/diffguard-lsp/src/config.rs` (`resolve_config_path`)
**Change:** After joining paths, canonicalize and verify result starts with workspace root
- Use the fix pattern suggested in issue:
```rust
let joined = workspace_root.join(candidate);
let canonical = joined.canonicalize()?;
if !canonical.starts_with(workspace_root) {
    bail!("config path escapes workspace root");
}
```

### 4. CI: Add cargo-audit (#107)
**File:** `.github/workflows/ci.yml`
**Change:** Add `security` job that runs `cargo audit`
- Should fail on CVSS ≥ 7.0 vulnerabilities

## Files Likely to Change
- `crates/diffguard-domain/src/rules.rs` — regex safety
- `crates/diffguard-domain/src/evaluate.rs` — first_match timeout
- `crates/diffguard/src/main.rs` — env var sanitization
- `crates/diffguard-lsp/src/config.rs` — path validation + env sanitization
- `Cargo.toml` — add `fanroy` dependency
- `.github/workflows/ci.yml` — add cargo-audit job

## Tests
- Add unit tests for env var escaping (malicious values)
- Add unit tests for path traversal (with mock workspace)
- Add unit tests for regex complexity rejection

## Verification
```bash
cargo test --workspace
cargo clippy --workspace
cargo fmt --check
cargo run -p xtask -- ci
```

## Risks & Open Questions
- fanroy may add latency to every regex match — benchmark if significant
- Env var escaping may break legitimate use cases (need careful allowlist vs denylist)
- Canonicalize can be expensive — consider caching workspace root canonical path
