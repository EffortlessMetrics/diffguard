# Security Review: Baseline/Grandfather Mode (work-5a1ff6f4)

**Date:** 2026-04-08
**Branch:** `feat/work-5a1ff6f4/add-baseline-grandfather-mode`
**Feature:** `--baseline` CLI flag for enterprise adoption
**Review Type:** Pattern scan (not penetration test)

---

## Executive Summary

| Category | Status |
|----------|--------|
| Vulnerabilities found | 0 |
| `cargo audit` | Clean (0 advisories) |
| `cargo clippy` | Clean (warnings only in test code) |
| Recommendation | **PASS** |

---

## Review Scope

The security review focused on the new baseline mode implementation:
- `crates/diffguard/src/main.rs` (new functions at lines 1528-1720, integration at 2386-2434)
- `crates/diffguard-analytics/src/lib.rs` (`fingerprint_for_finding`, `baseline_from_receipt`)

---

## Security Checks Performed

### 1. Command Injection
**Status:** PASS

All `Command::new("git")` invocations use hardcoded string literals:
- Line 926-928: `git --version`
- Line 934-937: `git --version`
- Line 949-951: `git rev-parse --is-inside-work-tree`
- Line 1776-1778: `git blame --line-porcelain`
- Line 3059-3061: `git diff --unified=<N>`

No user-supplied input is passed to any subprocess. The `--baseline <PATH>` argument is used only for reading a JSON file (not as a command argument).

### 2. Path Traversal
**Status:** PASS

Baseline file path handling:
```rust
// Line 1529-1530
if !path.exists() {
    bail!("baseline receipt not found: {}", path.display());
}
let text = std::fs::read_to_string(path)...
```

- Uses `std::fs::read_to_string` directly (not passed to shell)
- File existence is checked before reading
- Path comes from CLI `--baseline` argument (controlled by user but I/O-bound, not execution)
- No `Path::new(user_input).join(untrusted)` patterns found in this feature

### 3. Panic on User Input
**Status:** PASS (for production code)

Baseline receipt parsing:
```rust
// Line 1535-1536
let receipt: CheckReceipt = serde_json::from_str(&text)
    .with_context(|| format!("parse baseline receipt {}", path.display()))?;
```

- Uses `serde_json::from_str` with proper `Result` handling via `?`
- Schema version validation at line 1539-1545 returns a proper error (not panic)
- No `.unwrap()` or `.expect()` on user-controlled data in production paths

Note: Test code (lines 3173, 3182, 3191-3192, etc.) uses `.expect()` but these are test helpers, not production code.

### 4. Unsafe Code
**Status:** PASS

The `unsafe {}` blocks in `main.rs` are:
- All in test code only (testing environment variable manipulation)
- No `unsafe` in the baseline mode production code path
- No raw pointer access, extern calls, or unsafe memory operations

### 5. Resource Exhaustion
**Status:** PASS

Fingerprint computation:
```rust
// Line 1548-1552 (diffguard-analytics/src/lib.rs:68-73)
let input = format!("{}:{}:{}:{}", finding.rule_id, finding.path, finding.line, finding.match_text);
let hash = Sha256::digest(input.as_bytes());
hex::encode(hash)
```

- SHA-256 output is fixed 32-byte hash → 64 hex characters
- No unbounded loops over user input
- `BTreeSet<String>` with SHA-256 fingerprints (bounded by findings count)
- No memory allocation from untrusted input size concerns

### 6. Dependency Vulnerabilities
**Status:** PASS

```
cargo audit:
Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
  Loaded 1029 security advisories
  Updated crates.io index
  Scanning Cargo.lock for vulnerabilities (286 crate dependencies)
```

No vulnerabilities found.

### 7. Information Leakage
**Status:** PASS

Error messages (line 1530, 1534, 1536):
```rust
bail!("baseline receipt not found: {}", path.display());
bail!("incompatible baseline schema version '{}'; expected '{}'", ...);
```

- `path.display()` exposes the file path provided by the user (acceptable)
- Schema mismatch shows expected version (not sensitive internal paths)
- No version numbers, internal config, or credentials leaked

---

## Baseline Mode-Specific Security Analysis

### Fingerprint Computation
```rust
// crates/diffguard-analytics/src/lib.rs:67-73
pub fn fingerprint_for_finding(finding: &Finding) -> String {
    let input = format!("{}:{}:{}:{}", finding.rule_id, finding.path, finding.line, finding.match_text);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}
```

- Uses SHA-256 (collision-resistant) for fingerprinting
- Input is all Finding fields (owned by the tool, not user-supplied content)
- No timing or length-based side channels

### JSON Input Handling
The baseline receipt is parsed via `serde_json` with:
1. Schema version validation
2. Proper error handling via `?` operator
3. No deserialization of user code or dynamic execution

---

## Clippy Results

```
cargo clippy --all-targets --all-features
warning: variable does not need to be mutable
   --> crates/diffguard/tests/baseline_mode_properties.rs:106:13

warning: unused variable: `output`
   --> crates/diffguard/tests/baseline_mode_snapshots.rs:188:9

warning: function `create_baseline_from_first_run` is never used
  --> crates/diffguard/tests/baseline_mode_snapshots.rs:70:4
```

All warnings are in **test code only**, not production. No security-relevant issues.

---

## Failed Tests Context (from prior agent)

The prior agent reported 6 failing baseline mode tests. These are **functional/behavioral failures**, not security vulnerabilities:
- Exit code handling differences in baseline mode
- Markdown annotation display issues
- These do not indicate security flaws

---

## Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 0 | |
| High | 0 | |
| Medium | 0 | |
| Low | 0 | |

---

## Recommendation

**PASS** — The baseline/grandfather mode implementation is security-clean for the patterns checked:

1. No command injection vectors (all subprocess calls use hardcoded commands)
2. No path traversal issues (file read is I/O-bound, not executed)
3. No panic on user input (proper error handling with `?`)
4. No unsafe code in production paths
5. No resource exhaustion concerns (bounded SHA-256 fingerprints)
6. No dependency vulnerabilities (`cargo audit` clean)
7. No information leakage in error messages

The implementation follows safe Rust patterns and is ready for deep review.

---

## Notes for Deep Review

- Test code contains some `.expect()` calls for test setup; these are isolated to test helpers
- The 6 failing tests (from prior agent `green_test_output`) should be investigated as they may indicate logic bugs but not security vulnerabilities
- Consider running the full test suite to verify baseline mode behavior before shipping
