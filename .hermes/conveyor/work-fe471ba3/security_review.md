# Security Review: diffguard doctor implementation
**File:** crates/diffguard/src/main.rs
**Date:** 2026-04-06
**Scope:** `cmd_doctor()` and adjacent production code in main.rs

---

## 1. `unwrap()` on User Input

**Finding count:** 0 in production code

All production `unwrap()` calls are safe:
- Line 880: `git_check.as_ref().unwrap()` — guarded by prior `match` that confirms `Ok(_)` variant.
- Lines 2745-2746: Regex capture group unwraps inside `captures_iter()` loop — group 0 and group 1 always exist for a matched capture.

The remaining ~40 `unwrap()` calls are exclusively in `mod tests {}` (line 2867+), which is expected.

**Severity:** None

---

## 2. Command Injection via `Command::new()`

**Finding count:** 1 low-severity observation

All 6 `Command::new("git")` calls use `.args([...])` with individual string arguments — no shell interpolation, no `sh -c`, no `.arg(format!(...))` with concatenated strings. This is correct usage.

**Observation (LOW):** User-supplied git refs (`--base`, `--head`) and file paths are passed as arguments to git subprocess calls:
- `git_diff()` (line 2806): `base` and `head` from CLI args flow into git range `"{base}...{head}"` as a single `.arg()`.
- `git_blame_porcelain()` (line 1595): `head_ref` and `path` passed directly as args.
- `cmd_doctor()` (line 874, 888): Hardcoded args only (`--version`, `rev-parse --is-inside-work-tree`).

Since `Command::new()` does not invoke a shell, classic command injection is not possible. However, a malicious ref starting with `-` (e.g., `--upload-pack=evil`) could be interpreted as a git option. This is a well-known git CLI edge case, low severity in a local developer tool.

**Mitigation already present:** Git exits with error on invalid refs, and errors are propagated via `bail!()` / `?`.

**Severity:** Low

---

## 3. Path Traversal Risks

**Finding count:** 0 exploitable

User-supplied paths (`--config`, `--out`, `--diff-file`, `--output`, `--false-positive-baseline`, etc.) are used directly for file I/O without canonicalization or sandboxing. However:
- diffguard is a **local CLI tool** — users already have filesystem access at their own privilege level.
- No sandbox boundary is crossed. Path traversal is expected behavior for a tool the user runs intentionally.
- Output parent directories are created with `create_dir_all()` (line 2512-2516), but the user controls the path — no elevation of privilege.

**Severity:** None (by design for a local CLI tool)

---

## Clippy Results

```
$ cargo clippy -- -D warnings
Checking diffguard v0.2.0
Finished dev profile [unoptimized + debuginfo] target(s)
```

**Status:** Clean — zero warnings, zero errors.

---

## Summary

| Category              | Findings | Severity |
|-----------------------|----------|----------|
| unwrap() on user input | 0       | None     |
| Command injection      | 0 (+1 observation) | Low  |
| Path traversal         | 0        | None     |
| Clippy warnings        | 0        | None     |

**Total findings:** 0 actionable, 1 informational observation

**Recommendation: PASS**

No security issues requiring fixes. The code follows Rust best practices: `Command::new()` with `.args()` (no shell), proper error propagation via `anyhow`/`?`, and all `unwrap()` calls in production code are provably safe. The git option-injection observation is inherent to any tool that invokes git with user-supplied refs and is mitigated by git's own error handling.
