# Code Quality Review: Doctor Subcommand

**Work ID:** work-fe471ba3
**Gate:** HARDENED
**Reviewer:** code-quality-agent
**Date:** 2026-04-07

---

## Clippy Results

**Status: PASS — No warnings**

`cargo clippy -p diffguard` completed with zero warnings. The code passes clippy clean.

---

## Formatting Check Results

**Status: FAIL — Needs `cargo fmt`**

`cargo fmt --check` found formatting issues in two files:

### crates/diffguard/src/main.rs
- Lines 891-894: Multi-line match arm should be collapsed to a single line
- Lines 932-936: `config_errors.push(format!(...))` call should be collapsed to a single line with `config_errors.push(format!("Rule '{}': duplicate rule ID", rule.id))`
- Lines 943-948: Same issue for "no patterns defined" error message
- Lines 1009-1012: `println!` for config FAIL should be collapsed to a single line

### crates/diffguard/tests/doctor.rs
- Numerous asserts with inline `stdout.contains("..."), "msg:\n{}", stdout` should be reformatted to multi-line form per project convention
- Lines 351-355: The three-way `stdout.contains("Usage:") || ... || ...` condition should span multiple lines

These are all mechanical formatting issues that `cargo fmt` will fix automatically.

---

## Code Quality Findings

### 1. Stale/Incorrect Test Documentation (MEDIUM)

**Location:** `crates/diffguard/tests/doctor.rs`, lines 1-4

The test file header says:
```
//! These are RED tests — they define expected behavior but will fail
//! because the `doctor` command has not been implemented yet.
```

This is incorrect — the command IS implemented and all 19 tests pass. This is a copy-paste artifact that should have been updated or removed.

### 2. `cmd_doctor` Has Significant Nested Structure (MEDIUM)

**Location:** `crates/diffguard/src/main.rs`, lines 870-1038

The `cmd_doctor` function spans ~170 lines with 6+ levels of nesting in the config validation section (lines 911-1036):

```
fn cmd_doctor -> Result<i32>
  if git_available { ... } else { ... }
  if in_git_repo { ... } else { ... }
  if let Some(ref path) = config_path {
    match std::fs::read_to_string(path) {
      Ok(text) =>
        match expand_env_vars(&text)
          match toml::from_str(&expanded)
```

By contrast, `cmd_validate` (lines 691-868) uses early returns with `bail!()` and `?` operator to keep nesting at 3 levels maximum. `cmd_doctor` could be significantly simplified by extracting helper functions.

### 3. Magic Return Pattern (MEDIUM)

**Location:** `crates/diffguard/src/main.rs`, line 920

```rust
return if all_pass { Ok(0) } else { Ok(1) };
```

This early return on line 920 (inside the `expand_env_vars` error path) exits the entire function immediately, but `all_pass` is already set to `false` at that point — the return becomes `Ok(1)` regardless. This is functionally correct but creates a subtle code path that differs from the standard fall-through logic where other checks would continue. Other error paths in the same function do NOT early-return — they set `all_pass = false` and fall through. This inconsistency is confusing:

- expand_env_vars error: early return (line 920)
- TOML parse error: fall through to line 1016-1018
- File read error: fall through to line 1022-1025

### 4. Inconsistent Pattern Usage with `cmd_validate` (LOW)

`cmd_doctor` duplicates the entire config validation logic from `cmd_validate` (approximately lines 715-800 replicated in lines 927-999), with one notable omission:

- `cmd_validate` checks `multiline_window must be >= 2` (lines 767-772)
- `cmd_validate` has strict-mode warnings (lines 803-820)
- `cmd_validate` uses `info!()` and `debug!()` logging calls
- `cmd_doctor` has no logging

This code duplication is intentional given the different output format (doctor reports PASS/FAIL per check vs validate reports structured lists), but the overlap is substantial. If rule validation logic changes in one place, it must be manually updated in the other.

### 5. Missing Validation in `cmd_doctor` (LOW)

`cmd_validate` checks `exclude_paths` globs (lines 975-981 in main.rs via the glob validation loop in doctor). `cmd_doctor` does validate glob patterns for `paths` and `exclude_paths`, but it's missing the `multiline_window` check that `cmd_validate` has.

### 6. Variable Naming (LOW)

- `git_check` and `git_repo_check` — these names are slightly inconsistent. `git_check` produces an `Output` from `git --version`, `git_repo_check` produces an `Output` from `git rev-parse`. Both are subprocess results. Slightly better names would be `git_version_output` and `git_repo_output` to clarify what is being checked.
- `in_git_repo` as a variable name is good.
- `config_path` followed by `if let Some(ref path)` — the shadowing from `config_path` to `path` is clear.

### 7. Error Message in Git Availability Check (LOW)

**Location:** line 883
```rust
println!("git: FAIL (git not found)");
```

This prints "git not found" even when git exists but fails to execute successfully (e.g., permission denied). A more accurate message would be `git: FAIL (git --version failed)`.

### 8. Unnecessary `.clone()` on `args.config` (COSMETIC)

**Location:** line 906
```rust
let config_path = args.config.clone().or_else(|| { ...
```

Since `DoctorArgs` derives `Debug` but not `Clone`, and `args.config` is only used once, the `.clone()` is redundant here. However, `args` is moved in the function signature, so no clone is actually needed — this could just be `args.config.or_else(...)`.

---

## Recommendations

### Must Fix (Before Merge)

1. **Run `cargo fmt`** — Both `main.rs` and `doctor.rs` need formatting to match project style.

2. **Fix the stale test comment** in `crates/diffguard/tests/doctor.rs` lines 1-4. Update or remove the RED test header comment.

### Should Fix (Improvement)

3. **Extract config validation logic** into a helper function (e.g., `validate_config_rules(cfg: &ConfigFile) -> Vec<String>`) shared between `cmd_doctor` and `cmd_validate`. This eliminates ~80 lines of duplicated logic and ensures consistency.

4. **Fix the early return inconsistency** — Either make all error paths in `cmd_doctor` early-return, or make them all fall-through. The current mix is confusing.

5. **Improve the "git not found" error message** to be more precise.

### Nice to Have

6. Consider adding `info!`/`debug!` logging to `cmd_doctor` for consistency with other commands.

7. Consider adding the missing `multiline_window` validation check from `cmd_validate`.

---

## Summary

The doctor subcommand implementation is functionally complete with solid test coverage (19 tests, all passing). The primary issues are mechanical (formatting), a stale comment, and code structure (deep nesting, duplicated validation logic). The code follows established patterns for the Commands enum, Args struct, and exit code conventions. No clippy warnings were found.
