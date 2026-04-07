# Deep Review: Doctor Subcommand

**Work ID:** work-fe471ba3
**Gate:** HARDENED
**Reviewer:** deep-review-agent
**Date:** 2026-04-07

---

## Overall Assessment

The doctor subcommand is well-implemented and functionally correct. The refactoring from the earlier code-quality review has already addressed the major structural concerns: nesting depth has been reduced, duplicated validation logic has been extracted into a shared `validate_config_rules()` function, and the early-return inconsistencies have been resolved. All 19 integration tests pass. The code is formatting-clean and has zero clippy warnings.

However, I identified one significant issue in the test suite and a few minor observations.

---

## What's Done Well

1. **Clean architectural separation** — The extraction of `validate_config_rules(cfg: &ConfigFile) -> Vec<String>` as a shared function is excellent. It eliminates the ~80-line duplication that existed before and ensures both `cmd_validate` and `cmd_doctor` check the same rule properties consistently (duplicate IDs, regex validity, glob validity, dependency references, multiline_window constraints, and compilation).

2. **`validate_config_for_doctor()` helper** — This extracted function uses flat early-return guard clauses instead of the original 6+-level deep nesting. The `explicit_config: bool` parameter cleanly distinguishes the "no config expected" case from "config specified but missing."

3. **Comprehensive check coverage** — The doctor command validates three things a user would care about:
   - Git binary availability (with version string displayed)
   - Whether the current directory is inside a git repository
   - Config file existence and rule validity

4. **Consistent exit codes** — Returns 0 when all checks pass, 1 when any check fails. Matches the `cmd_validate` convention.

5. **Test suite breadth** — 19 tests cover: existence, git pass/fail, git-repo pass/fail, valid config, invalid config (bad regex), missing config with defaults, --config with missing file, --config with valid file, help completeness, duplicate rule IDs, all-checks-run-even-if-one-fails, unicode/spaces in paths, and multiple simultaneous issues.

6. **Formatting and clippy clean** — Confirmed via `cargo fmt --check` and `cargo clippy -p diffguard` in this review.

---

## Concerns and Findings

### Finding 1: Tests using `[[rules]]` (plural) instead of `[[rule]]` (singular) — MEDIUM

**Location:** `crates/diffguard/tests/doctor.rs`, lines 128-138, 229-234, 388-394

These three test cases use `[[rules]]` (plural) in their TOML, but the `ConfigFile` struct field is `rule` (singular, defined at `diffguard-types/src/lib.rs:201`). Since serde is not using an alias, `[[rules]]` is silently ignored and results in 0 rules being defined.

**Affected tests:**
- `doctor_with_valid_config_passes` (line 124) — passes with 0 rules regardless of correctness
- `doctor_config_flag_valid_file_passes` (line 221) — passes with 0 rules regardless of correctness
- `doctor_config_path_with_spaces_and_unicode` (line 376) — passes with 0 rules regardless of correctness

These tests are not actually validating *any* rules because 0 rules means there's nothing to validate. They pass trivially. Tests that use `[[rule]]` (singular) such as `doctor_with_invalid_config_fails` and `doctor_handles_duplicate_rule_ids` are correctly exercising the validation logic.

**Impact:** Low risk to the implementation itself, but these three tests create false confidence. If someone introduces a regression in config validation for properly-formed rule arrays, these tests would still pass.

**Recommendation:** Change `[[rules]]` to `[[rule]]` in the three affected test cases to ensure they actually exercise the rule validation path. This is a test file fix.

*(Note: The refactor summary notes the test file was not modified due to constraints, but this is a distinct issue from the stale RED comment.)*

### Finding 2: Stale test header comment — COSMETIC

**Location:** `crates/diffguard/tests/doctor.rs`, lines 1-4

The module doc comment says "These are RED tests — they define expected behavior but will fail because the `doctor` command has not been implemented yet." This is outdated since the implementation exists and 19/19 tests pass. Minor, but worth updating.

### Finding 3: Git error message could be more precise — LOW

**Location:** `crates/diffguard/src/main.rs`, line 898

```rust
println!("git: FAIL (git not found)");
```

This message is printed when `git --version` fails, but the failure could be due to permission issues, a corrupted binary, or other execution errors — not just "not found." The current test `doctor_reports_git_repo_fail_outside_repo` only tests the "not in a repo" scenario, not the "git missing" scenario. A more accurate message would be `"git --version failed"` or `"git not available"`.

**Impact:** Minimal — in practice, "git not found" is the overwhelmingly common case.

### Finding 4: No test for git binary actually missing — LOW

There is no test that simulates git being absent from PATH. This is understandable (hard to mock without significant infrastructure), but it's worth noting as a potential gap. A future improvement could use a modified PATH or a mock git binary.

### Finding 5: Env var expansion in doctor config validation — INFORMATIONAL

The `validate_config_for_doctor()` function calls `expand_env_vars()` before parsing TOML. This is consistent with how `cmd_validate` processes configs, which is correct. However, config file includes (`[includes]`) are not resolved during doctor validation — only the top-level file is parsed. This means `doctor` won't catch issues in included config files, while `check` would. This is a reasonable design choice for doctor (it's a quick health check, not a full validation), but could be documented.

---

## Edge Cases Checked

| Scenario | Covered? | Notes |
|----------|----------|-------|
| Git available | ✅ | Tested |
| Git missing | ⚠️ | Hard to test; no mock infrastructure |
| In git repo | ✅ | Tested |
| Not in git repo | ✅ | Tested |
| No config file (defaults) | ✅ | Tested |
| Explicit --config, file missing | ✅ | Tested |
| Explicit --config, valid file | ✅ | Tested |
| Invalid regex in config | ✅ | Tested |
| Duplicate rule IDs | ✅ | Tested |
| Multiple issues at once | ✅ | Tested |
| Unicode/spaces in config path | ✅ | Tested |
| All checks run even if one fails | ✅ | Tested |
| Help text completeness | ✅ | Tested |
| Config with `[includes]` | ⚠️ | Includes not validated (by design) |
| Empty `[rule]` array | ✅ | Implicitly covered (no errors, passes) |
| Config parse errors (bad TOML) | ✅ | Covered by file read error path |

---

## Recommendation: **approve-with-notes**

The implementation is solid, well-refactored, and functionally correct. The shared extraction of `validate_config_rules()` is a significant improvement. Three test cases use the wrong TOML table name (`[[rules]]` vs `[[rule]]`) which means they silently pass without testing any rule validation — these should be corrected. The stale test header comment should be updated. Neither of these are blockers for the `cmd_doctor` implementation itself, but they reduce test confidence.
