# Test Coverage Review: Baseline/Grandfather Mode

**Work ID:** work-5a1ff6f4
**Feature:** Baseline/Grandfather Mode for Enterprise Adoption
**Reviewer:** test-reviewer
**Date:** 2026-04-08

---

## Sufficiency Assessment: NEEDS-MORE

The tests exist and cover the acceptance criteria structure, but have **critical correctness issues** that prevent them from validating the feature properly.

---

## Test Execution Summary

```
cargo test -p diffguard --test baseline_mode
```

**Results:** 5 tests pass (error-condition tests), 11 tests fail

**Passing tests (error path validation):**
- `baseline_flag_is_accepted` - Flag parsing works
- `baseline_flag_missing_file_exits_with_code_1` - File not found handling
- `baseline_receipt_invalid_json_exits_code_1` - JSON parse error
- `baseline_receipt_wrong_schema_version_exits_code_1` - Schema validation
- `without_baseline_flag_behavior_unchanged` - Backward compatibility

**Failing tests (functional validation):**
All tests that require actual baseline matching/classification fail due to test fixture issues.

---

## Acceptance Criteria Coverage

### AC1: Baseline Flag
- [x] `CheckArgs` struct includes `--baseline` flag - **IMPLEMENTED**
- [x] Running `diffguard check --baseline /nonexistent/path.json` exits code 1 - **TESTED & PASSING**

### AC2: Baseline Receipt Loading
- [x] Valid baseline receipt JSON is parsed without error - **PARTIALLY TESTED** (passes when JSON is valid)
- [x] Invalid JSON produces exit 1 with parse error message - **TESTED & PASSING**
- [x] Missing file produces exit 1 with "not found" error - **TESTED & PASSING**
- [x] Schema version validation rejects incompatible versions - **TESTED & PASSING**

### AC3: Finding Classification
- [ ] Findings with fingerprints matching baseline are classified as BASELINE - **TEST HAS BUG**
- [ ] Findings with fingerprints NOT in baseline are classified as NEW - **TEST HAS BUG**
- [ ] Fingerprint computation is deterministic - **NOT TESTED**

### AC4: Exit Code - No New Findings
- [ ] When `--baseline` provided and only baseline findings exist, exit code is 0 - **TEST HAS BUG**
- [ ] When `--baseline` provided and no findings at all, exit code is 0 - **TEST HAS BUG**

### AC5: Exit Code - New Findings
- [ ] When `--baseline` provided and new errors exist, exit code is 2 - **TEST HAS BUG**
- [ ] When `--baseline` provided and only new warnings exist, exit code is 3 - **NOT TESTED**

### AC6: Output Annotation
- [ ] Markdown output shows `[BASELINE]` prefix for baseline findings - **TEST HAS BUG**
- [ ] Markdown output shows `[NEW]` prefix for new findings - **TEST HAS BUG**
- [ ] When `--report-mode=new-only`, baseline findings are hidden - **TEST HAS BUG**

### AC7: Backward Compatibility
- [x] Running `diffguard check` WITHOUT `--baseline` behaves identically - **TESTED & PASSING**
- [x] No changes to `run_check()` function or core engine - **NOT CODE REVIEWED**
- [x] All existing exit codes remain unchanged without baseline flag - **TESTED & PASSING**

### AC8: Mutual Exclusivity Documentation
- [ ] `--help` text clarifies that `--baseline` and `--false-positive-baseline` are different - **NOT TESTED**

---

## Critical Issues Found

### Issue 1: Incorrect `match_text` in Test Fixtures (CRITICAL)

**Location:** `baseline_mode.rs` - all tests using `create_baseline_receipt()` or inline baseline findings

**Problem:** The test fixtures use incorrect `match_text` values that don't match what diffguard actually produces.

**Example:**
```rust
// Test baseline has:
"match_text": "Some(1).unwrap()"

// But actual diffguard produces:
"match_text": ".unwrap("
```

**Impact:** Fingerprint comparison fails because fingerprint is computed as SHA-256 of `rule_id:path:line:match_text`. Different `match_text` = different fingerprint = finding classified as "NEW" instead of "BASELINE".

**Evidence:**
```
Test: findings_matching_baseline_are_classified_as_baseline
Expected: exit code 0 (all findings baseline)
Actual: exit code 2 (findings classified as new)
```

**Fix Required:** Test fixtures must use the actual `match_text` values that diffguard produces. To get correct values, run diffguard and inspect the receipt JSON.

### Issue 2: Invalid `DiffMeta` Structure in Test Receipts (CRITICAL)

**Location:** `baseline_mode.rs` lines 67-96 and inline receipts

**Problem:** Test baseline receipts are missing `context_lines` field and use invalid `scope` value.

**Current test receipt:**
```json
"diff": {
    "base": "abc123",
    "head": "def456",
    "scope": "added_and_changed",  // INVALID - not a valid Scope variant
    "files_scanned": 1,
    "lines_scanned": 10
    // MISSING: context_lines
}
```

**Required structure:**
```json
"diff": {
    "base": "abc123",
    "head": "def456",
    "context_lines": 3,  // REQUIRED field
    "scope": "added",     // Valid variant: added, changed, modified, deleted
    "files_scanned": 1,
    "lines_scanned": 10
}
```

**Impact:** Receipt parsing may fail with schema validation errors.

**Note:** Some tests appear to parse successfully, suggesting `context_lines` may have a default, but `scope: "added_and_changed"` is not a valid enum variant.

### Issue 3: No Test for Warning-Only New Findings (AC5)

**Missing Test:** When `--baseline` provided and only new warnings exist (no errors), exit code should be 3.

**Current Coverage:** Only tested with error-level new findings.

---

## Weak Tests

### Weak Test: `mixed_baseline_and_new_findings`

**Issue:** Test assumes `rust.no_println` rule exists and matches. But this requires the finding to exactly match including `match_text`.

**Problem:** If the `match_text` for println doesn't match what the test expects, the fingerprint won't match and the finding classification will be wrong.

### Weak Test: `baseline_mode_with_no_findings_at_all_exits_0`

**Issue:** Test sets `base` and `head` to the same commit, expecting empty diff. However, the test doesn't verify the diff is actually empty.

---

## Missing Tests

1. **Warning-only new findings exit code 3** (AC5)
2. **Help text documentation verification** (AC8)
3. **Fingerprint stability/determinism** (AC3)
4. **`--report-mode=all` (default) produces both BASELINE and NEW annotations** (AC6)
5. **Exit code 1 for unreadable baseline file (permissions)** (AC2/EC7)
6. **Exit code 1 for baseline with missing fingerprint fields** (AC2/EC6)

---

## Recommendations

### High Priority
1. **Fix test fixtures** - Use correct `match_text` values from actual diffguard output
2. **Fix `DiffMeta` structure** - Add `context_lines` field, fix `scope` to valid enum variant
3. **Add warning-only exit code test** - Test exit code 3 scenario

### Medium Priority
4. **Add fingerprint determinism test** - Verify same input produces same fingerprint
5. **Add file permissions error test** - Ensure proper error handling

### Low Priority
6. **Add help text verification test** - Document mutual exclusivity of baseline vs false-positive-baseline

---

## Confirmation: Tests Fail as Expected

| Test | Expected Result | Actual Result | Status |
|------|-----------------|---------------|--------|
| `baseline_flag_is_accepted` | Pass (flag accepted) | Pass | OK |
| `baseline_flag_missing_file_exits_code_1` | Pass (exit 1) | Pass | OK |
| `baseline_receipt_invalid_json_exits_code_1` | Pass (exit 1) | Pass | OK |
| `baseline_receipt_wrong_schema_version_exits_code_1` | Pass (exit 1) | Pass | OK |
| `without_baseline_flag_behavior_unchanged` | Pass (exit 2) | Pass | OK |
| `findings_matching_baseline_are_classified_as_baseline` | Fail (should exit 0) | Fail (exits 2) | BUG |
| `new_findings_not_in_baseline_are_classified_as_new` | Fail (should exit 2) | Fail (exits 2) | UNCERTAIN |
| `baseline_mode_with_only_baseline_findings_exits_0` | Fail (should exit 0) | Fail (exits 2) | BUG |
| `baseline_mode_with_no_findings_at_all_exits_0` | Fail (should exit 0) | Fail | BUG |
| `baseline_mode_with_new_errors_exits_2` | Fail (should exit 2) | Fail (exits 1) | BUG |
| `baseline_mode_marks_baseline_findings_in_output` | Fail (should show BASELINE) | Fail | BUG |
| `baseline_mode_marks_new_findings_in_output` | Fail (should show NEW) | Fail | BUG |
| `report_mode_new_only_hides_baseline_findings` | Fail (should hide) | Fail | BUG |
| `empty_baseline_all_findings_are_new` | Fail (should exit 2) | Fail | BUG |
| `mixed_baseline_and_new_findings` | Fail (should exit 2) | Fail | BUG |
| `baseline_flag_does_not_affect_non_baseline_runs` | Fail (should exit 0) | Fail | BUG |

---

## Summary

The test suite is **structurally complete** but has **critical correctness bugs** in the test fixtures. The tests use `match_text` values that don't match what diffguard actually produces, causing fingerprint comparison failures.

**Sufficiency: NEEDS-MORE**

The red tests need to be corrected before they can serve as valid acceptance criteria for the implementation.
