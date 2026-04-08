# Mutation Testing Report

**Date**: 2026-04-08
**Work Item**: work-48dac268
**Agent**: mutation-testing-agent
**Branch**: feat/work-48dac268/enable-xtask-ci

---

## Executive Summary

Mutation testing was performed on the diffguard codebase to verify that the test suite catches deliberate faults (mutations) injected into the code.

| Crate | Total Mutants | Caught | Missed | Unviable | Score |
|-------|---------------|--------|--------|-----------|-------|
| diffguard-diff | 85 | 82 | 0 | 3 | 96.5% |
| diffguard-domain | 278 | ~240* | ~20* | ~18* | ~86% |
| diffguard-core | 108 | ~100* | 4* | ~4* | ~93% |

*Note: Due to timeouts during mutation testing, some values are estimates based on partial runs.*

**Overall Test Suite Strength**: ~90% of mutations were caught by the test suite.

---

## Mutations by Category

### 1. diffguard-diff Crate

**Result**: Excellent - 96.5% caught

All 82 viable mutations were caught by tests. This indicates a strong test suite for the diff parsing module.

No critical gaps identified.

---

### 2. diffguard-domain Crate

**Result**: Good - ~86% caught

#### Caught Mutations (Examples)
- Boundary mutations in comparison operators (caught by property tests)
- Return value mutations in evaluation functions (caught)
- Logic mutations in suppression handling (caught)

#### Missed Mutations (Test Gaps)

##### Gap 1: Multiline Window Boundary (`find_multiline_matches`)
**File**: `crates/diffguard-domain/src/evaluate.rs:404-448`

**Missed Mutations**:
- `replace < with >` at line 404
- `replace < with >` at line 413
- `replace < with <=` at line 437
- `replace + with *` at line 437 (cursor calculation)
- `replace + with -` at line 448 (offset calculation)
- `replace + with *` at line 448

**Analysis**: These mutations affect how multiline windows are calculated. The window size boundary logic is not well tested. A window of size 2 is the minimum, but mutations that change the comparison operators could allow windows of size 1.

**Missing Test**: Test for multiline rule matching with edge-case window sizes (exactly 2 lines, or more lines than needed).

##### Gap 2: Context Window Calculation (`has_required_context`)
**File**: `crates/diffguard-domain/src/evaluate.rs:472-486`

**Missed Mutations**:
- `replace has_required_context -> bool with false` at line 472
- `replace + with -` at line 477 (window calculation)
- `replace + with *` at line 477

**Analysis**: When the context window calculation is mutated, the test suite doesn't catch the error because there's no test that verifies context patterns work correctly at window boundaries.

**Missing Test**: Test for context-based rules with varying window sizes and positions (start, middle, end of file).

##### Gap 3: Severity Escalation Window (`maybe_escalate_severity`)
**File**: `crates/diffguard-domain/src/evaluate.rs:500`

**Missed Mutations**:
- `replace + with -` at line 500 (window bounds)
- `replace + with *` at line 500

**Analysis**: Mutations in the escalation window bounds don't cause test failures.

**Missing Test**: Test for severity escalation with rules at file boundaries.

##### Gap 4: Override Logic (`normalize_directory`, `path_in_directory`)
**File**: `crates/diffguard-domain/src/overrides.rs:146-167`

**Missed Mutations**:
- `replace || with &&` at line 146
- `replace directory_depth -> usize with 0` at line 153
- `replace directory_depth -> usize with 1` at line 153
- `delete !` at line 156
- `replace && with ||` at line 167

**Analysis**: The directory override logic has complex boolean conditions that aren't fully tested. The test suite doesn't exercise all combinations of directory matching.

**Missing Test**: Test for directory overrides with various directory nesting levels and glob patterns.

##### Gap 5: Language Preprocessing (`comment_syntax`, `string_syntax`)
**File**: `crates/diffguard-domain/src/preprocess.rs:83, 108`

**Missed Mutations**:
- `delete match arm Language::Json` in `comment_syntax`
- `delete match arm Language::Yaml | Language::Toml | Language::Json` in `string_syntax`

**Analysis**: When JSON or YAML/TOML language detection is removed, tests still pass because tests may not specifically test JSON/YAML files or they fall back to default behavior.

**Missing Test**: Test that explicitly verifies JSON/YAML/TOML files are preprocessed correctly.

---

### 3. diffguard-core Crate

**Result**: Good - ~93% caught

#### Caught Mutations (Examples)
- Verdict computation mutations (caught by property tests)
- Exit code calculation mutations (caught)
- Path filtering mutations (caught)

#### Missed Mutations (Test Gaps)

##### Gap 1: Tag Filter Boolean Logic (`filter_rule_by_tags`)
**File**: `crates/diffguard-core/src/check.rs:276`

**Missed Mutation**: `replace && with ||` in `filter_rule_by_tags`

**Analysis**: The tag filtering logic uses `&&` to combine `only_tags` and `enable_tags` checks. When changed to `||`, the logic becomes incorrect but tests don't catch it.

**Missing Test**: Test for rules that match `enable_tags` but not `only_tags` (and vice versa).

##### Gap 2: Sensor Report Fields (`run_sensor`)
**File**: `crates/diffguard-core/src/sensor_api.rs:62-63`

**Missed Mutations**:
- `delete field truncated_count` 
- `delete field rules_total`

**Analysis**: These fields are set but their absence doesn't cause test failures because the tests may not verify the exact field values in the sensor report.

**Missing Test**: Test that verifies sensor report fields are populated correctly.

---

## Critical Gaps Requiring Regression Tests

### Priority 1 (High Impact)

1. **Multiline window boundary logic** - Could cause incorrect rule matching for multiline patterns
2. **Context window calculation** - Could cause rules to fire incorrectly when they should be suppressed by context
3. **Tag filter boolean logic** - Could cause rules to be incorrectly included/excluded

### Priority 2 (Medium Impact)

4. **Directory override depth logic** - Could cause overrides to apply to wrong directories
5. **Severity escalation window** - Could cause incorrect severity assignment

### Priority 3 (Low Impact)

6. **Language preprocessing for JSON/YAML** - Could cause false positives/negatives in config files
7. **Sensor report fields** - Internal consistency issue, low user impact

---

## Recommendations

1. **Add multiline pattern tests**: Create tests that specifically verify multiline matching at window boundaries (exactly 2 lines, more lines than window).

2. **Add context pattern tests**: Create tests that verify context-based rule suppression at file boundaries (first line, last line).

3. **Add tag filter tests**: Create tests with rules that have `enable_tags` but not `only_tags` and verify they are included.

4. **Add directory override tests**: Create tests with nested directory overrides at various depths.

5. **Add language-specific preprocessing tests**: Verify JSON/YAML files are preprocessed correctly with the right comment/string handling.

---

## Files Modified

No implementation files were modified. This report identifies test gaps that should be addressed by adding regression tests.

---

## Appendix: Mutation Testing Command Used

```bash
# diffguard-diff crate
cargo mutants -p diffguard-diff

# diffguard-domain crate (partial - timed out)
cargo mutants -p diffguard-domain --timeout 30

# diffguard-core crate (partial - timed out)
cargo mutants -p diffguard-core --timeout 30
```

The `cargo mutants` tool was used with default settings, excluding fuzz targets and GitHub workflows as specified in `mutants.toml`.
