# Specs — work-7634ff6b

## Feature/Behavior Description
Confirm that the checkstyle.rs output correctly maps all three `Severity` enum variants to distinct severity strings, making them distinguishable in the XML output.

**Current (correct) behavior:**
- `Severity::Error` → `"error"`
- `Severity::Warn` → `"warning"`
- `Severity::Info` → `"info"`

This was verified to be already implemented by commit `b31d836`.

## Acceptance Criteria

### AC1: Info severity produces distinct output from Warn severity
- [x] `Severity::Info` maps to `"info"` (not `"warning"`)
- [x] Verified in `checkstyle.rs` line 74: `Severity::Info => "info"`
- [x] Verified by snapshot test `test_checkstyle__checkstyle_all_severities.snap`

### AC2: All three severities are distinguishable in checkstyle XML output
- [x] `Severity::Error` → `severity="error"`
- [x] `Severity::Warn` → `severity="warning"`
- [x] `Severity::Info` → `severity="info"`
- [x] All three appear correctly in the snapshot

### AC3: Documentation matches implementation
- [x] `CHANGELOG.md` line 57 documents: Error→error, Warn→warning, Info→info
- [x] Implementation matches documentation

## Non-Goals
- No changes to the `Severity` enum definition in `diffguard-types`
- No changes to other format renderers (SARIF, JUnit, etc.) — each handles mapping independently
- No changes to the branch specified in the work item (it does not exist and is not needed)

## Dependencies
- `Severity` enum in `crates/diffguard-types/src/lib.rs`
- Checkstyle XSD schema compliance (allows "error", "warning", "info", "ignore")

## Verification
- Tests: `cargo test -p diffguard-core --test test_checkstyle_info_severity`
- Snapshot: `test_checkstyle__checkstyle_all_severities.snap` shows correct severity strings
- All 3 Info-severity tests pass
