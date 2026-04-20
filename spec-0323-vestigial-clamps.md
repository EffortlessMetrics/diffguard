# Spec: Remove Vestigial .min(u32::MAX) Clamps — work-803dfbba

## Feature/Behavior Description
Remove unnecessary defensive clamping from `Vec::len()` to `u32` conversion in `crates/diffguard-analytics/src/lib.rs`. The `.min(u32::MAX as usize)` pattern is vestigial — it protects against an impossible overflow scenario and obscures the code's intent.

## Acceptance Criteria

### AC1: Compilation succeeds
`cargo check -p diffguard-analytics` completes without errors.

### AC2: All existing tests pass
`cargo test -p diffguard-analytics` passes all tests with no regressions.

### AC3: Code changes are minimal and targeted
Only the following changes are made:
- Line 228: `receipt.findings.len().min(u32::MAX as usize) as u32` → `receipt.findings.len() as u32`
- Line 281: `history.runs.len().min(u32::MAX as usize) as u32` → `history.runs.len() as u32`

### AC4: No behavior change at runtime
The fix does not change runtime behavior. The clamps were never triggered in practice (impossible overflow scenario).

### AC5: Serialization compatibility maintained
Field types (`u32`) remain unchanged, so serde serialization is unaffected.

## Non-Goals
- This fix does not address similar patterns elsewhere in the codebase
- This fix does not change the serialization format
- This fix does not add new tests (existing tests verify the behavior)

## Dependencies
- None — the change is self-contained within `diffguard-analytics`

## Scope
**In scope:**
- Removal of the two vestigial clamps in `crates/diffguard-analytics/src/lib.rs`
- Verification that compilation and tests pass

**Out of scope:**
- Changes to other crates
- Changes to the serialization format
- Refactoring of the analytics data structures
- Addressing similar patterns elsewhere in the codebase
