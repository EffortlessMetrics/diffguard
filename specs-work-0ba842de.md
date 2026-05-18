# Specs: DiffStats Overflow Handling — work-0ba842de

## Feature/Behavior Description
The `parse_unified_diff` function in `crates/diffguard-diff/src/unified.rs` must not silently truncate `usize` counts to `u32`. When a diff contains more than 4,294,967,295 files or lines, the function must return a `DiffParseError::Overflow` error rather than:
- Panicking (violates "Never panics" invariant)
- Returning incorrect truncated values (silent data corruption)

This behavior was implemented in commit `e38e907` and is already present in the codebase.

## Acceptance Criteria

### AC1: Overflow Returns Error for File Count
**Given** a unified diff with more than `u32::MAX` (4,294,967,295) files  
**When** `parse_unified_diff` is called  
**Then** it returns `Err(DiffParseError::Overflow("too many files (> 4294967295)"))`  

### AC2: Overflow Returns Error for Line Count
**Given** a unified diff with more than `u32::MAX` (4,294,967,295) lines  
**When** `parse_unified_diff` is called  
**Then** it returns `Err(DiffParseError::Overflow("too many lines (> 4294967295)"))`  

### AC3: Valid Diffs Under u32::MAX Work Correctly
**Given** a valid unified diff with fewer than `u32::MAX` files and lines  
**When** `parse_unified_diff` is called  
**Then** it returns `Ok((Vec<DiffLine>, DiffStats))` with correct counts  

### AC4: Issue #278 Is Closed
**Given** issue #278 describes the overflow truncation bug  
**And** issue #475 (duplicate) is already closed  
**When** this work item is resolved  
**Then** issue #278 is closed as duplicate of issue #475  

## Non-Goals
- This spec does **not** require migrating `DiffStats` to u64 (tracked as technical debt)
- This spec does **not** require adding a regression test for the overflow path (identified gap but out of scope)
- This spec does **not** require changes to the `DiffStats` public API

## Dependencies
- `crates/diffguard-diff/src/unified.rs:337-342` — `u32::try_from()` with `map_err`
- `crates/diffguard-diff/src/unified.rs:120-121` — `DiffParseError::Overflow` variant
- Issue #475 (CLOSED) — original issue that was fixed
- Issue #278 (OPEN) — duplicate to be closed