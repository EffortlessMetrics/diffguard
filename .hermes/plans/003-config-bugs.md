# Plan: Fix Config Include Recursion & Defaults Merge (#11, #12)

**Created:** 2026-04-05
**PR:** #14
**Status:** merged to main
**Issues:** #11, #12

## Problem

Two P1 config bugs in `crates/diffguard/src/config_loader.rs`:

### #11: Config Include Recursion
Config includes used simple recursion without cycle detection. Any include cycle (A→B→A) would cause infinite recursion and stack overflow. Valid DAG configs also failed because the recursion didn't handle shared includes properly.

### #12: Defaults Merge
The defaults merge used struct replacement instead of field-wise merge, silently dropping inherited values from parent configs.

## Root Cause

`config_loader.rs` had two issues:
1. `load_include()` recursively loaded includes without tracking which files were already visited
2. Default config merging used `Config { ..defaults }` struct syntax which replaces the entire struct

## Solution

1. **DAG include support:** Added a `HashSet<PathBuf>` to track visited files, allowing shared includes (DAG structure) while detecting cycles
2. **Field-wise merge:** Changed defaults merge to explicitly merge each field instead of struct replacement

## Verification

- Added 3 tests for recursive config include scenarios
- Verified workspace tests pass (857 ok, 0 failed)
- CI checks: Format ✓, Clippy ✓, Test ✓
