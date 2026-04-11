# Specification: Remove Unnecessary Result from parse_blame_porcelain

## Overview

Refactor `parse_blame_porcelain` function to return `BTreeMap<u32, BlameLineMeta>` directly instead of `Result<BTreeMap<u32, BlameLineMeta>>`, since the function never returns `Err`.

## Feature / Behavior Description

The function `parse_blame_porcelain` parses git blame porcelain output and returns a mapping from line numbers to their metadata. Currently it returns `Result<...>` but always succeeds. After the change, it returns the `BTreeMap` directly.

**No behavioral change** — the function continues to silently skip malformed entries via `continue` statements. Only the type signature changes.

## Non-Goals

- No changes to parsing logic or error handling behavior
- No new functionality
- No changes to other functions or their signatures

## Changes

| Location | Before | After |
|----------|--------|-------|
| Line 1768 (function signature) | `fn parse_blame_porcelain(blame_text: &str) -> Result<BTreeMap<u32, BlameLineMeta>>` | `fn parse_blame_porcelain(blame_text: &str) -> BTreeMap<u32, BlameLineMeta>` |
| Line 1818 (return) | `Ok(out)` | `out` |
| Lines 1861-1862 (caller) | `.with_context(...)?` | Remove `.with_context()` and `?` |
| Line 4068 (test) | `.expect("parse")` | Remove `.expect()` |

## Acceptance Criteria

1. `cargo clippy -p diffguard` reports no warnings related to `parse_blame_porcelain`
2. `cargo test -p diffguard` passes with all tests green, including `parse_blame_porcelain_extracts_line_metadata`
3. The function signature is `fn parse_blame_porcelain(&str) -> BTreeMap<u32, BlameLineMeta>`
4. All call sites are updated to handle the non-Result return type

## Dependencies

- `anyhow` (already in dependency tree for `Result` type alias)
- No new dependencies required

## Test Plan

1. **Existing test** (`parse_blame_porcelain_extracts_line_metadata`): Update to call function without `.expect()` and verify it passes
2. **Clippy check**: Run `cargo clippy -p diffguard` to confirm no lint
3. **Full test suite**: Run `cargo test -p diffguard` to ensure no regressions

## File Changes

- `crates/diffguard/src/main.rs` — 4 locations (signature, return, caller, test)