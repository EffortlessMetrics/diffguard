# Plan: Fix LSP Git Diff Timeout (#13)

**Created:** 2026-04-05
**PR:** #16
**Status:** merged to main
**Issue:** #13

## Problem

The LSP server's `git diff` subprocess had no timeout. If git hung (e.g., waiting for input on a locked repo or broken git state), the LSP server would be blocked indefinitely, causing the editor to freeze.

## Root Cause

`crates/diffguard-lsp/src/server.rs` in `cmd_validate()` had an `ENV_LOCK` race condition and called `git diff` with no timeout handling.

## Solution

1. Added 30s timeout on LSP git diff subprocess
2. Process cleanup on timeout (kill + wait)
3. `ENV_LOCK` guarding in cmd_validate()

## Verification

- 49 LSP integration tests pass
- Verified `kill_on_drop` behavior correct
- No changes to diffguard core logic
