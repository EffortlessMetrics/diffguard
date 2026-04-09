# ADR-010: Add `--version` Flag to DiffGuard CLI

**Status:** Accepted

**Date:** 2026-04-09

**Work Item:** work-3b090538

---

## Context

Issue #47 requests a `--version` flag that prints the version string from `Cargo.toml`. DiffGuard currently lacks this basic CLI feature, which is expected by all users — especially in CI environments where version verification is common.

---

## Decision

Add `#[command(version)]` attribute to the `Cli` struct. Clap 4.x automatically derives `--version` (and `-V`) flags from `CARGO_PKG_VERSION`, which is set at compile time from `Cargo.toml` metadata.

**Implementation:**
- Add `#[command(version)]` above `#[derive(Parser)]` on the `Cli` struct
- No runtime parsing or I/O needed
- Version string matches `CARGO_PKG_VERSION` exactly

---

## Alternatives Considered

### 1. Manual version string parsing
Read version from `Cargo.toml` at runtime — unnecessary complexity since clap provides this for free.

### 2. `env!()` macro in a `--version` subcommand
Define a custom version subcommand using `env!("CARGO_PKG_VERSION")` — more code than needed.

### 3. `clap::crate_version!()` macro
Call `clap::crate_version!()` explicitly — equivalent to `#[command(version)]` but more verbose.

---

## Consequences

**Positive:**
- Single attribute addition, zero logic changes
- Standard CLI convention followed
- CI scripts can verify version before running

**Negative:**
- None

**Neutral:**
- The version string is already embedded in the binary via `CARGO_PKG_VERSION`

---

## Files Affected

- `crates/diffguard/src/main.rs` — add `#[command(version)]` to `Cli` struct