# ADR-0328: Inline Format Arguments for clippy::uninlined_format_args

**Status:** Proposed

**Work Item:** work-22c2dc77

---

## Context

GitHub issue #328 reports that `cmd_doctor()` in `main.rs:974+` uses ~20 uninlined format arguments, which degrades readability and triggers the `clippy::uninlined_format_args` lint at 22 locations across two crates:

- `crates/diffguard/src/main.rs`: 19 warnings
- `crates/diffguard-core/src/`: 3 warnings (checkstyle.rs:41, csv.rs:106, junit.rs:39)

The majority of the codebase already uses inline `{var}` form; these violations are outliers that should be corrected for consistency.

---

## Decision

**Adopt inline format arguments across `diffguard` and `diffguard-core` using clippy auto-fix with targeted manual intervention.**

### Style
- Default form: bare `{var}` inline (e.g., `println!("git: PASS ({version})")`)
- Named form (`var = var`) only where expressions must appear inside quoted `'{}'` patterns (lines 2880, 3079)
- Redundant `bail!("{}", msg)` at line 1083 → `bail!(msg)` (String needs no format wrapper)

### Implementation Approach
1. Run `cargo clippy --fix --package diffguard --allow-dirty` — handles ~17 auto-fixable cases
2. Run `cargo clippy --fix --package diffguard-core --allow-dirty` — handles 3 core warnings
3. Manual patch: `bail!("{}", msg)` → `bail!(msg)` at line 1083
4. Manual patch: `'{}'` edge cases at lines 2880 and 3079
5. Verify zero warnings in both packages

### Tooling
- Clippy 1.92 with `clippy::uninlined_format_args` lint (Rust RFC-2795)
- Rust edition 2021

---

## Alternatives Considered

### 1. Named argument form only
Use `format!("{var}", var = var)` for all instances.

**Rejected:** The existing codebase uses bare `{var}` form exclusively outside of quoted-string edge cases. Named form adds verbosity without benefit for simple variable references.

### 2. Auto-fix without manual review
Rely solely on `cargo clippy --fix` without manual edge-case handling.

**Rejected:** Clippy auto-fix for `bail!("{}", msg)` produces `bail!("{msg}", msg)`, not the idiomatic `bail!(msg)`. Additionally, the `'{}'` quoted patterns risk producing invalid Rust if handled mechanically.

---

## Tradeoffs and Consequences

| | |
|---|---|
| **Benefits** | Eliminates 22 clippy warnings; improves compile-time argument inlining; aligns codebase with Rust best practices |
| **Risks** | Manual intervention required for edge cases; line numbers drift after patches |
| **Complexity** | Low — purely mechanical style transformation, zero behavioral change |
| **Breaking** | None — no public API or runtime behavior changes |
