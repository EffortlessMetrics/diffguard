# Specification: RUSTSEC-2026-0097 rand via proptest patch

## Feature/Behavior Description

Add a `[patch.crates-io]` section to the root `Cargo.toml` that pins `rand` to version `0.9.4` to address RUSTSEC-2026-0097 (rand 0.9.2 unsoundness via proptest).

This is a **dependency-only change** — no source code is modified. The patch ensures that regardless of what version `proptest` requests or what lockfile state exists locally, `rand 0.9.4` (the safe version) is always resolved.

## Acceptance Criteria

### AC1: rand resolution is deterministic
After applying the patch, `cargo tree -i rand` must show `rand 0.9.4` as the resolved version. This must hold true even after `cargo clean` or fresh clone.

### AC2: Test suite passes
After applying the patch, `cargo test` must pass without rand-related panics or failures. This includes running property-based tests in all affected crates:
- diffguard-testkit (strategies)
- diffguard-types (properties)
- diffguard (baseline_mode_properties)
- diffguard-domain (properties)
- diffguard-core (properties, property_test_checkstyle, property_tests_escape_xml)
- diffguard-diff (properties)
- bench (property_tests)

### AC3: Only Cargo.toml is modified
The implementation must not introduce any changes to source code files (`.rs` files). Only `Cargo.toml` may be modified.

### AC4: Patch is documented
The `[patch.crates-io]` section must include an inline comment referencing RUSTSEC-2026-0097 and noting that this only affects dev/test dependencies.

## Non-Goals

1. **No production code changes**: This patch affects only dev/test dependencies (property-based tests). Production binaries are unaffected.
2. **No Cargo.lock commit**: The Cargo.lock remains gitignored. The fix is deterministic via the patch mechanism, not via lockfile pinning.
3. **No proptest upgrade**: This patch does not require upgrading proptest. The current `proptest = "1.10.0"` workspace dependency resolves to `1.11.0` via semver.
4. **No other dependency changes**: Only `rand` is patched. No other dependencies are added, removed, or modified.

## Dependencies

- **Workspace dependency**: `proptest = "1.10.0"` (already exists, resolves to 1.11.0)
- **Vulnerable version**: `rand 0.9.2` (specified by proptest 1.11.0 at time of RUSTSEC filing)
- **Safe version**: `rand 0.9.4` (patched/safe version)
- **No new dependencies added**: The patch uses an existing crate (rand) from the existing source (crates-io)

## Technical Notes

### Why a patch and not a direct dependency?
A `[patch.crates-io]` section intercepts *all* requests for `rand` from any dependency (including transitive), forcing the patched version. A direct dependency would only add a new `rand` version to the resolution, potentially resulting in both 0.9.2 and 0.9.4 being resolved.

### Why crates.io source and not git tag?
Using `rand = "0.9.4"` without a git reference uses the standard crates.io registry. This is more robust than a git-tag reference because:
1. No dependency on external git repository availability
2. No risk of tag being moved/deleted
3. crates.io is the canonical source for published crates

### Scope of affected crates
All 7 workspace crates that use `proptest.workspace = true` are affected:
- diffguard-analytics
- diffguard
- diffguard-core
- diffguard-diff
- diffguard-domain
- diffguard-testkit
- diffguard-types