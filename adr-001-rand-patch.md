# ADR-001: Pin rand to 0.9.4 via crates-io patch for RUSTSEC-2026-0097

## Status
Proposed

## Context

RUSTSEC-2026-0097 discloses that `rand 0.9.2` is unsound when used with a custom logger via `proptest`. The unsoundness allows access to rand's global RNG state in a way incompatible with certain logging implementations, leading to undefined behavior or data corruption in logged state.

diffguard is affected **transitively only** — it does not use `rand` directly. The vulnerability is introduced via `proptest 1.11.0`, which is used extensively for property-based testing in 7 workspace crates:
- diffguard-analytics
- diffguard
- diffguard-core
- diffguard-diff
- diffguard-domain
- diffguard-testkit
- diffguard-types

**Key constraint**: The workspace `Cargo.lock` is gitignored. This means:
1. Developers with older cached lockfiles could still resolve `rand 0.9.2`
2. The fix cannot rely on lockfile-based resolution alone
3. A deterministic fix must be pinned in source control

**Current state**: The existing Cargo.lock already resolves to `rand 0.9.4` (safe), but this is not guaranteed for fresh clones or cache-cleared environments because `proptest = "1.10.0"` allows resolution to `proptest 1.11.0`, which previously specified `rand = "0.9.2"` explicitly.

## Decision

We will add a `[patch.crates-io]` section to the root `Cargo.toml` that pins `rand` to version `0.9.4` using the standard crates.io source:

```toml
# Pinned due to RUSTSEC-2026-0097: rand 0.9.2 is unsound via proptest
# This only affects dev/test dependencies (property-based tests), not production.
[patch.crates-io]
rand = "0.9.4"
```

This patch ensures that whenever Cargo resolves `rand` for any dependency (including transitive), it substitutes `rand 0.9.4` regardless of what version `proptest` requests.

## Consequences

### Positive
- **Deterministic resolution**: Fresh clones and cache-cleared environments will always resolve `rand 0.9.4`
- **Minimal change**: Single addition to root `Cargo.toml`, no source code changes
- **Transparent to workflows**: Standard Cargo mechanism, doesn't affect normal cargo operations
- **Easy to remove**: When upstream proptest pins a safe rand version, this patch can be removed
- **No production impact**: `rand` is a transitive dev-dependency only; this affects test reliability, not production binaries

### Negative
- **Patch precedence**: This patch takes precedence over any semver-compatible `rand` version requested by any dependency until the patch is removed
- **Future maintenance**: If proptest 1.12+ changes its rand dependency significantly, this patch may need updating
- **Precedent set**: This establishes a pattern for handling transitive dependency vulnerabilities in the workspace

### Risks
1. **Tag immutability**: Git tags can theoretically be moved. Using the crates.io source (version-based) avoids this risk.
2. **Build failure**: If the crates.io index is unavailable during build, the patch fails. This is a standard cargo risk, not unique to this patch.
3. **Version conflicts**: If another dependency pins `rand = "=0.9.2"` exactly, cargo may resolve both versions. The `[patch.crates-io]` only affects the `crates-io` source.

## Alternatives Considered

### Alternative 1: Run `cargo update -p rand` (rejected)
- **Description**: Update the Cargo.lock to pin rand 0.9.4
- **Rejection reason**: Cargo.lock is gitignored, so the fix doesn't persist across fresh clones or cache clears. The next developer would re-resolve the vulnerable version.

### Alternative 2: Add `rand = "0.9"` as direct dev-dependency (rejected)
- **Description**: Add `rand` as an explicit dev-dependency in the workspace
- **Rejection reason**: Less explicit than the patch approach; doesn't guarantee proptest uses that specific version; more heavyweight than a targeted patch.

### Alternative 3: Git-tag patch `rand = { git = "...", tag = "0.9.4" }` (rejected)
- **Description**: Use the git repository with a tag reference
- **Rejection reason**: The git tag could not be verified as existent and stable due to network restrictions. Using the crates.io source (version-based) is more robust and doesn't depend on external git repository availability.

### Alternative 4: Wait for proptest to release a fix (not applicable)
- **Description**: Do nothing and wait for proptest to address the issue
- **Status**: Already addressed by proptest 1.11.0 (which allows any rand 0.9.x), but this is not deterministic without the patch given gitignored Cargo.lock.

## References

- RUSTSEC-2026-0097: https://rustsec.org/advisories/RUSTSEC-2026-0097
- Cargo patch documentation: https://doc.rust-lang.org/cargo/reference/manifest.html#the-patch-section