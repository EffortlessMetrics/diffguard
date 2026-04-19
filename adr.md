# ADR-2026-0423: Remove Duplicate diffguard-core Dependency from bench/Cargo.toml

## Status
**Proposed** (pending implementation)

## Context

GitHub Issue [#304](https://github.com/EffortlessMetrics/diffguard/issues/304) reports that in `bench/Cargo.toml`, the crate `diffguard-core` is declared in **both** `[dependencies]` and `[dev-dependencies]` sections with identical configuration:

- Line 38 (in `[dependencies]`): `diffguard-core = { path = "../crates/diffguard-core", version = "0.2.0" }`
- Line 43 (in `[dev-dependencies]`): `diffguard-core = { path = "../crates/diffguard-core", version = "0.2.0" }`

This duplication causes `diffguard-core` to be compiled twice when building the bench crate for benchmarks or tests, wasting build time and CI resources.

Analysis of the bench crate shows:
- `bench/lib.rs` and `bench/fixtures.rs` (production/library code) do **not** use `diffguard-core`
- `bench/benches/rendering.rs` (benchmark code, line 25) uses `diffguard-core` for rendering utilities
- `bench/tests/snapshot_tests.rs` (test code, line 13) uses `diffguard-core` for rendering utilities

All actual uses of `diffguard-core` are exclusively in dev-only code paths (`benches/` and `tests/`), which are only compiled when running `cargo bench` or `cargo test`.

## Decision

Remove the `diffguard-core` entry from the `[dependencies]` section of `bench/Cargo.toml` (line 38), keeping it only in `[dev-dependencies]` (line 43).

The rationale:
1. `[dependencies]` is for production dependencies of the library (`lib.rs`, `fixtures.rs`)
2. `diffguard-core` is only used by benchmark and test code, not the library itself
3. Dev-only dependencies belong in `[dev-dependencies]`, not `[dependencies]`
4. This eliminates the duplicate compilation without any functional change

## Consequences

### Benefits
- `diffguard-core` is compiled only once instead of twice during benchmark/test builds
- Reduced CI build time and resource usage
- Correct dependency categorization reflecting actual usage
- Cleaner Cargo.lock (fewer duplicate entries)

### Tradeoffs / Risks
- **Low risk**: If future code is added to `lib.rs` or `fixtures.rs` that transitively needs `diffguard-core`, it would fail to compile. However, this is unlikely given the clear separation of concerns and the fact that `diffguard-core` provides rendering utilities only needed by benchmarks/tests.
- **Lockfile change**: Cargo.lock will be updated to reflect the removed dependency path. This is expected and correct.

## Alternatives Considered

### Alternative 1: Keep both entries (Status Quo)
**Rejected because**: The crate is compiled twice, wasting build resources. There is no functional benefit to the duplication — both entries are identical. The status quo is strictly worse.

### Alternative 2: Remove from `[dev-dependencies]`, keep in `[dependencies]`
**Rejected because**: This would break benchmarks and tests, which are only compiled with dev dependencies. The rendering utilities in `diffguard-core` are only needed by benchmark and test code, not by the library itself. This would also be semantically incorrect — production code does not use `diffguard-core`.

### Alternative 3: Add a comment to prevent future duplication
**Deferred**: While a comment like `# diffguard-core is in [dev-dependencies] only — do not add to [dependencies]` could help prevent recurrence, it is out of scope for this fix. The immediate fix is the single-line deletion; documentation improvements can follow.
