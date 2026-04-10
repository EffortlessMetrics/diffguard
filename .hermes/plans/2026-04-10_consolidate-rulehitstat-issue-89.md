# Plan: Consolidate RuleHitStat structs across diffguard-domain and diffguard-core (Issue #89)

## Goal

Eliminate duplicate `RuleHitStat` definitions by moving a canonical type to `diffguard-types` and updating both consumers.

## Current Context

- **Issue:** #89 — "Duplicate RuleHitStat structs in diffguard-domain and diffguard-core with incompatible fields"
- **Problem:** Two separate structs with overlapping fields; awkward translation layer in `diffguard-core`
- **diffguard-domain RuleHitStat** (evaluate.rs:29): `rule_id, total, emitted, suppressed, info, warn, error`
- **diffguard-core RuleHitStat** (sensor_api.rs:64): same + `false_positive`
- The `false_positive` field is only tracked in diffguard-core

## Proposed Approach

1. **Move canonical type to diffguard-types:** Add `RuleHitStat` with all fields including `false_positive` to `diffguard-types`
2. **Update diffguard-domain:** Import from diffguard-types, remove local definition
3. **Update diffguard-core:** Import from diffguard-types, remove local definition, remove translation layer
4. **Regenerate schemas:** `cargo run -p xtask -- schema`
5. **Run tests:** Full workspace test pass

## Step-by-Step

1. Read current `RuleHitStat` in both crates and `diffguard-types/src/lib.rs`
2. Define canonical `RuleHitStat` in `diffguard-types` with fields: `rule_id`, `total`, `emitted`, `suppressed`, `info`, `warn`, `error`, `false_positive`
3. Update `diffguard-domain/src/evaluate.rs` to use re-export from diffguard-types (remove local struct)
4. Update `diffguard-domain/src/lib.rs` exports
5. Update `diffguard-core/src/sensor_api.rs` similarly
6. Remove translation layer (approx lines 210-213 in sensor_api.rs)
7. Regenerate schemas: `cargo run -p xtask -- schema`
8. Verify: `cargo test --workspace && cargo clippy`

## Files Likely to Change

- `diffguard-types/src/lib.rs` — add `RuleHitStat`
- `diffguard-domain/src/evaluate.rs` — remove local struct, use re-export
- `diffguard-domain/src/lib.rs` — update exports
- `diffguard-core/src/sensor_api.rs` — remove local struct, translation layer
- `diffguard-core/src/lib.rs` — update exports

## Tests / Validation

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo run -p xtask -- schema` (verify schemas still valid)

## Risks, Tradeoffs, Open Questions

- **Risk:** Medium — involves type relocation across multiple crates; could affect public API stability
- **Tradeoff:** `diffguard-types` is supposed to be the canonical types crate; this aligns with that design
- **Open Question:** Is `RuleHitStat` part of the public API (serialized in receipts)? If so, this may be a breaking change
- **Question:** Should `false_positive` be tracked in domain evaluation too, or only in core sensor layer?
