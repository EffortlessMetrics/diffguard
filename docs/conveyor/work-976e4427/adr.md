# ADR-2026-0426-001: Explicit Truncation for u128→u64 Duration Cast

## Status
Accepted

## Context

Issue #297 reports a silent `u128→u64` truncation in `crates/diffguard/src/main.rs:1925`:

```rust
let duration_ms = start_time.elapsed().as_millis() as u64;
```

`Instant::elapsed().as_millis()` returns `u128`, and the `as u64` cast silently discards high bits if the duration exceeds ~584 million years — practically impossible for a CLI command. However, Clippy's `cast_truncation` lint warns about this, and the silent truncation is poor defensive practice.

Two fix options were listed in issue #297:
- **Option A**: `#[allow(clippy::cast_truncation)]` with explanatory comment
- **Option B**: `u64::try_from(...).expect(...)` to make truncation explicit with a panic path

## Decision

Use **Option A** — `#[allow(clippy::cast_truncation)]` with an inline comment explaining why truncation is safe:

```rust
// u128 millis represents ~584M years; a CLI command cannot approach this
#[allow(clippy::cast_truncation)]
let duration_ms = start_time.elapsed().as_millis() as u64;
```

## Rationale

1. **Philosophy alignment**: diffguard enforces `rust.no_unwrap` — `.expect()` is forbidden in production code. Option B violates this project rule.

2. **Complexity without benefit**: Option B adds a documented panic path for a condition requiring ~584M years of uptime. This is pure noise that obscures the actual code logic.

3. **Explicit intent**: The `#[allow]` attribute explicitly documents that truncation is intentional, making the code self-explanatory.

4. **Matches issue guidance**: Issue #297 listed `#[allow(...)]` as a valid fix option.

5. **Future-proof**: If Clippy's `cast_truncation` lint becomes deny-by-default in the future, the `#[allow]` attribute ensures the code remains compliant without requiring re-engineering.

## Consequences

### Benefits
- Explicit documentation of intentional truncation
- No panic paths introduced
- Passes existing Clippy checks
- Aligns with project's `rust.no_unwrap` philosophy
- Single-line change, minimal diff

### Tradeoffs/Risks
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Clippy in deny-mode could still flag this | Low | Low | The `#[allow]` attribute explicitly opts out; future clippy versions are unlikely to break this |
| Someone may misunderstand the allow as a "hack" | Low | Low | Comment explains the practical impossibility (~584M years) |

## Alternatives Considered

### Option B: `u64::try_from(...).expect(...)`
Rejected because:
- Violates diffguard's `rust.no_unwrap` lint rule (`.expect()` forbidden in production)
- Adds unnecessary panic path for a physically impossible condition
- More verbose with no additional safety benefit

### Leave As-Is: Silent `as u64`
Rejected because:
- Silently discarding data is poor defensive practice, even for impossible cases
- Clippy warns about this and the warning should not be suppressed globally
- Explicit is better than implicit per Rust philosophy
