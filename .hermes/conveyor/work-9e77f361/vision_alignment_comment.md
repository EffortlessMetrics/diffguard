# Vision Alignment Comment: Performance Benchmark Infrastructure

## Alignment Assessment: **ALIGNED**

## Reasoning

The proposed change to add benchmark infrastructure is fully aligned with diffguard's architecture, stated design goals, and development trajectory.

### 1. Performance is the Core Value Proposition

Diffguard's tagline is "fast because diff-scoped." The issue (#36) explicitly calls out that the project lacks infrastructure to prove or protect this performance advantage. Adding benchmarks is not a tangential concern—it directly addresses the project's competitive differentiation. Without benchmarks, performance regressions go undetected and the "fast" claim becomes marketing rather than demonstrated fact.

### 2. Clean Architecture Supports Benchmarking

The codebase's clean architecture (I/O at edges, pure logic in domain crates) makes benchmarking straightforward and reliable:

- `diffguard-diff` (I/O-free) — Can benchmark parsing in complete isolation
- `diffguard-domain` (I/O-free) — Can benchmark rule evaluation without external dependencies
- `diffguard-core` — Can benchmark the full pipeline including rendering

The domain crate invariant ("no `std::fs`, `std::process`, or `std::env`") means benchmarks using synthetic inputs will accurately reflect production behavior without file system noise.

### 3. Existing Test Infrastructure Indicates Maturity

The project already has:
- Unit tests (co-located in source files)
- Snapshot tests (`insta`)
- Property-based tests (`proptest`)
- Mutation tests (`cargo-mutants`)
- Fuzz tests (`fuzz/fuzz_targets/`)

Adding benchmark infrastructure via `criterion` completes the testing maturity picture. This is not scope creep—it is the expected evolution of a serious Rust project that cares about correctness and performance.

### 4. The Plan Correctly Leverages Existing Infrastructure

The plan uses `diffguard-testkit` (already a dev-dependency) for fixture generation rather than reinventing. The `[[bench]]` workspace targets follow Rust conventions. The CI job on main-push-only avoids PR noise while still capturing regressions.

### 5. No Architectural Violations

- Benchmarks don't require I/O in domain crates
- Benchmarks don't change public API surfaces
- Benchmarks don't violate any stated invariants
- Benchmarks use synthetic inputs (in-memory only)

## Concerns (Non-Blocking)

### Concern 1: CI Runner Variance Will Limit Regression Detection Precision

GitHub Actions shared runners have ±10-30% microbenchmark variance. This is real and documented. The plan mitigates by focusing on relative comparisons and artifact storage for trend analysis.

**Recommendation**: Accept this limitation for now. If regression detection proves too noisy, consider a dedicated self-hosted runner or periodic local benchmark runs with results posted as PR comments.

### Concern 2: Preprocessor Mutable State Requires Careful Handling

The plan review correctly identified that `Preprocessor::sanitize_line` requires `&mut self` and tracks multi-line comment state. This is an implementation detail, not a vision misalignment. The implementation must use `reset()` between iterations or create fresh instances.

**This is a task for the implementation agent**, not a reason to reject the approach.

### Concern 3: Zero-Input Edge Cases Missing from Plan

The plan tests 1/10/100/500 rules but omits zero rules (valid fast path) and 0-line diffs. These are legitimate baseline cases.

**Recommendation**: Implementation agent should add zero-input cases as baseline floors. This is a quality gap, not a vision gap.

## Long-Term Impact Assessment

**Positive:**
- Enables data-driven performance conversations ("our 100K-line parse is 3ms")
- Creates regression protection as the project scales
- Demonstrates engineering maturity to users evaluating the tool
- Supports the "dogfood its own governance" philosophy—benchmarks are a natural complement to fuzz tests and mutation tests

**Neutral:**
- Initial baseline numbers will vary by hardware; the README section will need to note this
- Benchmarks will require periodic review as the project evolves (but this is true of all tests)

**Risks:**
- Benchmark-only regressions in CI could cause false failures (mitigated by main-push-only trigger)
- Excessive benchmark noise could cause teams to ignore CI benchmark status (mitigated by artifact-based trend analysis)

## Conclusion

This change is **aligned** with the codebase's direction. The project claims performance as a differentiator, the architecture supports isolated benchmarking, and the existing test maturity suggests this is the expected next step. The plan review's concerns are implementation details that the implementation agent must handle—not reasons to reject the change.

The key question was never "should we add benchmarks" but "how do we add them without violating invariants." The plan answers the "how" adequately, with the plan review identifying specific corrections needed for preprocessor handling, fixture generation bounds, and DiffLine→InputLine conversion.

**Proceed to implementation with the plan review's Must Fix items addressed.**
