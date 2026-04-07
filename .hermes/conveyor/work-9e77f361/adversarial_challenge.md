# Adversarial Challenge: Performance Benchmark Infrastructure

## Summary of Current Approach

The ADR proposes adding criterion-based benchmark infrastructure to the diffguard workspace:

1. **New `bench/` workspace package** at root level (not a library, just a `[bench]` binary crate)
2. **Four benchmark categories**: parsing, evaluation, rendering, preprocessing — each in its own file under `bench/benches/`
3. **criterion 0.5** as the measurement framework with statistical analysis
4. **Four input sizes** per category: small/medium via testkit (bounded to 20 lines/hunk), large via `bench/fixtures.rs` generators
5. **GitHub Actions CI job** on main-only push with CSV artifact upload
6. **README performance section** with baseline numbers and runner variance disclaimer

---

## Alternative Approach 1: Embedded Benchmarks via `cargo bench` + Existing Test Infrastructure

**What it is**: Instead of a separate `bench/` package, put benchmarks in the existing crate directories using Rust's built-in `#[bench]` attribute in `tests/` directories. Cargo automatically discovers these via `cargo bench`.

**Why it might be better**:

- **Zero new package overhead** — no `bench/Cargo.toml`, no `bench/lib.rs`, no additional workspace entry. Each crate benchmarks its own module in isolation.
- **Encourages crate-level ownership** — `diffguard-diff` owns parsing benchmarks, `diffguard-domain` owns evaluation benchmarks. The ADR's structure distributes benchmark ownership across multiple files in a single package, which creates a "who owns this?" ambiguity.
- **Closer to where the code lives** — benchmark code lives next to the code it measures. When `evaluate.rs` changes, the benchmark author sees both in the same crate.
- **Avoids the fixtures.rs indirection** — Instead of a centralized `bench/fixtures.rs`, each crate's `tests/` directory can use proptest strategies already defined in `diffguard-testkit`. The bounds problem (testkit's 20-line hunk limit) is real, but the ADR's solution (a separate fixtures module) adds coupling between packages that Rust's module system handles naturally.
- **Simpler CI** — `cargo bench --workspace` already discovers all benches. The ADR's CI job with CSV output and artifact upload is addressing a problem that criterion already solves via `--output-format csv`. The CI job could just be: `cargo bench --workspace -- --no-terminal`.

**What current approach preserves that this sacrifices**:

- Dedicated performance documentation (`README.md` section) — the ADR explicitly calls for a performance section. This approach doesn't naturally produce a centralized performance summary.
- The "one place for all benchmarks" organizational clarity — for someone scanning the repo, `bench/` is a single entry point.

**Strongest argument against current approach**: The ADR creates a new package, directory structure, and CI job for something that can be accomplished with Rust's built-in `#[bench]` attribute and one additional CI command. The ceremony-to-value ratio is high.

---

## Alternative Approach 2: Synthetic Full-Pipeline Integration Tests as Benchmarks

**What it is**: Instead of microbenchmarks (parsing N lines, evaluating M rules), benchmark the **full end-to-end pipeline** on representative diffs at meaningful sizes, and run them as integration tests that double as performance tests.

**Why it might be better**:

- **Tests what actually matters** — diffguard's value proposition is "fast because diff-scoped." The current approach benchmarks isolated functions in a way that doesn't directly prove this claim. A full-pipeline benchmark on a 50K-line Rust diff with 100 rules measures what users actually experience.
- **Simpler input generation** — No need for four size categories per benchmark category. One representative large diff (10K-100K lines) is more realistic than four synthetic sizes.
- **Catches architectural regressions, not just algorithmic ones** — If a change makes parsing 10% faster but evaluation 20% slower due to a subtle interaction, microbenchmarks miss it. Full-pipeline benchmarks catch cross-component effects.
- **Closer to dogfooding** — The project already has `cargo test --test integration` patterns. Adding performance assertions to integration tests follows existing conventions rather than introducing a new benchmark framework.
- **Memory pressure is realistic** — Microbenchmarks often hide memory allocation patterns that only appear in full pipeline runs. A 100K-line diff creates allocation pressure that a single `parse_unified_diff()` call doesn't.

**What current approach preserves that this sacrifices**:

- **Granular breakdown** — The ADR's structure tells you exactly which function is slow. A full-pipeline benchmark only tells you "the total is slow," requiring profiling to identify the cause. This is a real trade-off for debugging.
- **Targeted regression detection** — If parsing regresses but evaluation doesn't, microbenchmarks catch it precisely. Integration tests would require bisection to identify which stage regressed.

**Strongest argument against current approach**: Microbenchmarks give precise regression signals. When a PR causes a parsing regression, the developer wants to know "parsing slowed by 15%, specifically the hunk-header loop." Full-pipeline benchmarks hide which stage caused the regression. The ADR's four-category structure is a reasonable compromise between the extremes.

---

## Alternative Approach 3: Competitive Benchmarking (vs. semgrep, grep, git diff)

**What it is**: Instead of benchmarking internal functions, create benchmarks that compare diffguard's evaluation time against **alternative tools** running on equivalent diffs.

**Why it might be better**:

- **Proves the value proposition directly** — diffguard claims "fast because diff-scoped." The current approach measures internal speed without establishing whether this is actually faster than alternatives. A competitive benchmark answers: "diffguard evaluates a 10K-line Rust diff in 8ms vs. semgrep's 450ms on the same diff."
- **Provides marketing ammunition** — Benchmark results that compare against competitors are publishable. Internal microbenchmarks are not.
- **Validates the core claim empirically** — The ADR acknowledges that the issue calls for proving "fast because diff-scoped" but benchmarks internal functions. Competitive benchmarking actually tests this claim.
- **Guides architecture decisions** — If grep is 2x faster on the same problem, that signals diffguard is doing unnecessary work. Internal benchmarks can't reveal this.

**What current approach preserves that this sacrifices**:

- **Isolation from external dependencies** — Competitive benchmarks require installing and running semgrep or other tools in CI, which adds CI complexity and external toolchain dependencies.
- **Repeatability** — Criterion microbenchmarks are deterministic and reproducible. Competitive benchmarks depend on tool versions, installation method, and system state.

**Strongest argument against current approach**: The ADR explicitly states the motivation is proving "fast because diff-scoped" but benchmarks functions that prove speed, not the competitive advantage. This is a category error — measuring internal performance doesn't validate the market differentiator.

---

## Assessment: Modify

The current approach is **workable but leaves significant value on the table**. The core structure (criterion + bench package + four categories) is sound, but two modifications would substantially improve the outcome:

### Recommended Modifications

1. **Add a competitive benchmark as a fifth category** — A benchmark that compares `diffguard-core::run_check()` against `semgrep --no-git-ignore` on the same diff directly tests the value proposition. This is the benchmark the issue actually asks for, even though it doesn't say so explicitly.

2. **Use `criterion::黑了::black_box()` consistently** — The friction log notes that Preprocessor state management is tricky. The ADR's suggestion to call `reset()` or create fresh instances is correct but under-specified. A well-written benchmark harness should use `black_box()` to ensure the compiler can't optimize away the measured code path.

### Risks of Current Approach That Alternatives Would Avoid

| Risk | Severity | What Alternatives Do |
|------|----------|----------------------|
| Benchmarks prove internal speed, not competitive advantage | Medium | Alternative 3 directly measures competitive advantage |
| 100K-line fixtures generator duplicates testkit logic | Medium | Alternative 1 uses existing test infrastructure; Alternative 2 uses fewer, more realistic sizes |
| CI runner variance makes microbenchmark results noisy | Medium | Alternatives 1 and 2 reduce benchmark count, improving signal-to-noise |

### What to Keep

- criterion as the framework (not custom, not iai)
- Four-category decomposition (even if the boundaries could be refined)
- GitHub Actions CI integration with artifact upload
- README performance section

### What to Fix

- The `DiffLine → InputLine` conversion is an implementation detail that should be hidden in the fixtures module, not exposed as a public API concern in the ADR
- The "zero-input edge cases" inclusion is correct and should be kept — baseline floors are important for regression detection
- The Preprocessor `reset()` approach is the right mitigation but needs explicit mention in the benchmark implementation, not just the ADR

---

## Strongest Argument Against Current Approach

The ADR benchmarks internal functions to prove a competitive advantage claim. The issue says diffguard lacks infrastructure to "prove or protect its 'fast because diff-scoped' performance advantage." The current approach measures parsing speed, evaluation speed, and rendering speed — but never compares these against any alternative. A 3ms parsing time is meaningless without context: is 3ms fast? For 100K lines? Compared to what?

The most adversarial question is: **If benchmarks show that diffguard parses 100K lines in 3ms but semgrep evaluates the equivalent check in 2ms, what have the benchmarks proven?** Nothing. They've proven internal performance is measurable, not that the value proposition is true.

This doesn't mean the current approach is wrong — it means the scope is incomplete. Adding a competitive benchmarking category (even as an optional, manual benchmark not in CI) would complete the picture.
