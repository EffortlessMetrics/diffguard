//! Parsing benchmarks for `parse_unified_diff()`.
//!
//! Measures throughput of diff parsing at various input sizes.
//!
//! # Benchmark Categories
//!
//! | Size | Lines | Description |
//! |------|-------|-------------|
//! | Empty | 0 | Baseline empty input |
//! | Small | 100 | Typical PR-sized change |
//! | Medium | 1K | Several file changes |
//! | Large | 10K | Large feature branch |
//! | XLarge | 100K | Full codebase scan |
//!
//! # Notes
//!
//! - Uses synthetic unified diff text generated in-memory (no file I/O)
//! - For sizes > 1K lines, uses generators in `fixtures.rs` (not testkit)
//! - `parse_unified_diff()` returns `(Vec<DiffLine>, DiffStats)`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

use diffguard_bench::fixtures::generate_unified_diff;

/// Benchmark group: parsing various diff sizes.
fn parsing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");

    // Sizes to benchmark: (name, num_lines)
    let sizes = [
        ("empty", 0),
        ("small_100", 100),
        ("medium_1K", 1_000),
        ("large_10K", 10_000),
        ("xlarge_100K", 100_000),
    ];

    for (name, num_lines) in sizes {
        group.bench_with_input(
            BenchmarkId::new("parse_unified_diff", name),
            &num_lines,
            |b, &n| {
                let diff_text = generate_unified_diff(n, "src/main.rs");
                b.iter(|| {
                    let result = parse_unified_diff(black_box(&diff_text), Scope::Added);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: parsing with Changed scope (modified lines).
///
/// Changed scope requires tracking whether '+' lines directly follow '-' lines,
/// which has additional overhead compared to Added scope.
fn parsing_changed_scope(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing_changed_scope");

    let sizes = [
        ("small_100", 100),
        ("medium_1K", 1_000),
        ("large_10K", 10_000),
    ];

    for (name, num_lines) in sizes {
        group.bench_with_input(
            BenchmarkId::new("parse_unified_diff", name),
            &num_lines,
            |b, &n| {
                let diff_text = generate_unified_diff(n, "src/main.rs");
                b.iter(|| {
                    let result = parse_unified_diff(black_box(&diff_text), Scope::Changed);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: parsing with mixed change kinds.
///
/// This generates diffs with added, deleted, and context lines mixed together,
/// which exercises more of the parser's state machine.
fn parsing_mixed_diff(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing_mixed");

    let sizes = [
        ("small_100", 100),
        ("medium_1K", 1_000),
        ("large_10K", 10_000),
    ];

    for (name, num_lines) in sizes {
        group.bench_with_input(
            BenchmarkId::new("parse_mixed_diff", name),
            &num_lines,
            |b, &n| {
                let diff_text =
                    diffguard_bench::fixtures::generate_mixed_unified_diff(n, "src/main.rs");
                b.iter(|| {
                    let result = parse_unified_diff(black_box(&diff_text), Scope::Added);
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    parsing_benchmarks,
    parsing_changed_scope,
    parsing_mixed_diff,
);
criterion_main!(benches);
