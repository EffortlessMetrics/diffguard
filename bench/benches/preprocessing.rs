//! Preprocessing benchmarks for `Preprocessor::sanitize_line()`.
//!
//! Measures throughput of comment/string masking at various comment densities.
//!
//! # Benchmark Categories
//!
//! | Comment Density | Description |
//! |-----------------|-------------|
//! | 0% | Plain code (no comments/strings) |
//! | 25% | Light commenting |
//! | 50% | Moderate commenting |
//! | 75% | Heavy commenting/documentation
//!
//! # Languages Tested
//!
//! - `rust`: `//` and `/* */` comments, `"` and `r#"...`# strings
//! - `python`: `#` comments, `"""` triple-quoted strings
//! - `javascript`: `//` and `/* */` comments, `"` and `` ` `` template strings
//!
//! # Preprocessor State Management
//!
//! `Preprocessor::sanitize_line()` requires `&mut self` and tracks multi-line
//! comment/string state across consecutive lines. Two approaches are used:
//!
//! 1. **Fresh instance per iteration**: Used for single-line measurements.
//!    This is the safest approach as it avoids state pollution but includes
//!    allocation overhead in the measured path.
//!
//! 2. **Reset between iterations**: Used for pipeline measurements.
//!    This more closely simulates production where the Preprocessor
//!    is reused across lines.
//!
//! # Notes
//!
//! - Uses `Preprocessor::with_language(opts, lang)` for construction
//! - `Preprocessor::reset()` is called between iterations where appropriate
//! - All inputs are generated in-memory (no file I/O)

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use diffguard_domain::preprocess::{Language, Preprocessor};

use diffguard_bench::fixtures::generate_lines_with_comment_density;
use diffguard_bench::fixtures::preprocessor_helpers::{fresh_preprocessor, reset_preprocessor};

/// Benchmark group: preprocessing at various comment densities in Rust.
fn rust_preprocessing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess_rust");

    let densities = [
        ("density_0", 0.0),
        ("density_25", 0.25),
        ("density_50", 0.50),
        ("density_75", 0.75),
    ];

    // Fixed line count for density benchmarks
    let num_lines = 1000;

    for (name, density) in densities {
        let lines = generate_lines_with_comment_density(num_lines, density as f32, "rust");

        group.bench_with_input(
            BenchmarkId::new("sanitize_line_rust", name),
            &num_lines,
            |b, _| {
                // Fresh instance per iteration (includes allocation)
                b.iter(|| {
                    let mut preprocessor = fresh_preprocessor(Language::Rust);
                    let mut outputs = Vec::with_capacity(lines.len());
                    for line in &lines {
                        let sanitized = preprocessor.sanitize_line(black_box(line));
                        outputs.push(black_box(sanitized));
                    }
                    black_box(outputs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark group: preprocessing at various comment densities in Python.
fn python_preprocessing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess_python");

    let densities = [
        ("density_0", 0.0),
        ("density_25", 0.25),
        ("density_50", 0.50),
        ("density_75", 0.75),
    ];

    let num_lines = 1000;

    for (name, density) in densities {
        let lines = generate_lines_with_comment_density(num_lines, density as f32, "python");

        group.bench_with_input(
            BenchmarkId::new("sanitize_line_python", name),
            &num_lines,
            |b, _| {
                b.iter(|| {
                    let mut preprocessor = fresh_preprocessor(Language::Python);
                    let mut outputs = Vec::with_capacity(lines.len());
                    for line in &lines {
                        let sanitized = preprocessor.sanitize_line(black_box(line));
                        outputs.push(black_box(sanitized));
                    }
                    black_box(outputs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark group: preprocessing at various comment densities in JavaScript.
fn javascript_preprocessing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess_javascript");

    let densities = [
        ("density_0", 0.0),
        ("density_25", 0.25),
        ("density_50", 0.50),
        ("density_75", 0.75),
    ];

    let num_lines = 1000;

    for (name, density) in densities {
        let lines = generate_lines_with_comment_density(num_lines, density as f32, "javascript");

        group.bench_with_input(
            BenchmarkId::new("sanitize_line_javascript", name),
            &num_lines,
            |b, _| {
                b.iter(|| {
                    let mut preprocessor = fresh_preprocessor(Language::JavaScript);
                    let mut outputs = Vec::with_capacity(lines.len());
                    for line in &lines {
                        let sanitized = preprocessor.sanitize_line(black_box(line));
                        outputs.push(black_box(sanitized));
                    }
                    black_box(outputs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: multi-line comment state tracking.
///
/// This specifically exercises the preprocessor's ability to track
/// state across lines when encountering multi-line comments or strings.
fn multi_line_state_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess_multiline");

    // Rust block comments
    let rust_block_comments = vec![
        "fn main() {",
        "    /* this is a",
        "     * multi-line",
        "     * block comment",
        "     */",
        "    let x = 5;",
        "}",
    ];

    group.bench_function("rust_block_comment_multiline", |b| {
        b.iter(|| {
            let mut preprocessor = fresh_preprocessor(Language::Rust);
            let mut outputs = Vec::new();
            for line in &rust_block_comments {
                let sanitized = preprocessor.sanitize_line(black_box(*line));
                outputs.push(black_box(sanitized));
            }
            black_box(outputs)
        });
    });

    // Python triple-quoted strings
    let python_docstring = vec![
        "def foo():",
        "    \"\"\"This is a",
        "    triple-quoted",
        "    docstring\"\"\"",
        "    pass",
    ];

    group.bench_function("python_docstring_multiline", |b| {
        b.iter(|| {
            let mut preprocessor = fresh_preprocessor(Language::Python);
            let mut outputs = Vec::new();
            for line in &python_docstring {
                let sanitized = preprocessor.sanitize_line(black_box(*line));
                outputs.push(black_box(sanitized));
            }
            black_box(outputs)
        });
    });

    group.finish();
}

/// Benchmark: plain code (0% comment density) baseline.
///
/// This measures the overhead of the preprocessor on regular code
/// with no comments or strings to mask.
fn plain_code_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("preprocess_plain_code_baseline");

    let line_counts = [1, 10, 100, 1000, 10000];

    for &num_lines in &line_counts {
        let lines: Vec<String> = (0..num_lines)
            .map(|i| format!("let x_{} = {} * {} + {};", i, i, i + 1, i + 2))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("plain_code_rust", num_lines),
            &num_lines,
            |b, _| {
                b.iter(|| {
                    let mut preprocessor = fresh_preprocessor(Language::Rust);
                    let mut outputs = Vec::with_capacity(lines.len());
                    for line in &lines {
                        let sanitized = preprocessor.sanitize_line(black_box(line));
                        outputs.push(black_box(sanitized));
                    }
                    black_box(outputs)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: reset() overhead measurement.
///
/// Compares fresh instance creation vs reset() between iterations.
fn reset_overhead(c: &mut Criterion) {
    let lines: Vec<String> = (0..100)
        .map(|i| format!("let x_{} = {};", i, i * 2))
        .collect();

    let mut group = c.benchmark_group("preprocess_reset_overhead");

    // Fresh instance approach
    group.bench_function("fresh_instance_per_iteration", |b| {
        b.iter(|| {
            let mut preprocessor = fresh_preprocessor(Language::Rust);
            for line in &lines {
                let _ = preprocessor.sanitize_line(black_box(line));
                // Fresh instance for next iteration
                preprocessor = fresh_preprocessor(Language::Rust);
            }
        });
    });

    // Reset approach
    group.bench_function("reset_between_iterations", |b| {
        b.iter(|| {
            let mut preprocessor = fresh_preprocessor(Language::Rust);
            for line in &lines {
                let _ = preprocessor.sanitize_line(black_box(line));
                // Reset state for next line
                reset_preprocessor(&mut preprocessor);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    rust_preprocessing_benchmarks,
    python_preprocessing_benchmarks,
    javascript_preprocessing_benchmarks,
    multi_line_state_tracking,
    plain_code_baseline,
    reset_overhead,
);
criterion_main!(benches);
