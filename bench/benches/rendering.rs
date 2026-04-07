//! Rendering benchmarks for `render_*_for_receipt()` functions.
//!
//! Measures throughput of output rendering at various finding counts.
//!
//! # Benchmark Categories
//!
//! | Finding Count | Description |
//! |----------------|-------------|
//! | 0 findings | Empty output baseline |
//! | 10 findings | Small PR |
//! | 100 findings | Medium PR |
//! | 1000 findings | Large PR with many violations |
//!
//! # Renderers Benchmarked
//!
//! - `render_markdown_for_receipt()` - Human-readable markdown output
//! - `render_sarif_for_receipt()` - SARIF format for CI integration
//!
//! # Notes
//!
//! - `CheckReceipt` is pre-constructed before measurement (not in measured time)
//! - Both Markdown and SARIF renderers are benchmarked

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use diffguard_core::{render_markdown_for_receipt, render_sarif_for_receipt};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, MatchMode, Scope, Severity, TimingMetrics, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

/// Generate a CheckReceipt with a specified number of findings.
fn generate_receipt(num_findings: usize) -> CheckReceipt {
    let findings: Vec<Finding> = (0..num_findings)
        .map(|i| Finding {
            rule_id: format!("rule_{:03}", i % 10), // Cycle through 10 rule IDs
            severity: match i % 3 {
                0 => Severity::Error,
                1 => Severity::Warn,
                _ => Severity::Info,
            },
            message: format!(
                "Finding {}: This is a sample finding message with some content to simulate real output",
                i
            ),
            path: format!("src/module_{}.rs", i % 20), // 20 different files
            line: (10 + (i * 3) % 1000) as u32,
            column: Some((5 + (i % 20)) as u32),
            match_text: format!("matched content {}", i),
            snippet: "additional context for the finding".to_string(),
        })
        .collect();

    let verdict = if findings.is_empty() {
        Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        }
    } else {
        let error_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warn_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        Verdict {
            status: if error_count > 0 {
                VerdictStatus::Fail
            } else if warn_count > 0 {
                VerdictStatus::Warn
            } else {
                VerdictStatus::Pass
            },
            counts: VerdictCounts {
                info: info_count as u32,
                warn: warn_count as u32,
                error: error_count as u32,
                suppressed: 0,
            },
            reasons: vec![],
        }
    };

    CheckReceipt {
        schema: "diffguard.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "abc1234".to_string(),
            head: "def5678".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 100,
        },
        findings,
        verdict,
        timing: Some(TimingMetrics {
            total_ms: 42,
            diff_parse_ms: 10,
            rule_compile_ms: 5,
            evaluation_ms: 27,
        }),
    }
}

/// Benchmark group: Markdown rendering at various finding counts.
fn markdown_rendering_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("render_markdown");

    let finding_counts = [0, 10, 100, 1000];

    for &num_findings in &finding_counts {
        let receipt = generate_receipt(num_findings);

        group.bench_with_input(
            BenchmarkId::new("render_markdown_for_receipt", num_findings),
            &num_findings,
            |b, _| {
                b.iter(|| {
                    let result = render_markdown_for_receipt(black_box(&receipt));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark group: SARIF rendering at various finding counts.
fn sarif_rendering_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("render_sarif");

    let finding_counts = [0, 10, 100, 1000];

    for &num_findings in &finding_counts {
        let receipt = generate_receipt(num_findings);

        group.bench_with_input(
            BenchmarkId::new("render_sarif_for_receipt", num_findings),
            &num_findings,
            |b, _| {
                b.iter(|| {
                    let result = render_sarif_for_receipt(black_box(&receipt));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Empty receipt rendering baseline.
///
/// This isolates the fixed overhead of receipt structure traversal
/// when there are no findings to format.
fn rendering_empty_baseline(c: &mut Criterion) {
    let receipt = generate_receipt(0);

    let mut group = c.benchmark_group("render_empty_baseline");

    group.bench_function("render_markdown_empty", |b| {
        b.iter(|| {
            let result = render_markdown_for_receipt(black_box(&receipt));
            black_box(result)
        });
    });

    group.bench_function("render_sarif_empty", |b| {
        b.iter(|| {
            let result = render_sarif_for_receipt(black_box(&receipt));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark: Large receipt rendering at 1000 findings.
///
/// This exercises the full rendering pipeline with a realistic
/// large-PR finding count.
fn rendering_large_receipt(c: &mut Criterion) {
    let receipt = generate_receipt(1000);

    let mut group = c.benchmark_group("render_large");

    group.bench_function("render_markdown_1000_findings", |b| {
        b.iter(|| {
            let result = render_markdown_for_receipt(black_box(&receipt));
            black_box(result)
        });
    });

    group.bench_function("render_sarif_1000_findings", |b| {
        b.iter(|| {
            let result = render_sarif_for_receipt(black_box(&receipt));
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    markdown_rendering_benchmarks,
    sarif_rendering_benchmarks,
    rendering_empty_baseline,
    rendering_large_receipt,
);
criterion_main!(benches);
