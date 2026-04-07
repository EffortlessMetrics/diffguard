//! Evaluation benchmarks for `evaluate_lines()`.
//!
//! Measures throughput of rule evaluation at various rule counts.
//!
//! # Benchmark Categories
//!
//! | Rule Count | Description |
//! |------------|-------------|
//! | 0 rules | Empty rule set (fast path) |
//! | 1 rule | Single rule baseline |
//! | 10 rules | Typical small rule set |
//! | 100 rules | Large enterprise rule set |
//! | 500 rules | Very large rule set |
//!
//! # Notes
//!
//! - Rules are pre-compiled once per benchmark group (outside measured time)
//! - `DiffLine → InputLine` conversion is included in measured path
//! - Uses synthetic InputLine iterators
//! - Helper `convert_diff_line_to_input_line()` is in `fixtures.rs`

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use diffguard_domain::evaluate::evaluate_lines;
use diffguard_domain::rules::compile_rules;
use diffguard_types::{MatchMode, RuleConfig, Scope, Severity};

use diffguard_bench::fixtures::{convert_diff_line_to_input_line, generate_unified_diff};

/// Pre-compile a set of rules for benchmarking.
///
/// Rules are compiled once outside the measured timing path.
fn compile_benchmark_rules(count: usize) -> Vec<diffguard_domain::rules::CompiledRule> {
    let configs: Vec<RuleConfig> = (0..count)
        .map(|i| RuleConfig {
            id: format!("rule_{:03}", i),
            severity: Severity::Warn,
            message: format!("Finding for rule {:03}", i),
            description: String::new(),
            languages: vec![],
            patterns: vec![format!(r"test_pattern_{}", i)],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Any,
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        })
        .collect();

    compile_rules(&configs).expect("Rule compilation should succeed for valid configs")
}

/// Benchmark group: evaluating with various rule counts.
fn evaluation_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation");

    // Generate input lines once (fixed 1K lines for evaluation)
    let input_lines: Vec<diffguard_domain::InputLine> = (1..=1_000)
        .map(|i| diffguard_domain::InputLine {
            path: "src/main.rs".to_string(),
            line: i,
            content: format!("line {} has test_pattern_0 in it\n", i),
        })
        .collect();

    // Rule counts to benchmark
    let rule_counts = [0, 1, 10, 100, 500];

    for &num_rules in &rule_counts {
        let compiled_rules = compile_benchmark_rules(num_rules);

        group.bench_with_input(
            BenchmarkId::new("evaluate_lines", num_rules),
            &num_rules,
            |b, _| {
                b.iter(|| {
                    let result = evaluate_lines(
                        black_box(input_lines.clone()),
                        black_box(&compiled_rules),
                        black_box(10_000),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: evaluating with 0 rules (empty fast path).
///
/// This measures the overhead of the evaluation loop itself
/// with no rules to match against.
fn evaluation_zero_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation_zero_rules");

    // Vary input line count with 0 rules
    let line_counts = [0, 10, 100, 1_000, 10_000];

    for &num_lines in &line_counts {
        let input_lines: Vec<diffguard_domain::InputLine> = (1..=num_lines as u32)
            .map(|i| diffguard_domain::InputLine {
                path: "src/main.rs".to_string(),
                line: i,
                content: format!("line {} content\n", i),
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("evaluate_lines_zero_rules", num_lines),
            &num_lines,
            |b, _| {
                b.iter(|| {
                    let result = evaluate_lines(
                        black_box(input_lines.clone()),
                        black_box(&[] as &[diffguard_domain::rules::CompiledRule]),
                        black_box(10_000),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: evaluation including DiffLine → InputLine conversion.
///
/// This measures the full pipeline that production code uses,
/// where diff parsing produces DiffLines and evaluation expects InputLines.
fn evaluation_with_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation_with_conversion");

    // Generate a diff and parse it
    let diff_text = generate_unified_diff(1_000, "src/main.rs");
    let (diff_lines, _) = diffguard_diff::parse_unified_diff(&diff_text, Scope::Added)
        .expect("Diff parsing should succeed");

    // Convert DiffLines to InputLines (this is in the measured path per spec)
    let input_lines: Vec<diffguard_domain::InputLine> = diff_lines
        .iter()
        .map(|dl| convert_diff_line_to_input_line(dl.clone()))
        .collect();

    // Benchmark with 100 rules
    let compiled_rules = compile_benchmark_rules(100);

    group.bench_function("evaluate_lines_with_conversion_1K", |b| {
        b.iter(|| {
            // Include conversion in measured path
            let result = evaluate_lines(
                black_box(input_lines.clone()),
                black_box(&compiled_rules),
                black_box(10_000),
            );
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    evaluation_benchmarks,
    evaluation_zero_rules,
    evaluation_with_conversion,
);
criterion_main!(benches);
