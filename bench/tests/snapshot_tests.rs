//! Snapshot tests for benchmark fixture output baselines.
//!
//! These snapshots capture the deterministic output of fixture generators
//! so that any changes to generator behavior are immediately detected.
//!
//! Snapshot Strategy:
//! - `generate_unified_diff` produces a specific string format
//! - `generate_mixed_unified_diff` produces a specific string format  
//! - `generate_receipt_with_findings` produces a CheckReceipt (JSON serialized)
//! - `render_markdown_for_receipt` produces markdown (text)
//! - `render_sarif_for_receipt` produces SarifReport (JSON serialized)

use diffguard_core::{render_markdown_for_receipt, render_sarif_for_receipt};
use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

// Import fixtures under test
use diffguard_bench::fixtures::{
    convert_diff_line_to_input_line, generate_input_lines, generate_lines_with_comment_density,
    generate_mixed_unified_diff, generate_receipt_with_findings, generate_unified_diff,
};

// =============================================================================
// generate_unified_diff snapshots
// =============================================================================

#[test]
fn snapshot_generate_unified_diff_empty() {
    let result = generate_unified_diff(0, "src/main.rs");
    insta::assert_snapshot!(result);
}

#[test]
fn snapshot_generate_unified_diff_single_line() {
    let result = generate_unified_diff(1, "src/main.rs");
    insta::assert_snapshot!("generate_unified_diff_single_line", result);
}

#[test]
fn snapshot_generate_unified_diff_10_lines() {
    let result = generate_unified_diff(10, "src/lib.rs");
    insta::assert_snapshot!("generate_unified_diff_10_lines", result);
}

// =============================================================================
// generate_mixed_unified_diff snapshots
// =============================================================================

#[test]
fn snapshot_generate_mixed_unified_diff_empty() {
    let result = generate_mixed_unified_diff(0, "src/main.rs");
    insta::assert_snapshot!(result);
}

#[test]
fn snapshot_generate_mixed_unified_diff_10_lines() {
    let result = generate_mixed_unified_diff(10, "src/lib.rs");
    insta::assert_snapshot!("generate_mixed_unified_diff_10_lines", result);
}

// =============================================================================
// generate_input_lines snapshots
// =============================================================================

#[test]
fn snapshot_generate_input_lines_empty() {
    let result = generate_input_lines(0, "test.rs");
    insta::assert_snapshot!("generate_input_lines_empty", result.len());
    assert!(result.is_empty());
}

#[test]
fn snapshot_generate_input_lines_5() {
    let result = generate_input_lines(5, "test.rs");
    let as_string = format!("{:?}", result);
    insta::assert_snapshot!("generate_input_lines_5", as_string);
}

// =============================================================================
// generate_lines_with_comment_density snapshots
// =============================================================================

#[test]
fn snapshot_generate_lines_density_0_rust() {
    let lines = generate_lines_with_comment_density(10, 0.0, "rust");
    insta::assert_snapshot!("generate_lines_density_0_rust", lines.join("\n"));
}

#[test]
fn snapshot_generate_lines_density_50_rust() {
    let lines = generate_lines_with_comment_density(10, 0.5, "rust");
    insta::assert_snapshot!("generate_lines_density_50_rust", lines.join("\n"));
}

#[test]
fn snapshot_generate_lines_density_100_python() {
    let lines = generate_lines_with_comment_density(10, 1.0, "python");
    insta::assert_snapshot!("generate_lines_density_100_python", lines.join("\n"));
}

// =============================================================================
// CheckReceipt generation snapshots
// =============================================================================

#[test]
fn snapshot_generate_receipt_empty() {
    let receipt = generate_receipt_with_findings(0, vec![]);
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    insta::assert_snapshot!("generate_receipt_empty", json);
}

#[test]
fn snapshot_generate_receipt_single_finding() {
    let finding = diffguard_types::Finding {
        rule_id: "test.rule".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Test finding message".to_string(),
        path: "src/main.rs".to_string(),
        line: 42,
        column: Some(10),
        match_text: "test_pattern".to_string(),
        snippet: "matched content".to_string(),
    };
    let receipt = generate_receipt_with_findings(1, vec![finding]);
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    insta::assert_snapshot!("generate_receipt_single_finding", json);
}

#[test]
fn snapshot_generate_receipt_multiple_findings() {
    let findings: Vec<diffguard_types::Finding> = (0..3)
        .map(|i| diffguard_types::Finding {
            rule_id: format!("rule_{}", i),
            severity: diffguard_types::Severity::Warn,
            message: format!("Finding {}", i),
            path: format!("src/file{}.rs", i),
            line: i as u32 * 10,
            column: Some(5),
            match_text: format!("match_{}", i),
            snippet: "context".to_string(),
        })
        .collect();
    let receipt = generate_receipt_with_findings(3, findings);
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    insta::assert_snapshot!("generate_receipt_multiple_findings", json);
}

// =============================================================================
// Rendering output snapshots
// =============================================================================

#[test]
fn snapshot_render_markdown_empty_receipt() {
    let receipt = generate_receipt_with_findings(0, vec![]);
    let output = render_markdown_for_receipt(&receipt);
    insta::assert_snapshot!("render_markdown_empty", output);
}

#[test]
fn snapshot_render_markdown_with_finding() {
    let finding = diffguard_types::Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Avoid unwrap in production code".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(15),
        match_text: ".unwrap()".to_string(),
        snippet: "x.unwrap()".to_string(),
    };
    let receipt = generate_receipt_with_findings(1, vec![finding]);
    let output = render_markdown_for_receipt(&receipt);
    insta::assert_snapshot!("render_markdown_with_finding", output);
}

#[test]
fn snapshot_render_sarif_empty_receipt() {
    let receipt = generate_receipt_with_findings(0, vec![]);
    let report = render_sarif_for_receipt(&receipt);
    let json = serde_json::to_string_pretty(&report).unwrap();
    insta::assert_snapshot!("render_sarif_empty", json);
}

#[test]
fn snapshot_render_sarif_with_finding() {
    let finding = diffguard_types::Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Avoid unwrap in production code".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(15),
        match_text: ".unwrap()".to_string(),
        snippet: "x.unwrap()".to_string(),
    };
    let receipt = generate_receipt_with_findings(1, vec![finding]);
    let report = render_sarif_for_receipt(&receipt);
    let json = serde_json::to_string_pretty(&report).unwrap();
    insta::assert_snapshot!("render_sarif_with_finding", json);
}

// =============================================================================
// DiffLine to InputLine conversion snapshots
// =============================================================================

#[test]
fn snapshot_diffline_conversion() {
    use diffguard_diff::DiffLine;

    let diff_line = DiffLine {
        path: "src/main.rs".to_string(),
        line: 42,
        content: "let x = 1;".to_string(),
        kind: diffguard_diff::ChangeKind::Added,
    };

    let input_line = convert_diff_line_to_input_line(diff_line);
    insta::assert_snapshot!("diffline_conversion", format!("{:?}", input_line));
}

// =============================================================================
// Parsed diff output snapshots
// =============================================================================

#[test]
fn snapshot_parse_unified_diff_small() {
    let diff_text = generate_unified_diff(5, "src/lib.rs");
    let (diff_lines, stats) =
        parse_unified_diff(&diff_text, Scope::Added).expect("Should parse generated diff");

    let summary = format!(
        "lines={}, stats_lines={}, first_path={}, first_line={}",
        diff_lines.len(),
        stats.lines,
        diff_lines.first().map(|l| l.path.as_str()).unwrap_or("N/A"),
        diff_lines.first().map(|l| l.line).unwrap_or(0)
    );
    insta::assert_snapshot!("parse_unified_diff_small", summary);
}
