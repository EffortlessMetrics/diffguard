//! Red tests for issue #424: wildcard imports in sample_receipts module
//!
//! These tests verify that the `sample_receipts` module in fixtures.rs
//! uses explicit named imports instead of wildcard `use super::*;` imports.
//!
//! The wildcard import pattern obscures symbol provenance — callers cannot
//! determine which traits/types are re-exported without reading the parent module.
//! This violates the explicit import principle established in issue #335.
//!
//! These tests FAIL when the wildcard import exists and PASS when explicit
//! named imports are used.

/// The expected explicit imports for the sample_receipts module.
/// These 10 symbols are used in the module and must be explicitly imported.
const EXPECTED_EXPLICIT_IMPORTS: &[&str] = &[
    "CHECK_SCHEMA_V1",
    "CheckReceipt",
    "DiffMeta",
    "Finding",
    "Scope",
    "Severity",
    "ToolMeta",
    "Verdict",
    "VerdictCounts",
    "VerdictStatus",
];

/// Extracts the `sample_receipts` module body from the fixtures.rs source.
/// Returns the source code between `pub mod sample_receipts {` and the closing `}`.
fn extract_sample_receipts_module(source: &str) -> Option<&str> {
    let start_marker = "pub mod sample_receipts {";
    let start = source.find(start_marker)? + start_marker.len();

    // Find the matching closing brace by counting braces
    let mut depth = 1;
    let mut end = start;
    for (i, c) in source[start..].chars().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    Some(&source[start..end])
}

/// Test that sample_receipts module does NOT use wildcard import `use super::*;`.
///
/// This test verifies the fix for issue #424: wildcard imports obscure symbol
/// provenance and make it impossible for callers to determine which symbols
/// are re-exported without reading the parent module.
///
/// The wildcard import `use super::*;` at line 608 must be replaced with
/// explicit named imports.
#[test]
fn test_sample_receipts_no_wildcard_import() {
    let source = include_str!("../src/fixtures.rs");
    let module_body = extract_sample_receipts_module(source)
        .expect("sample_receipts module not found in fixtures.rs");

    // The module should NOT contain `use super::*;`
    let wildcard_import = "use super::*;";
    assert!(
        !module_body.contains(wildcard_import),
        "sample_receipts module still contains wildcard import `use super::*;`. \
         This obscures symbol provenance (issue #424). \
         Expected explicit named imports instead."
    );
}

/// Test that sample_receipts module uses explicit named imports.
///
/// This test verifies that all 10 required symbols are explicitly imported
/// from `super` rather than being pulled in via a wildcard import.
///
/// Symbols required: CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding,
/// Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus
#[test]
fn test_sample_receipts_has_explicit_imports() {
    let source = include_str!("../src/fixtures.rs");
    let module_body = extract_sample_receipts_module(source)
        .expect("sample_receipts module not found in fixtures.rs");

    // Find the import statement(s) from super
    // The fix should replace `use super::*;` with `use super::{...,};`
    let import_section_start = module_body.find("use super::");
    assert!(
        import_section_start.is_some(),
        "sample_receipts module has no `use super::` import statement"
    );

    // Check that each required symbol is explicitly imported
    // The import should look like: use super::{CHECK_SCHEMA_V1, CheckReceipt, ...};
    let import_line = &module_body[import_section_start.unwrap()..];
    let import_line_end = import_line.find('\n').unwrap_or(import_line.len());
    let import_statement = &import_line[..import_line_end];

    for symbol in EXPECTED_EXPLICIT_IMPORTS {
        assert!(
            import_statement.contains(symbol),
            "sample_receipts module import statement does not include `{}`. \
             Expected explicit named imports for all 10 symbols (issue #424). \
             Import statement: {}",
            symbol,
            import_statement
        );
    }
}

/// Test that sample_receipts module has proper use statement with braces.
///
/// The wildcard `use super::*;` must be replaced with a braced import
/// like `use super::{Symbol1, Symbol2, ...};`
#[test]
fn test_sample_receipts_import_uses_braces() {
    let source = include_str!("../src/fixtures.rs");
    let module_body = extract_sample_receipts_module(source)
        .expect("sample_receipts module not found in fixtures.rs");

    // Find the import statement
    let import_section_start = module_body.find("use super::");
    assert!(
        import_section_start.is_some(),
        "sample_receipts module has no `use super::` import statement"
    );

    let import_line = &module_body[import_section_start.unwrap()..];
    let import_line_end = import_line.find('\n').unwrap_or(import_line.len());
    let import_statement = &import_line[..import_line_end];

    // The import must use braces, not a bare semicolon (which indicates wildcard)
    assert!(
        import_statement.contains('{') && import_statement.contains('}'),
        "sample_receipts import does not use braced syntax `use super={{...}};`. \
         Wildcard import `use super::*;` must be replaced with explicit imports. \
         Import statement: {}",
        import_statement
    );
}
