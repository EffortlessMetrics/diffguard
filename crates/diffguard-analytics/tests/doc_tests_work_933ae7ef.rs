//! Red tests for diffguard-analytics documentation requirements.
//!
//! These tests verify that all public functions in diffguard-analytics have:
//! 1. The `#[must_use]` attribute where appropriate
//! 2. Doc comments that state "Does not panic" for functions that don't panic

/// List of public functions that should have #[must_use] attribute.
const MUST_USE_FUNCTIONS: &[&str] = &[
    "normalize_false_positive_baseline",
    "fingerprint_for_finding",
    "baseline_from_receipt",
    "merge_false_positive_baselines",
    "false_positive_fingerprint_set",
    "normalize_trend_history",
    "trend_run_from_receipt",
    "append_trend_run",
    "summarize_trend_history",
];

/// Functions that don't panic and should document this in their doc comments.
const NON_PANICKING_FUNCTIONS: &[&str] = &[
    "normalize_false_positive_baseline",
    "fingerprint_for_finding",
    "baseline_from_receipt",
    "merge_false_positive_baselines",
    "false_positive_fingerprint_set",
    "normalize_trend_history",
    "trend_run_from_receipt",
    "append_trend_run",
    "summarize_trend_history",
];

/// Verifies that the source file contains the expected #[must_use] attribute
/// on the given function.
fn source_has_must_use(function_name: &str) -> bool {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));

    // Find the function and look backwards for #[must_use]
    if let Some(fn_pos) = src.find(&format!("pub fn {}", function_name)) {
        // Look at the 200 chars before the function declaration
        let start = fn_pos.saturating_sub(200);
        let snippet = &src[start..fn_pos];

        // Check if there's a #[must_use] in this range
        snippet.contains("#[must_use]")
    } else {
        false
    }
}

/// Verifies that the source file contains "Does not panic" documentation
/// for the given function.
fn source_has_no_panic_doc(function_name: &str) -> bool {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));

    // Find the function's doc comment and check for "Does not panic"
    if let Some(fn_pos) = src.find(&format!("pub fn {}", function_name)) {
        // Look backwards for the doc comment (/// or //!)
        let search_start = fn_pos.saturating_sub(500);
        let snippet = &src[search_start..fn_pos];

        // Find the last doc comment
        if let Some(doc_pos) = snippet.rfind("///") {
            let doc = &snippet[doc_pos..];
            // Check if doc mentions "Does not panic" or "# Panics" section
            doc.contains("Does not panic") || doc.contains("# Panics")
        } else {
            false
        }
    } else {
        false
    }
}

#[test]
fn test_all_public_functions_have_must_use_attribute() {
    let mut missing_must_use = Vec::new();

    for &fn_name in MUST_USE_FUNCTIONS {
        if !source_has_must_use(fn_name) {
            missing_must_use.push(fn_name);
        }
    }

    assert!(
        missing_must_use.is_empty(),
        "The following public functions are missing #[must_use] attribute: {:?}. \
         These functions return values that must be used to avoid silent data loss. \
         Add #[must_use] to each function declaration.",
        missing_must_use
    );
}

#[test]
fn test_all_non_panicking_functions_document_this() {
    let mut missing_docs = Vec::new();

    for &fn_name in NON_PANICKING_FUNCTIONS {
        if !source_has_no_panic_doc(fn_name) {
            missing_docs.push(fn_name);
        }
    }

    assert!(
        missing_docs.is_empty(),
        "The following functions do not document their panic behavior: {:?}. \
         Per Rust API Guidelines C409, functions that do not panic should document this. \
         Add '/// Does not panic.' to the doc comment of each function.",
        missing_docs
    );
}

#[test]
fn test_no_result_returning_functions_have_errors_section() {
    // This test documents that NO functions return Result,
    // so # Errors sections are not applicable
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));

    let result_functions: Vec<&str> = MUST_USE_FUNCTIONS
        .iter()
        .filter(|&&fn_name| {
            if let Some(fn_pos) = src.find(&format!("pub fn {}", fn_name)) {
                // Look at 300 chars after fn name for -> Result
                let snippet_end = (fn_pos + 300).min(src.len());
                let snippet = &src[fn_pos..snippet_end];
                snippet.contains("-> Result<") || snippet.contains("-> Result ::")
            } else {
                false
            }
        })
        .copied()
        .collect();

    // If there were any Result-returning functions, they would need # Errors sections
    // But there are none, so this test just documents that fact
    assert!(
        result_functions.is_empty(),
        "Functions returning Result found - these would need # Errors documentation: {:?}",
        result_functions
    );
}

#[test]
fn test_merge_false_positive_baselines_has_must_use() {
    // Specific test for merge_false_positive_baselines which is documented as missing #[must_use]
    assert!(
        source_has_must_use("merge_false_positive_baselines"),
        "merge_false_positive_baselines is missing #[must_use] attribute. \
         This function returns a new baseline that must be used."
    );
}

#[test]
fn test_false_positive_fingerprint_set_has_must_use() {
    // Specific test for false_positive_fingerprint_set
    assert!(
        source_has_must_use("false_positive_fingerprint_set"),
        "false_positive_fingerprint_set is missing #[must_use] attribute. \
         This function returns a BTreeSet that must be used."
    );
}

#[test]
fn test_normalize_trend_history_has_must_use() {
    // Specific test for normalize_trend_history
    assert!(
        source_has_must_use("normalize_trend_history"),
        "normalize_trend_history is missing #[must_use] attribute. \
         This function returns a normalized history that must be used."
    );
}

#[test]
fn test_trend_run_from_receipt_has_must_use() {
    // Specific test for trend_run_from_receipt
    assert!(
        source_has_must_use("trend_run_from_receipt"),
        "trend_run_from_receipt is missing #[must_use] attribute. \
         This function returns a TrendRun that must be used."
    );
}

#[test]
fn test_append_trend_run_has_must_use() {
    // Specific test for append_trend_run
    assert!(
        source_has_must_use("append_trend_run"),
        "append_trend_run is missing #[must_use] attribute. \
         This function returns a TrendHistory that must be used."
    );
}

#[test]
fn test_summarize_trend_history_has_must_use() {
    // Specific test for summarize_trend_history
    assert!(
        source_has_must_use("summarize_trend_history"),
        "summarize_trend_history is missing #[must_use] attribute. \
         This function returns a TrendSummary that must be used."
    );
}
