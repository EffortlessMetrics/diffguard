//! Red tests for fuzz corpus seed inputs (work-0bf57ad5)
//!
//! These tests verify that fuzz targets have proper corpus seed directories
//! and that the seeds are in the correct format for libfuzzer.
//!
//! Acceptance Criteria:
//! 1. `fuzz/corpus/rule_matcher/` directory exists
//! 2. `fuzz/corpus/config_parser/` directory exists
//! 3. Each directory contains at least one valid arbitrary binary format seed
//! 4. Seeds are not empty text files but proper binary corpus inputs

use std::fs;
use std::path::Path;

/// Test that the rule_matcher corpus directory exists.
#[test]
fn test_rule_matcher_corpus_directory_exists() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let path_str = corpus_dir.display().to_string();
    assert!(
        corpus_dir.exists(),
        "fuzz/corpus/rule_matcher/ directory should exist, but path {} does not exist",
        path_str
    );
    assert!(
        corpus_dir.is_dir(),
        "fuzz/corpus/rule_matcher/ should be a directory, but it exists as a file or symlink: {}",
        path_str
    );
}

/// Test that the config_parser corpus directory exists.
#[test]
fn test_config_parser_corpus_directory_exists() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let path_str = corpus_dir.display().to_string();
    assert!(
        corpus_dir.exists(),
        "fuzz/corpus/config_parser/ directory should exist, but path {} does not exist",
        path_str
    );
    assert!(
        corpus_dir.is_dir(),
        "fuzz/corpus/config_parser/ should be a directory, but it exists as a file or symlink: {}",
        path_str
    );
}

/// Test that rule_matcher corpus contains at least one seed file.
#[test]
fn test_rule_matcher_corpus_has_seed_file() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    assert!(
        !seed_files.is_empty(),
        "fuzz/corpus/rule_matcher/ should contain at least one seed file, but directory is empty"
    );

    // Verify at least one file is non-empty (corpus seeds must have content)
    let non_empty = seed_files
        .iter()
        .any(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false));

    assert!(
        non_empty,
        "fuzz/corpus/rule_matcher/ should contain at least one non-empty seed file"
    );
}

/// Test that config_parser corpus contains at least one seed file.
#[test]
fn test_config_parser_corpus_has_seed_file() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    assert!(
        !seed_files.is_empty(),
        "fuzz/corpus/config_parser/ should contain at least one seed file, but directory is empty"
    );

    // Verify at least one file is non-empty (corpus seeds must have content)
    let non_empty = seed_files
        .iter()
        .any(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false));

    assert!(
        non_empty,
        "fuzz/corpus/config_parser/ should contain at least one non-empty seed file"
    );
}

/// Test that rule_matcher seeds are in binary format (not text).
///
/// Arbitrary-based fuzz targets produce binary corpus files in libfuzzer's
/// custom binary format. These files are NOT valid UTF-8 text and should
/// not be mistaken for text-based seed files.
#[test]
fn test_rule_matcher_seed_is_binary_format() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    assert!(
        !seed_files.is_empty(),
        "fuzz/corpus/rule_matcher/ should contain at least one non-empty seed file"
    );

    // Check first seed file - it should contain non-UTF-8 bytes
    // libfuzzer arbitrary binary format is not valid UTF-8
    let first_seed = &seed_files[0];
    let content = fs::read(first_seed.path()).expect("Should be able to read seed file");

    // Corpus seeds for arbitrary-based targets contain binary data
    // If this is pure ASCII/UTF-8 text, it's likely a misconfigured seed
    let is_valid_utf8 = std::str::from_utf8(&content).is_ok();

    assert!(
        !is_valid_utf8,
        "fuzz/corpus/rule_matcher/ seed '{}' appears to be UTF-8 text, but should be binary arbitrary format",
        first_seed.path().display()
    );
}

/// Test that config_parser seeds are in binary format (not text).
///
/// When use_structured=true, config_parser uses arbitrary derive which
/// produces binary corpus files in libfuzzer's custom binary format.
#[test]
fn test_config_parser_seed_is_binary_format() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    assert!(
        !seed_files.is_empty(),
        "fuzz/corpus/config_parser/ should contain at least one non-empty seed file"
    );

    // Check first seed file - it should contain non-UTF-8 bytes
    let first_seed = &seed_files[0];
    let content = fs::read(first_seed.path()).expect("Should be able to read seed file");

    // Corpus seeds for arbitrary-based targets contain binary data
    let is_valid_utf8 = std::str::from_utf8(&content).is_ok();

    assert!(
        !is_valid_utf8,
        "fuzz/corpus/config_parser/ seed '{}' appears to be UTF-8 text, but should be binary arbitrary format",
        first_seed.path().display()
    );
}
