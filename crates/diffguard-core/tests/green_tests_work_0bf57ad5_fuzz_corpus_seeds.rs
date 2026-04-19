//! Green tests for fuzz corpus seed inputs (work-0bf57ad5)
//!
//! Edge case tests that confirm the implementation provides sufficient
//! corpus diversity for effective fuzzing.
//!
//! These tests verify:
//! 1. Corpus has multiple seeds (not just 1-2) for better initial coverage
//! 2. Seed files have size diversity (not all identical size)
//! 3. Seed sizes are within reasonable bounds for arbitrary binary format
//! 4. All seed files in corpus are readable (no corruption)

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Edge case: rule_matcher corpus has multiple seeds for better fuzzing coverage.
///
/// A corpus with many seeds provides better initial coverage than a single seed.
/// Fuzzers benefit from diverse inputs that exercise different code paths.
#[test]
fn test_rule_matcher_corpus_has_multiple_seeds() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    // A good corpus has multiple seeds for diversity
    // 926 seeds in rule_matcher corpus
    assert!(
        seed_files.len() >= 10,
        "fuzz/corpus/rule_matcher/ should have multiple seeds for effective fuzzing, found {}",
        seed_files.len()
    );
}

/// Edge case: config_parser corpus has multiple seeds for better fuzzing coverage.
#[test]
fn test_config_parser_corpus_has_multiple_seeds() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    // 513 seeds in config_parser corpus
    assert!(
        seed_files.len() >= 10,
        "fuzz/corpus/config_parser/ should have multiple seeds for effective fuzzing, found {}",
        seed_files.len()
    );
}

/// Edge case: rule_matcher seeds have size diversity.
///
/// Seeds with varying sizes indicate the corpus was generated with diverse inputs,
/// not just copy-pasted from a single source. This helps the fuzzer explore
/// different code paths based on input size.
#[test]
fn test_rule_matcher_seeds_have_size_diversity() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    let sizes: HashSet<u64> = seed_files
        .iter()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .collect();

    // Multiple different sizes indicate diversity
    assert!(
        sizes.len() >= 3,
        "fuzz/corpus/rule_matcher/ seeds should have size diversity, found only {} unique size(s)",
        sizes.len()
    );
}

/// Edge case: config_parser seeds have size diversity.
#[test]
fn test_config_parser_seeds_have_size_diversity() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false))
        .collect();

    let sizes: HashSet<u64> = seed_files
        .iter()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .collect();

    assert!(
        sizes.len() >= 3,
        "fuzz/corpus/config_parser/ seeds should have size diversity, found only {} unique size(s)",
        sizes.len()
    );
}

/// Edge case: rule_matcher seeds are within reasonable size bounds.
///
/// Arbitrary binary format encodes struct data - seeds should be neither
/// suspiciously small (less than 4 bytes for arbitrary header) nor
/// excessively large (more than 1KB for simple fuzz structs).
#[test]
fn test_rule_matcher_seed_sizes_within_bounds() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    for entry in seed_files {
        let metadata = entry.metadata().expect("Should be able to read metadata");
        let size = metadata.len();

        // Seeds should have content
        assert!(
            size > 0,
            "Seed file {} has zero size",
            entry.path().display()
        );

        // Seeds should be within reasonable bounds (not more than 1KB for simple structs)
        assert!(
            size <= 1024,
            "Seed file {} has suspiciously large size {} bytes",
            entry.path().display(),
            size
        );
    }
}

/// Edge case: config_parser seeds are within reasonable size bounds.
#[test]
fn test_config_parser_seed_sizes_within_bounds() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    for entry in seed_files {
        let metadata = entry.metadata().expect("Should be able to read metadata");
        let size = metadata.len();

        assert!(
            size > 0,
            "Seed file {} has zero size",
            entry.path().display()
        );

        assert!(
            size <= 1024,
            "Seed file {} has suspiciously large size {} bytes",
            entry.path().display(),
            size
        );
    }
}

/// Edge case: All rule_matcher seed files are readable.
///
/// Corrupted or unreadable seeds would cause fuzzing to fail.
#[test]
fn test_rule_matcher_all_seeds_readable() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/rule_matcher/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    for entry in seed_files {
        let content = fs::read(entry.path());
        assert!(
            content.is_ok(),
            "Seed file {} should be readable, got error: {:?}",
            entry.path().display(),
            content.err()
        );
    }
}

/// Edge case: All config_parser seed files are readable.
#[test]
fn test_config_parser_all_seeds_readable() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let entries =
        fs::read_dir(&corpus_dir).expect("fuzz/corpus/config_parser/ directory should be readable");

    let seed_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    for entry in seed_files {
        let content = fs::read(entry.path());
        assert!(
            content.is_ok(),
            "Seed file {} should be readable, got error: {:?}",
            entry.path().display(),
            content.err()
        );
    }
}

/// Edge case: rule_matcher corpus directory is accessible.
///
/// This verifies the directory has proper permissions and is not locked.
#[test]
fn test_rule_matcher_corpus_directory_accessible() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/rule_matcher");

    // Should be able to read directory contents
    let read_result = fs::read_dir(&corpus_dir);
    assert!(
        read_result.is_ok(),
        "fuzz/corpus/rule_matcher/ should be accessible, got error: {:?}",
        read_result.err()
    );

    // Should be able to stat the directory itself
    let stat_result = fs::metadata(&corpus_dir);
    assert!(
        stat_result.is_ok(),
        "fuzz/corpus/rule_matcher/ metadata should be accessible"
    );
}

/// Edge case: config_parser corpus directory is accessible.
#[test]
fn test_config_parser_corpus_directory_accessible() {
    let corpus_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz/corpus/config_parser");

    let read_result = fs::read_dir(&corpus_dir);
    assert!(
        read_result.is_ok(),
        "fuzz/corpus/config_parser/ should be accessible, got error: {:?}",
        read_result.err()
    );

    let stat_result = fs::metadata(&corpus_dir);
    assert!(
        stat_result.is_ok(),
        "fuzz/corpus/config_parser/ metadata should be accessible"
    );
}
