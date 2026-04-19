//! Dependency structure tests for diffguard-bench.
//!
//! These tests verify that the Cargo.toml dependency structure is correct,
//! ensuring no redundant compilations due to duplicate dependencies.
//!
//! Key invariants:
//! - `diffguard-core` appears exactly ONCE in bench/Cargo.toml
//! - `diffguard-core` is ONLY in [dev-dependencies], not in [dependencies]
//! - Library code (lib.rs, fixtures.rs) does not transitively need diffguard-core

use std::env;
use std::fs;

/// Get the path to the bench crate directory.
fn bench_crate_dir() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR points to the crate root (where Cargo.toml is)
    env::var("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Count occurrences of a dependency name in a Cargo.toml file content.
fn count_dependency_occurrences(content: &str, dep_name: &str) -> usize {
    let mut count = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        // Match dependency declarations (not comments, not workspace entries)
        // Must be at start of line, followed by = (not part of a path)
        if trimmed.starts_with(dep_name)
            && trimmed.len() > dep_name.len()
            && trimmed[dep_name.len()..].trim().starts_with('=')
        {
            count += 1;
        }
    }
    count
}

/// Check if a dependency appears in the [dependencies] section (not [dev-dependencies]).
fn dep_in_dependencies_section(content: &str, dep_name: &str) -> bool {
    // Find the [dependencies] section
    let deps_section_start = content.find("[dependencies]");
    let dev_deps_section_start = content.find("[dev-dependencies]");

    if let Some(deps_pos) = deps_section_start {
        // Determine where [dependencies] ends
        let deps_end = dev_deps_section_start.unwrap_or(content.len());

        // Check if the dependency is declared within [dependencies]
        let deps_section = &content[deps_pos..deps_end];

        let mut found_section_header = false;
        for line in deps_section.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Skip the section header itself (first [dependencies] line)
            if trimmed.starts_with('[') {
                if found_section_header {
                    break; // Another section started
                }
                found_section_header = true;
                continue;
            }
            if trimmed.starts_with(dep_name)
                && trimmed.len() > dep_name.len()
                && trimmed[dep_name.len()..].trim().starts_with('=')
            {
                return true;
            }
        }
    }
    false
}

/// Check if a dependency appears in the [dev-dependencies] section.
fn dep_in_dev_dependencies_section(content: &str, dep_name: &str) -> bool {
    // Find the [dev-dependencies] section
    if let Some(dev_deps_pos) = content.find("[dev-dependencies]") {
        let dev_deps_section = &content[dev_deps_pos..];

        let mut found_section_header = false;
        for line in dev_deps_section.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') {
                if found_section_header {
                    break; // Another section started
                }
                found_section_header = true;
                continue;
            }
            if trimmed.starts_with(dep_name)
                && trimmed.len() > dep_name.len()
                && trimmed[dep_name.len()..].trim().starts_with('=')
            {
                return true;
            }
        }
    }
    false
}

#[test]
fn test_diffguard_core_appears_exactly_once() {
    let manifest_dir = bench_crate_dir();
    let cargo_toml_path = manifest_dir.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", cargo_toml_path, e));

    let count = count_dependency_occurrences(&cargo_toml, "diffguard-core");

    assert_eq!(
        count, 1,
        "diffguard-core should appear exactly ONCE in bench/Cargo.toml, but found {} occurrences. \
         This causes redundant compilation of diffguard-core when building benchmarks/tests.",
        count
    );
}

#[test]
fn test_diffguard_core_not_in_dependencies_section() {
    let manifest_dir = bench_crate_dir();
    let cargo_toml_path = manifest_dir.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", cargo_toml_path, e));

    assert!(
        !dep_in_dependencies_section(&cargo_toml, "diffguard-core"),
        "diffguard-core should NOT be in [dependencies] section. \
         It is only needed by benchmarks and tests, not by the library itself. \
         Having it in [dependencies] causes redundant compilation."
    );
}

#[test]
fn test_diffguard_core_only_in_dev_dependencies() {
    let manifest_dir = bench_crate_dir();
    let cargo_toml_path = manifest_dir.join("Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", cargo_toml_path, e));

    let in_deps = dep_in_dependencies_section(&cargo_toml, "diffguard-core");
    let in_dev_deps = dep_in_dev_dependencies_section(&cargo_toml, "diffguard-core");

    assert!(
        !in_deps && in_dev_deps,
        "diffguard-core should only appear in [dev-dependencies], not in [dependencies]. \
         Benchmark code (benches/rendering.rs) and test code (tests/snapshot_tests.rs) use it, \
         but library code (lib.rs, fixtures.rs) does not. \
         Currently in [dependencies]: {}, in [dev-dependencies]: {}",
        in_deps,
        in_dev_deps
    );
}

#[test]
fn test_library_does_not_need_diffguard_core() {
    // This test verifies that the library portion of diffguard-bench
    // (lib.rs and fixtures.rs) does NOT use diffguard-core directly.
    //
    // If this test passes, it confirms that removing diffguard-core from
    // [dependencies] will not break the library compilation.

    let manifest_dir = bench_crate_dir();
    let lib_rs_path = manifest_dir.join("lib.rs");
    let fixtures_rs_path = manifest_dir.join("fixtures.rs");

    let lib_rs = fs::read_to_string(&lib_rs_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", lib_rs_path, e));
    let fixtures_rs = fs::read_to_string(&fixtures_rs_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", fixtures_rs_path, e));

    let lib_has_core = lib_rs.contains("diffguard_core");
    let fixtures_has_core = fixtures_rs.contains("diffguard_core");

    assert!(
        !lib_has_core && !fixtures_has_core,
        "Library code (lib.rs, fixtures.rs) should not use diffguard-core directly. \
         If library code uses diffguard-core, it MUST be in [dependencies]. \
         lib.rs uses diffguard_core: {}, fixtures.rs uses diffguard_core: {}",
        lib_has_core,
        fixtures_has_core
    );
}
