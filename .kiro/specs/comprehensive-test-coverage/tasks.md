# Implementation Plan: Comprehensive Test Coverage

## Overview

This plan implements comprehensive test coverage across the diffguard workspace through property-based tests, fuzz targets, mutation testing improvements, and BDD integration tests. Tasks are organized by crate following the dependency hierarchy.

## Tasks

- [x] 1. Enhance diffguard-types property tests
  - [x] 1.1 Add TOML serialization round-trip property test for ConfigFile
    - Extend existing properties.rs with TOML round-trip test
    - Use toml crate for serialization/deserialization
    - _Requirements: 1.2_
  - [x] 1.2 Write property test for enum variant serialization round-trip
    - **Property 1: Serialization Round-Trip (enum variants)**
    - Test Severity, Scope, FailOn, VerdictStatus enums
    - **Validates: Requirements 1.5**
  - [x] 1.3 Write property test for serde field name validation
    - **Property 2: Schema Validation (field names)**
    - Verify snake_case field names in serialized JSON
    - **Validates: Requirements 1.4**

- [x] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Enhance diffguard-diff property tests
  - [x] 3.1 Add property test for diff parsing consistency
    - Verify parse_unified_diff returns identical results on repeated calls
    - _Requirements: 2.1_
  - [x] 3.2 Write property test for scope filtering correctness
    - **Property 4: Scope Filtering Correctness**
    - Verify Changed is subset of Added, pure additions return empty Changed
    - **Validates: Requirements 2.2, 2.3**
  - [ ] 3.3 Write property test for DiffStats accuracy
    - **Property 5: DiffStats Accuracy**
    - Verify file count and line count match actual results
    - **Validates: Requirements 2.4**
  - [ ] 3.4 Add edge case tests for empty diff and context-only diff
    - Test empty string input, diff with no hunks, diff with only context lines
    - _Requirements: 9.1, 9.2, 9.3_

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Enhance diffguard-domain property tests
  - [ ] 5.1 Add property test for rule compilation success
    - Test that valid RuleConfig combinations compile successfully
    - _Requirements: 3.1_
  - [ ] 5.2 Write property test for rule applicability filtering
    - **Property 9: Rule Applicability Filtering**
    - Test path glob and language filter combinations
    - **Validates: Requirements 3.2, 3.3**
  - [ ] 5.3 Write property test for preprocessor line length preservation
    - **Property 11: Preprocessor Line Length Preservation**
    - Test all Language and PreprocessOptions combinations
    - **Validates: Requirements 3.5**
  - [ ] 5.4 Add error condition tests for invalid rules
    - Test empty patterns, invalid regex, invalid globs
    - _Requirements: 9.4, 9.5, 9.6_
  - [ ] 5.5 Write property test for evaluation count accuracy
    - **Property 13: Evaluation Count Accuracy**
    - Verify counts match actual findings
    - **Validates: Requirements 3.8**

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Add diffguard-core property tests
  - [ ] 7.1 Create property test file for diffguard-core
    - Create crates/diffguard-core/tests/properties.rs
    - Add proptest dependency to Cargo.toml
    - _Requirements: 4.1_
  - [ ] 7.2 Write property test for exit code semantics
    - **Property 15: Exit Code Semantics**
    - Test all FailOn and VerdictCounts combinations
    - **Validates: Requirements 4.2**
  - [ ] 7.3 Write property test for markdown rendering validity
    - **Property 16: Markdown Rendering Validity**
    - Verify proper escaping and table structure
    - **Validates: Requirements 4.3**
  - [ ] 7.4 Write property test for annotation format correctness
    - **Property 17: Annotation Format Correctness**
    - Verify ::level file=path,line=N::rule message format
    - **Validates: Requirements 4.4**

- [ ] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Add new fuzz targets
  - [ ] 9.1 Create fuzz target for TOML config parsing
    - Create fuzz/fuzz_targets/config_parse.rs
    - Test arbitrary TOML strings against config parsing
    - _Requirements: 5.6_
  - [ ] 9.2 Create fuzz target for evaluate_lines
    - Create fuzz/fuzz_targets/evaluate_lines.rs
    - Use Arbitrary derive for structured input
    - _Requirements: 5.4_
  - [ ] 9.3 Verify existing fuzz targets compile and run
    - Test unified_diff_parser, preprocess, rule_matcher targets
    - _Requirements: 5.1, 5.2, 5.3_

- [ ] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Add BDD integration tests
  - [ ] 11.1 Add integration test for config file loading
    - Test loading from diffguard.toml, merging with CLI args
    - _Requirements: 7.3_
  - [ ] 11.2 Add integration test for path filtering
    - Test --path glob filtering behavior
    - _Requirements: 7.4_
  - [ ] 11.3 Add integration test for scope filtering
    - Test --scope added vs changed behavior
    - _Requirements: 7.5_
  - [ ] 11.4 Add integration test for fail_on behavior
    - Test exit codes for error, warn, never settings
    - _Requirements: 7.6_
  - [ ] 11.5 Add integration test for max_findings truncation
    - Test truncation behavior at boundary
    - _Requirements: 7.7, 9.9_

- [ ] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Add snapshot tests
  - [ ] 13.1 Add snapshot tests for JSON receipt output
    - Test receipt structure with various finding combinations
    - _Requirements: 8.2_
  - [ ] 13.2 Add snapshot tests for GitHub annotation format
    - Test annotation output for different severities
    - _Requirements: 8.3_

- [ ] 14. Run mutation testing and fix gaps
  - [ ] 14.1 Run cargo-mutants on diffguard-types
    - Identify and fix surviving mutants
    - _Requirements: 6.1_
  - [ ] 14.2 Run cargo-mutants on diffguard-diff
    - Identify and fix surviving mutants
    - _Requirements: 6.2_
  - [ ] 14.3 Run cargo-mutants on diffguard-domain
    - Identify and fix surviving mutants
    - _Requirements: 6.3_
  - [ ] 14.4 Run cargo-mutants on diffguard-core
    - Identify and fix surviving mutants
    - _Requirements: 6.4_

- [ ] 15. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Each property test references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- Mutation testing runs should be done after property tests are in place
