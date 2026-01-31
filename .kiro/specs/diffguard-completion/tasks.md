# Implementation Plan: diffguard-completion

## Overview

This implementation plan breaks down the diffguard completion work into discrete coding tasks. Each task builds incrementally on previous work, with property tests placed close to implementation to catch errors early. The plan follows the existing layered architecture (Types → Domain → App → CLI).

## Tasks

- [ ] 1. Extend language detection in diffguard-domain
  - [x] 1.1 Add multi-language support to detect_language function
    - Extend the match statement in `crates/diffguard-domain/src/rules.rs`
    - Add mappings for: py, js, ts, tsx, jsx, go, java, kt, rb, c, h, cpp, cc, cxx, hpp, cs
    - Return lowercase language identifiers
    - _Requirements: 1.1-1.13_
  
  - [x] 1.2 Write property test for language detection
    - **Property 1: Language Detection Correctness**
    - **Property 2: Unknown Extension Fallback**
    - **Validates: Requirements 1.1-1.13**

- [ ] 2. Implement language-aware preprocessing
  - [-] 2.1 Add Language enum and syntax types to preprocessor
    - Create `Language` enum in `crates/diffguard-domain/src/preprocess.rs`
    - Add `CommentSyntax` and `StringSyntax` enums
    - Implement `Language::from_str()`, `comment_syntax()`, `string_syntax()` methods
    - _Requirements: 2.1-2.8_
  
  - [~] 2.2 Extend Preprocessor to support language-specific syntax
    - Add `lang` field to `Preprocessor` struct
    - Add `with_language()` constructor and `set_language()` method
    - Modify `sanitize_line()` to use language-specific comment/string detection
    - Implement hash comment detection for Python/Ruby
    - Implement template literal detection for JavaScript
    - Implement backtick raw string detection for Go
    - Implement triple-quoted string detection for Python
    - _Requirements: 2.1-2.8_
  
  - [~] 2.3 Write property tests for language-aware preprocessing
    - **Property 3: Comment Masking by Language**
    - **Property 4: String Masking by Language**
    - **Validates: Requirements 2.1-2.8**

- [ ] 3. Update evaluator to use language-aware preprocessing
  - [~] 3.1 Pass detected language to preprocessor in evaluate_lines
    - Modify `evaluate_lines()` in `crates/diffguard-domain/src/evaluate.rs`
    - Create language-specific preprocessors based on detected language
    - Update preprocessor selection logic for ignore_comments/ignore_strings
    - _Requirements: 2.1-2.8_

- [~] 4. Checkpoint - Ensure preprocessing tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Add built-in rules for multiple languages
  - [~] 5.1 Add Python built-in rules
    - Add `python.no_print` rule (severity: warn) to `ConfigFile::built_in()`
    - Add `python.no_pdb` rule (severity: error) to `ConfigFile::built_in()`
    - Configure appropriate paths and exclude_paths
    - _Requirements: 3.1, 3.2_
  
  - [~] 5.2 Add JavaScript/TypeScript built-in rules
    - Add `js.no_console` rule (severity: warn) to `ConfigFile::built_in()`
    - Add `js.no_debugger` rule (severity: error) to `ConfigFile::built_in()`
    - Configure for both .js and .ts file extensions
    - _Requirements: 3.3, 3.4_
  
  - [~] 5.3 Add Go built-in rules
    - Add `go.no_fmt_print` rule (severity: warn) to `ConfigFile::built_in()`
    - Configure appropriate paths and exclude_paths for test files
    - _Requirements: 3.5_
  
  - [~] 5.4 Write property test for built-in rules compilation
    - **Property 5: Built-in Rules Compile Successfully**
    - **Validates: Requirements 3.6**

- [ ] 6. Enhance diff parser for special cases
  - [~] 6.1 Add detection functions for special diff content
    - Add `is_binary_file()` function to detect "Binary files ... differ"
    - Add `is_submodule()` function to detect "Subproject commit"
    - Add `is_deleted_file()` function to detect "deleted file mode"
    - Add `is_mode_change_only()` function for mode-only changes
    - Add `parse_rename()` function to extract rename paths
    - _Requirements: 4.1-4.5_
  
  - [~] 6.2 Update parse_unified_diff to handle special cases
    - Skip binary files when detected
    - Skip submodule changes when detected
    - Skip deleted files when detected
    - Skip mode-only changes when detected
    - Use new path for renamed files
    - Continue processing after malformed content
    - _Requirements: 4.1-4.6_
  
  - [~] 6.3 Write property tests for enhanced diff parsing
    - **Property 6: Diff Parser Skips Special Files**
    - **Property 7: Diff Parser Handles Renames**
    - **Property 8: Diff Parser Resilience**
    - **Validates: Requirements 4.1-4.6**

- [~] 7. Checkpoint - Ensure diff parser tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Generate and commit JSON schemas
  - [~] 8.1 Run xtask schema and commit results
    - Execute `cargo run -p xtask -- schema`
    - Verify `schemas/diffguard.config.schema.json` is created
    - Verify `schemas/diffguard.check.schema.json` is created
    - _Requirements: 5.1, 5.2_
  
  - [~] 8.2 Write property test for schema validation
    - **Property 9: Schema Validation Round-Trip**
    - Add `jsonschema` dev dependency for validation
    - Generate random ConfigFile/CheckReceipt instances
    - Serialize to JSON and validate against schemas
    - **Validates: Requirements 5.3, 5.4**

- [ ] 9. Add error message context tests
  - [~] 9.1 Write property test for error messages
    - **Property 10: Error Messages Contain Context**
    - Test invalid regex returns error with rule_id and pattern
    - Test invalid glob returns error with rule_id and glob
    - Test missing patterns returns error with rule_id
    - **Validates: Requirements 6.1, 6.2, 6.3**

- [ ] 10. Add snapshot tests for markdown output
  - [~] 10.1 Add insta dependency and create snapshot tests
    - Add `insta` to dev-dependencies in `diffguard-app/Cargo.toml`
    - Create snapshot test for markdown with findings
    - Create snapshot test for markdown with no findings
    - Create snapshot test for verdict rendering
    - _Requirements: 7.1-7.4_

- [ ] 11. Create rule matcher fuzz target
  - [~] 11.1 Implement fuzz target for evaluate_lines
    - Create `fuzz/fuzz_targets/rule_matcher.rs`
    - Add `arbitrary` dependency to fuzz crate
    - Generate random input lines and rule patterns
    - Exercise evaluate_lines without panicking
    - _Requirements: 8.1-8.4_

- [ ] 12. Add comprehensive unit tests
  - [~] 12.1 Add diff parser edge case tests
    - Test empty hunks
    - Test multiple files in single diff
    - Test Unicode content in diff lines
    - _Requirements: 9.1, 9.2, 9.6_
  
  - [~] 12.2 Add preprocessor state tests
    - Test multi-line block comments
    - Test multi-line strings
    - Test state reset between files
    - _Requirements: 9.3_
  
  - [~] 12.3 Add rule matching tests
    - Test overlapping patterns (first match wins)
    - Test complex glob patterns
    - Test language filtering edge cases
    - _Requirements: 9.4, 9.5_

- [~] 13. Final checkpoint - Run full test suite
  - Ensure all tests pass, ask the user if questions arise.
  - Run `cargo test --workspace`
  - Run `cargo clippy --workspace --all-targets -- -D warnings`
  - Run `cargo fmt --check`

## Notes

- All tasks are required for comprehensive testing
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation follows the existing layered architecture
