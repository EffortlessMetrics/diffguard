# Requirements Document

## Introduction

This document defines requirements for achieving comprehensive test coverage across the diffguard workspace. The goal is to establish full BDD coverage, 100% mutation testing coverage, robust property-based testing, and thorough fuzzing coverage across all crates.

## Glossary

- **Test_Suite**: The complete collection of tests across all crates in the diffguard workspace
- **Property_Test**: A test that verifies a universal property holds across many randomly generated inputs using proptest
- **Mutation_Testing**: Testing technique that introduces small code changes (mutants) to verify tests catch them
- **Fuzz_Target**: A test harness that feeds random/semi-random inputs to find crashes or bugs
- **BDD_Test**: Behavior-Driven Development test that describes expected behavior in Given/When/Then format
- **Snapshot_Test**: A test that captures output and compares against a stored reference using insta
- **Coverage_Gap**: A code path or behavior not exercised by existing tests

## Requirements

### Requirement 1: Property-Based Testing for diffguard-types

**User Story:** As a developer, I want comprehensive property-based tests for all DTOs, so that serialization and schema validation are guaranteed correct.

#### Acceptance Criteria

1. THE Test_Suite SHALL include property tests verifying JSON serialization round-trip for all DTO types (ConfigFile, CheckReceipt, Finding, Verdict, RuleConfig, Defaults)
2. THE Test_Suite SHALL include property tests verifying TOML serialization round-trip for ConfigFile
3. THE Test_Suite SHALL include property tests verifying all generated instances validate against JSON schemas
4. WHEN arbitrary DTO instances are generated, THE Test_Suite SHALL verify serde attributes produce expected field names
5. THE Test_Suite SHALL include property tests for enum variant serialization (Severity, Scope, FailOn, VerdictStatus)

### Requirement 2: Property-Based Testing for diffguard-diff

**User Story:** As a developer, I want comprehensive property-based tests for diff parsing, so that all valid unified diffs are correctly parsed.

#### Acceptance Criteria

1. THE Test_Suite SHALL include property tests verifying parse_unified_diff returns consistent results for valid diff structures
2. WHEN a diff contains only added lines, THE Test_Suite SHALL verify Scope::Added returns all lines and Scope::Changed returns none
3. WHEN a diff contains changed lines (removed followed by added), THE Test_Suite SHALL verify both scopes return appropriate lines
4. THE Test_Suite SHALL include property tests verifying DiffStats accurately counts files and lines
5. THE Test_Suite SHALL include property tests verifying special file detection functions (is_binary_file, is_submodule, is_deleted_file, is_new_file, is_mode_change_only)
6. THE Test_Suite SHALL include property tests verifying rename parsing extracts correct source and destination paths

### Requirement 3: Property-Based Testing for diffguard-domain

**User Story:** As a developer, I want comprehensive property-based tests for rule compilation and evaluation, so that pattern matching is guaranteed correct.

#### Acceptance Criteria

1. THE Test_Suite SHALL include property tests verifying compile_rules succeeds for all valid RuleConfig combinations
2. THE Test_Suite SHALL include property tests verifying CompiledRule.applies_to correctly filters by path globs
3. THE Test_Suite SHALL include property tests verifying CompiledRule.applies_to correctly filters by language
4. THE Test_Suite SHALL include property tests verifying detect_language returns correct language for all known extensions
5. THE Test_Suite SHALL include property tests verifying Preprocessor preserves line length for all inputs
6. THE Test_Suite SHALL include property tests verifying comment masking works correctly for each supported language
7. THE Test_Suite SHALL include property tests verifying string masking works correctly for each supported language
8. THE Test_Suite SHALL include property tests verifying evaluate_lines produces correct finding counts

### Requirement 4: Property-Based Testing for diffguard-app

**User Story:** As a developer, I want comprehensive property-based tests for the application layer, so that check orchestration is guaranteed correct.

#### Acceptance Criteria

1. THE Test_Suite SHALL include property tests verifying run_check produces valid CheckReceipt for all valid inputs
2. THE Test_Suite SHALL include property tests verifying exit code computation follows documented semantics
3. THE Test_Suite SHALL include property tests verifying markdown rendering produces valid markdown for all receipts
4. THE Test_Suite SHALL include property tests verifying GitHub annotations are correctly formatted

### Requirement 5: Fuzz Testing Coverage

**User Story:** As a developer, I want comprehensive fuzz testing, so that edge cases and malformed inputs are handled safely.

#### Acceptance Criteria

1. THE Test_Suite SHALL include a fuzz target for parse_unified_diff that tests arbitrary byte sequences
2. THE Test_Suite SHALL include a fuzz target for Preprocessor.sanitize_line that tests arbitrary strings with all language modes
3. THE Test_Suite SHALL include a fuzz target for compile_rules that tests arbitrary RuleConfig structures
4. THE Test_Suite SHALL include a fuzz target for evaluate_lines that tests arbitrary InputLine sequences
5. WHEN fuzz targets receive malformed input, THE System SHALL not panic or crash
6. THE Test_Suite SHALL include a fuzz target for TOML config parsing

### Requirement 6: Mutation Testing Coverage

**User Story:** As a developer, I want 100% mutation testing coverage, so that all logic is verified by tests.

#### Acceptance Criteria

1. THE Test_Suite SHALL kill all mutants in diffguard-types crate
2. THE Test_Suite SHALL kill all mutants in diffguard-diff crate
3. THE Test_Suite SHALL kill all mutants in diffguard-domain crate
4. THE Test_Suite SHALL kill all mutants in diffguard-app crate
5. WHEN cargo-mutants identifies surviving mutants, THE Test_Suite SHALL be extended to kill them
6. THE mutants.toml configuration SHALL exclude only CLI and xtask crates

### Requirement 7: BDD Integration Tests

**User Story:** As a developer, I want BDD-style integration tests, so that end-to-end behavior is documented and verified.

#### Acceptance Criteria

1. THE Test_Suite SHALL include integration tests for the check command with various rule configurations
2. THE Test_Suite SHALL include integration tests verifying exit codes match documented semantics
3. THE Test_Suite SHALL include integration tests for config file loading and merging
4. THE Test_Suite SHALL include integration tests for path filtering with glob patterns
5. THE Test_Suite SHALL include integration tests for scope filtering (added vs changed)
6. THE Test_Suite SHALL include integration tests for fail_on behavior (error, warn, never)
7. THE Test_Suite SHALL include integration tests for max_findings truncation behavior

### Requirement 8: Snapshot Testing Coverage

**User Story:** As a developer, I want comprehensive snapshot tests, so that output format stability is guaranteed.

#### Acceptance Criteria

1. THE Test_Suite SHALL include snapshot tests for markdown output with various finding combinations
2. THE Test_Suite SHALL include snapshot tests for JSON receipt output structure
3. THE Test_Suite SHALL include snapshot tests for GitHub annotation format
4. WHEN output format changes, THE Snapshot_Test SHALL fail and require explicit approval

### Requirement 9: Edge Case Coverage

**User Story:** As a developer, I want explicit edge case tests, so that boundary conditions are handled correctly.

#### Acceptance Criteria

1. THE Test_Suite SHALL include tests for empty diff input
2. THE Test_Suite SHALL include tests for diff with no added lines
3. THE Test_Suite SHALL include tests for diff with only context lines
4. THE Test_Suite SHALL include tests for rules with empty patterns (should fail compilation)
5. THE Test_Suite SHALL include tests for rules with invalid regex patterns
6. THE Test_Suite SHALL include tests for rules with invalid glob patterns
7. THE Test_Suite SHALL include tests for Unicode content in diff lines
8. THE Test_Suite SHALL include tests for very long lines (snippet truncation)
9. THE Test_Suite SHALL include tests for max_findings boundary (exactly at limit, one over)
10. THE Test_Suite SHALL include tests for files with no extension (language detection)

### Requirement 10: Test Infrastructure

**User Story:** As a developer, I want proper test infrastructure, so that tests are maintainable and fast.

#### Acceptance Criteria

1. THE Test_Suite SHALL use proptest with minimum 100 iterations per property test
2. THE Test_Suite SHALL use insta for all snapshot tests
3. THE Test_Suite SHALL use tempfile for tests requiring filesystem operations
4. THE Test_Suite SHALL use assert_cmd for CLI integration tests
5. WHEN property tests fail, THE Test_Suite SHALL provide clear shrunk counterexamples
6. THE Test_Suite SHALL complete in under 60 seconds for the full workspace (excluding fuzz)
