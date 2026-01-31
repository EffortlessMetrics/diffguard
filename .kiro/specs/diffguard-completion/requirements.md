# Requirements Document

## Introduction

This document specifies the requirements for completing the diffguard implementation. Diffguard is a diff-scoped governance linter that applies rules only to added/changed lines in a Git diff, designed for PR automation workflows. The current implementation has a working foundation but needs enhancements in language detection, built-in rules, diff parsing robustness, schema generation, and testing coverage.

## Glossary

- **Diff_Parser**: The component that parses unified diff output from git and extracts added/changed lines
- **Preprocessor**: The component that masks comments and string literals in source code for rule evaluation
- **Rule_Compiler**: The component that compiles rule configurations into executable matchers with regex and glob patterns
- **Evaluator**: The component that matches compiled rules against input lines and produces findings
- **Language_Detector**: The component that determines the programming language of a file based on its extension
- **Schema_Generator**: The xtask component that generates JSON schemas for config and receipt types
- **Finding**: A single rule violation detected in the diff
- **Receipt**: The JSON output document containing all findings and verdict information

## Requirements

### Requirement 1: Multi-Language Detection

**User Story:** As a developer, I want diffguard to detect multiple programming languages by file extension, so that language-specific rules can be applied correctly across polyglot codebases.

#### Acceptance Criteria

1. WHEN a file with extension `.py` is processed, THE Language_Detector SHALL return "python"
2. WHEN a file with extension `.js` is processed, THE Language_Detector SHALL return "javascript"
3. WHEN a file with extension `.ts` is processed, THE Language_Detector SHALL return "typescript"
4. WHEN a file with extension `.tsx` is processed, THE Language_Detector SHALL return "typescript"
5. WHEN a file with extension `.jsx` is processed, THE Language_Detector SHALL return "javascript"
6. WHEN a file with extension `.go` is processed, THE Language_Detector SHALL return "go"
7. WHEN a file with extension `.java` is processed, THE Language_Detector SHALL return "java"
8. WHEN a file with extension `.kt` is processed, THE Language_Detector SHALL return "kotlin"
9. WHEN a file with extension `.rb` is processed, THE Language_Detector SHALL return "ruby"
10. WHEN a file with extension `.c` or `.h` is processed, THE Language_Detector SHALL return "c"
11. WHEN a file with extension `.cpp`, `.cc`, `.cxx`, or `.hpp` is processed, THE Language_Detector SHALL return "cpp"
12. WHEN a file with extension `.cs` is processed, THE Language_Detector SHALL return "csharp"
13. WHEN a file with an unrecognized extension is processed, THE Language_Detector SHALL return None

### Requirement 2: Language-Specific Preprocessing

**User Story:** As a developer, I want the preprocessor to correctly handle comment and string syntax for different languages, so that ignore_comments and ignore_strings work correctly across languages.

#### Acceptance Criteria

1. WHEN processing Python code with ignore_comments enabled, THE Preprocessor SHALL mask `#` line comments
2. WHEN processing Python code with ignore_strings enabled, THE Preprocessor SHALL mask single-quoted, double-quoted, and triple-quoted strings
3. WHEN processing JavaScript/TypeScript code with ignore_comments enabled, THE Preprocessor SHALL mask `//` line comments and `/* */` block comments
4. WHEN processing JavaScript/TypeScript code with ignore_strings enabled, THE Preprocessor SHALL mask single-quoted, double-quoted, and template literal strings
5. WHEN processing Go code with ignore_comments enabled, THE Preprocessor SHALL mask `//` line comments and `/* */` block comments
6. WHEN processing Go code with ignore_strings enabled, THE Preprocessor SHALL mask double-quoted strings and backtick raw strings
7. WHEN processing Ruby code with ignore_comments enabled, THE Preprocessor SHALL mask `#` line comments
8. WHEN processing code for an unsupported language, THE Preprocessor SHALL fall back to C-style comment syntax (`//` and `/* */`)

### Requirement 3: Additional Built-in Rules

**User Story:** As a developer, I want diffguard to include built-in rules for common patterns across multiple languages, so that I can catch policy violations without extensive configuration.

#### Acceptance Criteria

1. THE ConfigFile::built_in() SHALL include a rule for Python that detects `print(` statements with severity warn
2. THE ConfigFile::built_in() SHALL include a rule for Python that detects `import pdb` or `pdb.set_trace()` with severity error
3. THE ConfigFile::built_in() SHALL include a rule for JavaScript/TypeScript that detects `console.log` with severity warn
4. THE ConfigFile::built_in() SHALL include a rule for JavaScript/TypeScript that detects `debugger` statements with severity error
5. THE ConfigFile::built_in() SHALL include a rule for Go that detects `fmt.Println` or `fmt.Printf` with severity warn
6. WHEN built-in rules are loaded, THE Rule_Compiler SHALL successfully compile all patterns without errors

### Requirement 4: Enhanced Diff Parsing

**User Story:** As a developer, I want the diff parser to gracefully handle binary files, submodules, and renames, so that diffguard doesn't fail on complex diffs.

#### Acceptance Criteria

1. WHEN a diff contains a binary file marker (`Binary files ... differ`), THE Diff_Parser SHALL skip the file without error
2. WHEN a diff contains a submodule change (`Subproject commit`), THE Diff_Parser SHALL skip the submodule without error
3. WHEN a diff contains a file rename (`rename from`/`rename to`), THE Diff_Parser SHALL use the new path for findings
4. WHEN a diff contains a mode change only (no content), THE Diff_Parser SHALL skip the file without error
5. WHEN a diff contains a deleted file (`deleted file mode`), THE Diff_Parser SHALL skip the file without error
6. IF the diff contains malformed content after a valid header, THEN THE Diff_Parser SHALL continue processing subsequent files

### Requirement 5: JSON Schema Generation

**User Story:** As a developer, I want JSON schemas generated and committed to the schemas/ directory, so that config files and receipts can be validated by external tools.

#### Acceptance Criteria

1. WHEN `xtask schema` is run, THE Schema_Generator SHALL create `schemas/diffguard.config.schema.json`
2. WHEN `xtask schema` is run, THE Schema_Generator SHALL create `schemas/diffguard.check.schema.json`
3. THE generated config schema SHALL validate all fields in ConfigFile including defaults and rule arrays
4. THE generated receipt schema SHALL validate all fields in CheckReceipt including findings and verdict

### Requirement 6: Improved Error Handling

**User Story:** As a developer, I want clear error messages when configuration is invalid, so that I can quickly fix issues.

#### Acceptance Criteria

1. IF a rule has an invalid regex pattern, THEN THE Rule_Compiler SHALL return an error message containing the rule ID and the invalid pattern
2. IF a rule has an invalid glob pattern, THEN THE Rule_Compiler SHALL return an error message containing the rule ID and the invalid glob
3. IF a rule has no patterns defined, THEN THE Rule_Compiler SHALL return an error message indicating the rule ID
4. IF the config file contains invalid TOML syntax, THEN THE CLI SHALL exit with code 1 and display the parse error location
5. IF git diff fails, THEN THE CLI SHALL exit with code 1 and display the git error message

### Requirement 7: Snapshot Testing for Markdown Output

**User Story:** As a developer, I want snapshot tests for markdown output, so that output format changes are detected and reviewed.

#### Acceptance Criteria

1. THE test suite SHALL include snapshot tests using insta for markdown rendering
2. WHEN findings are rendered to markdown, THE snapshot test SHALL capture the complete table format
3. WHEN the verdict is rendered to markdown, THE snapshot test SHALL capture the header and summary format
4. WHEN no findings exist, THE snapshot test SHALL capture the "No findings" output

### Requirement 8: Rule Matcher Fuzz Target

**User Story:** As a developer, I want a fuzz target for rule matching, so that edge cases in pattern matching are discovered.

#### Acceptance Criteria

1. THE fuzz target SHALL exercise the evaluate_lines function with random input lines
2. THE fuzz target SHALL use randomly generated rule configurations
3. THE fuzz target SHALL not panic on any valid UTF-8 input
4. THE fuzz target SHALL be located at `fuzz/fuzz_targets/rule_matcher.rs`

### Requirement 9: Comprehensive Unit Test Coverage

**User Story:** As a developer, I want comprehensive unit tests for edge cases, so that the codebase is robust and maintainable.

#### Acceptance Criteria

1. THE test suite SHALL include tests for diff parsing with empty hunks
2. THE test suite SHALL include tests for diff parsing with multiple files
3. THE test suite SHALL include tests for preprocessor state across multiple lines (multi-line strings/comments)
4. THE test suite SHALL include tests for rule matching with overlapping patterns
5. THE test suite SHALL include tests for path glob matching with complex patterns
6. THE test suite SHALL include tests for Unicode content in diff lines
7. WHEN all tests pass, THE mutation testing coverage SHALL have no surviving mutants in critical paths
