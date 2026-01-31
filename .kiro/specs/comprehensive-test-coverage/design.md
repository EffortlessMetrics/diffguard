# Design Document: Comprehensive Test Coverage

## Overview

This design establishes a systematic approach to achieving comprehensive test coverage across the diffguard workspace. The strategy combines property-based testing (proptest), fuzz testing (libFuzzer), mutation testing (cargo-mutants), snapshot testing (insta), and BDD-style integration tests to ensure correctness at all layers.

The testing architecture follows the crate dependency hierarchy:
- **diffguard-types**: DTO serialization and schema validation
- **diffguard-diff**: Unified diff parsing
- **diffguard-domain**: Rule compilation, evaluation, and preprocessing
- **diffguard-app**: Check orchestration and rendering
- **diffguard (CLI)**: End-to-end integration tests

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Categories                          │
├─────────────────────────────────────────────────────────────────┤
│  Property Tests    │  Fuzz Tests    │  Integration Tests        │
│  (proptest)        │  (libFuzzer)   │  (assert_cmd)             │
├────────────────────┼────────────────┼───────────────────────────┤
│  - Round-trip      │  - Crash       │  - CLI behavior           │
│  - Invariants      │    resistance  │  - Exit codes             │
│  - Metamorphic     │  - Edge cases  │  - Config loading         │
│  - Schema valid.   │  - Malformed   │  - Output formats         │
└────────────────────┴────────────────┴───────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Mutation Testing                            │
│                     (cargo-mutants)                             │
├─────────────────────────────────────────────────────────────────┤
│  Validates that tests actually catch bugs by introducing        │
│  small code changes and verifying tests fail                    │
└─────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Property Test Generators (proptest strategies)

Each crate requires custom proptest strategies to generate valid test inputs:

```rust
// diffguard-types generators
mod arb {
    fn severity() -> impl Strategy<Value = Severity>;
    fn scope() -> impl Strategy<Value = Scope>;
    fn fail_on() -> impl Strategy<Value = FailOn>;
    fn verdict_status() -> impl Strategy<Value = VerdictStatus>;
    fn rule_config() -> impl Strategy<Value = RuleConfig>;
    fn config_file() -> impl Strategy<Value = ConfigFile>;
    fn finding() -> impl Strategy<Value = Finding>;
    fn check_receipt() -> impl Strategy<Value = CheckReceipt>;
}

// diffguard-diff generators
mod arb {
    fn file_path() -> impl Strategy<Value = String>;
    fn diff_line() -> impl Strategy<Value = String>;
    fn hunk_header(start: u32, count: u32) -> String;
    fn unified_diff() -> impl Strategy<Value = String>;
    fn binary_diff() -> impl Strategy<Value = String>;
    fn submodule_diff() -> impl Strategy<Value = String>;
    fn rename_diff() -> impl Strategy<Value = String>;
}

// diffguard-domain generators
mod arb {
    fn language() -> impl Strategy<Value = Language>;
    fn code_line() -> impl Strategy<Value = String>;
    fn comment_line(lang: Language) -> impl Strategy<Value = String>;
    fn string_literal(lang: Language) -> impl Strategy<Value = String>;
    fn input_line() -> impl Strategy<Value = InputLine>;
}
```

### 2. Fuzz Target Structure

Each fuzz target follows a consistent pattern:

```rust
// fuzz/fuzz_targets/{target}.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Structured input fields
}

fuzz_target!(|input: FuzzInput| {
    // Exercise the code under test
    // No assertions - just verify no panics/crashes
});
```

### 3. Integration Test Fixtures

BDD-style integration tests use a fixture pattern:

```rust
// tests/cli_check.rs
struct TestRepo {
    dir: TempDir,
    base_commit: String,
}

impl TestRepo {
    fn new() -> Self;
    fn add_file(&self, path: &str, content: &str);
    fn commit(&self, message: &str) -> String;
    fn run_diffguard(&self, args: &[&str]) -> Command;
}
```

### 4. Snapshot Test Organization

Snapshot tests are organized by output type:

```
crates/diffguard-app/src/snapshots/
├── render__markdown_with_findings.snap
├── render__markdown_no_findings.snap
├── render__verdict_rendering.snap
└── check__receipt_structure.snap
```

## Data Models

### Test Configuration

```rust
/// Property test configuration
struct PropertyTestConfig {
    cases: u32,           // Minimum 100
    max_shrink_iters: u32,
}

/// Fuzz target configuration  
struct FuzzConfig {
    max_len: usize,       // Maximum input size
    timeout: Duration,    // Per-iteration timeout
}

/// Mutation test configuration (mutants.toml)
struct MutantsConfig {
    exclude_globs: Vec<String>,
    timeout_multiplier: f64,
}
```

### Test Coverage Metrics

```rust
/// Coverage report structure
struct CoverageReport {
    crate_name: String,
    mutants_killed: u32,
    mutants_total: u32,
    property_tests: u32,
    fuzz_targets: u32,
    integration_tests: u32,
}
```

### Generator Output Types

```rust
/// Generated diff structure for property tests
struct GeneratedDiff {
    files: Vec<GeneratedFile>,
    expected_lines: Vec<DiffLine>,
    expected_stats: DiffStats,
}

struct GeneratedFile {
    path: String,
    hunks: Vec<GeneratedHunk>,
}

struct GeneratedHunk {
    old_start: u32,
    new_start: u32,
    context_lines: Vec<String>,
    removed_lines: Vec<String>,
    added_lines: Vec<String>,
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Serialization Round-Trip

*For any* valid DTO instance (ConfigFile, CheckReceipt, Finding, Verdict, RuleConfig, Defaults, or enum variant), serializing to JSON/TOML and deserializing back SHALL produce an equivalent value.

**Validates: Requirements 1.1, 1.2, 1.5**

### Property 2: Schema Validation

*For any* valid DTO instance generated by proptest strategies, serializing to JSON and validating against the corresponding JSON schema SHALL succeed without errors.

**Validates: Requirements 1.3, 1.4**

### Property 3: Diff Parsing Consistency

*For any* well-formed unified diff string, calling `parse_unified_diff` twice with the same scope SHALL return identical results (same DiffLines in same order).

**Validates: Requirements 2.1**

### Property 4: Scope Filtering Correctness

*For any* unified diff, the set of lines returned by `Scope::Changed` SHALL be a subset of lines returned by `Scope::Added`, and for pure additions (no removed lines), `Scope::Changed` SHALL return empty.

**Validates: Requirements 2.2, 2.3**

### Property 5: DiffStats Accuracy

*For any* parsed diff result, `DiffStats.files` SHALL equal the count of unique file paths in the returned DiffLines, and `DiffStats.lines` SHALL equal the total count of DiffLines.

**Validates: Requirements 2.4**

### Property 6: Special File Detection

*For any* line matching the documented pattern for binary files, submodules, deleted files, new files, or mode changes, the corresponding detection function SHALL return true; for non-matching lines, it SHALL return false.

**Validates: Requirements 2.5**

### Property 7: Rename Path Extraction

*For any* rename line in the format "rename from {path}" or "rename to {path}", the corresponding parse function SHALL extract exactly the path portion.

**Validates: Requirements 2.6**

### Property 8: Rule Compilation Success

*For any* RuleConfig with non-empty patterns containing valid regex and valid glob patterns, `compile_rules` SHALL succeed and return a CompiledRule with the same number of patterns.

**Validates: Requirements 3.1**

### Property 9: Rule Applicability Filtering

*For any* CompiledRule with path globs and language filters, `applies_to(path, language)` SHALL return true if and only if the path matches at least one include glob (or include is empty), matches no exclude globs, and the language matches the filter (or filter is empty).

**Validates: Requirements 3.2, 3.3**

### Property 10: Language Detection Correctness

*For any* file path with a known extension (rs, py, js, ts, tsx, jsx, go, java, kt, rb, c, h, cpp, cc, cxx, hpp, cs), `detect_language` SHALL return the documented language identifier; for unknown extensions, it SHALL return None.

**Validates: Requirements 3.4**

### Property 11: Preprocessor Line Length Preservation

*For any* input string and any combination of PreprocessOptions and Language, `Preprocessor.sanitize_line` SHALL return a string with exactly the same byte length as the input.

**Validates: Requirements 3.5, 9.7, 9.8**

### Property 12: Preprocessing Masking Correctness

*For any* source line containing comments or strings in the language's documented syntax, when the corresponding mask option is enabled, the preprocessor SHALL replace the comment/string content with spaces while preserving non-comment/string content.

**Validates: Requirements 3.6, 3.7**

### Property 13: Evaluation Count Accuracy

*For any* set of InputLines and CompiledRules, the `VerdictCounts` in the Evaluation SHALL accurately reflect the count of findings by severity (info, warn, error), and `findings.len() + truncated_findings` SHALL equal the total count.

**Validates: Requirements 3.8**

### Property 14: CheckReceipt Validity

*For any* valid CheckPlan, ConfigFile, and diff text, `run_check` SHALL produce a CheckReceipt that validates against the check schema and contains consistent internal data (counts match findings, stats match diff).

**Validates: Requirements 4.1**

### Property 15: Exit Code Semantics

*For any* FailOn setting and VerdictCounts combination, `compute_exit_code` SHALL return: 0 if FailOn::Never, 2 if error > 0, 3 if FailOn::Warn and warn > 0, else 0.

**Validates: Requirements 4.2**

### Property 16: Markdown Rendering Validity

*For any* CheckReceipt, the rendered markdown SHALL contain properly escaped pipe and backtick characters, valid table structure, and all finding information.

**Validates: Requirements 4.3**

### Property 17: Annotation Format Correctness

*For any* Finding, the rendered GitHub annotation SHALL follow the format `::level file=path,line=N::rule message` where level is notice/warning/error based on severity.

**Validates: Requirements 4.4**

### Property 18: Fuzz Target Crash Resistance

*For any* arbitrary byte sequence or structured input, fuzz targets SHALL not panic, crash, or exhibit undefined behavior.

**Validates: Requirements 5.5**

## Error Handling

### Compilation Errors

| Error Type | Condition | Handling |
|------------|-----------|----------|
| `RuleCompileError::MissingPatterns` | Rule has empty patterns vec | Return error, do not compile |
| `RuleCompileError::InvalidRegex` | Pattern fails regex compilation | Return error with pattern and source |
| `RuleCompileError::InvalidGlob` | Glob fails compilation | Return error with glob and source |

### Parse Errors

| Error Type | Condition | Handling |
|------------|-----------|----------|
| `DiffParseError::MalformedHunkHeader` | Hunk header doesn't match format | Skip hunk, continue parsing |

### Runtime Errors

| Error Type | Condition | Handling |
|------------|-----------|----------|
| Invalid UTF-8 in diff | Diff contains non-UTF-8 bytes | Use lossy conversion |
| Fuzz input causes panic | Arbitrary input triggers panic | Test failure (must fix) |

## Testing Strategy

### Dual Testing Approach

The test suite uses complementary testing methods:

1. **Property-Based Tests (proptest)**: Verify universal properties across randomly generated inputs
   - Minimum 100 iterations per property
   - Shrinking enabled for counterexample minimization
   - Each test tagged with property number and requirements

2. **Unit Tests**: Verify specific examples and edge cases
   - Edge cases: empty input, boundary conditions, error conditions
   - Integration points between components
   - Regression tests for fixed bugs

### Property-Based Testing Configuration

```rust
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    // Feature: comprehensive-test-coverage, Property N: Property Title
    // **Validates: Requirements X.Y**
    #[test]
    fn property_name(input in strategy()) {
        // Property assertion
    }
}
```

### Fuzz Testing Configuration

Fuzz targets use `libFuzzer` via `cargo-fuzz`:

```rust
// Each fuzz target in fuzz/fuzz_targets/
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise code, verify no panics
});
```

Recommended fuzzing duration: 1+ hours per target for thorough coverage.

### Mutation Testing Configuration

`mutants.toml` configuration:

```toml
exclude_globs = [
  "crates/diffguard/src/**",  # CLI - I/O heavy
  "xtask/src/**",              # Build tooling
  "fuzz/**",                   # Fuzz harnesses
]
```

Target: 100% mutant kill rate for included crates.

### Snapshot Testing

Use `insta` for output stability:

```rust
#[test]
fn snapshot_markdown_output() {
    let receipt = create_test_receipt();
    let md = render_markdown_for_receipt(&receipt);
    insta::assert_snapshot!(md);
}
```

### Integration Testing

BDD-style tests using `assert_cmd` and `tempfile`:

```rust
#[test]
fn given_unwrap_in_diff_when_check_then_exit_2() {
    let repo = TestRepo::new();
    repo.add_file("src/lib.rs", "fn f() { x.unwrap() }");
    repo.commit("add unwrap");
    
    repo.run_diffguard(&["check"])
        .assert()
        .code(2);
}
```

### Test Organization by Crate

| Crate | Property Tests | Fuzz Targets | Unit Tests | Integration Tests |
|-------|---------------|--------------|------------|-------------------|
| diffguard-types | 2 (round-trip, schema) | 1 (toml parse) | Enum tests | - |
| diffguard-diff | 5 (parse, scope, stats, detect, rename) | 1 (unified_diff_parser) | Edge cases | - |
| diffguard-domain | 6 (compile, applies_to, detect, preprocess) | 2 (preprocess, rule_matcher) | Language tests | - |
| diffguard-app | 4 (check, exit, markdown, annotations) | 1 (evaluate_lines) | Render tests | - |
| diffguard (CLI) | - | - | - | BDD tests |

