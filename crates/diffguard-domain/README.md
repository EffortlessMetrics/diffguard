# diffguard-domain

Domain logic for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This crate contains the core business logic: rule compilation, line evaluation, text preprocessing, and inline suppression handling. It is I/O-free and designed for high testability with pure functions.

## Modules

| Module | Purpose |
|--------|---------|
| `rules` | Compile `RuleConfig` → `CompiledRule` with regex/glob matchers |
| `evaluate` | Match lines against compiled rules, produce findings |
| `preprocess` | Mask comments/strings before pattern matching |
| `suppression` | Parse and track `diffguard: ignore` directives |

## Usage

```rust
use diffguard_domain::{compile_rules, evaluate_lines, InputLine};
use diffguard_types::ConfigFile;

// Compile rules from config
let config = ConfigFile::built_in();
let rules = compile_rules(&config.rules)?;

// Prepare input lines (typically from diffguard-diff)
let lines = vec![
    InputLine {
        path: "src/main.rs".to_string(),
        line_no: 10,
        content: "    .unwrap()".to_string(),
        kind: ChangeKind::Added,
    },
];

// Evaluate and get findings
let evaluation = evaluate_lines(&rules, &lines);

println!("Findings: {}", evaluation.findings.len());
println!("Errors: {}", evaluation.counts.errors);
println!("Warnings: {}", evaluation.counts.warnings);
println!("Suppressed: {}", evaluation.counts.suppressed);
```

## Rule Compilation

Rules are compiled once and reused for all lines:

```rust
use diffguard_domain::{compile_rules, CompiledRule};

let rules: Vec<CompiledRule> = compile_rules(&config.rules)?;

// CompiledRule contains:
// - Pre-compiled regex patterns
// - GlobSets for path include/exclude
// - Language filters
// - Preprocessor options
```

## Language Detection

Automatic language detection from file extensions:

```rust
use diffguard_domain::detect_language;

let lang = detect_language("src/main.rs");  // Some(Language::Rust)
let lang = detect_language("app.py");       // Some(Language::Python)
let lang = detect_language("unknown.xyz");  // None
```

Supported languages: Rust, Python, JavaScript, TypeScript, Go, Ruby, C, C++, C#, Java, Kotlin, Shell

## Preprocessing

Best-effort comment/string masking using C-like syntax heuristics:

```rust
use diffguard_domain::{Preprocessor, PreprocessOptions, Language};

let preprocessor = Preprocessor::new(Language::Rust, PreprocessOptions {
    ignore_comments: true,
    ignore_strings: true,
});

// Original: let x = "TODO: fix"; // TODO: important
// Masked:   let x = "         "; //
let masked = preprocessor.sanitize(line);
```

**Note:** Preprocessing is intentionally simple and best-effort. It uses C-like syntax heuristics rather than full language parsers.

## Inline Suppressions

Support for inline directives to suppress specific findings:

```rust
// Suppress on same line
let x = get_value().unwrap(); // diffguard: ignore rust.no_unwrap

// Suppress on next line
// diffguard: ignore-next-line rust.no_unwrap
let x = get_value().unwrap();

// Suppress multiple rules
let x = foo(); // diffguard: ignore rule1, rule2

// Suppress all rules
let x = foo(); // diffguard: ignore *
// or: diffguard: ignore-all
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
