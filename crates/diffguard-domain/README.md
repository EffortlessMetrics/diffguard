# diffguard-domain

Pure rule-domain logic for diffguard.

This crate performs rule compilation, line evaluation, preprocessing, directory
override resolution, and inline suppression handling. It contains no process,
filesystem, or environment I/O.

## Public Modules

- `rules` - compile `RuleConfig` to `CompiledRule`, detect languages
- `evaluate` - evaluate `InputLine` streams against compiled rules
- `preprocess` - best-effort comment/string masking by language
- `overrides` - compile and resolve per-directory rule overrides
- `suppression` - parse `diffguard: ignore...` directives

## Core Flow

```rust
use diffguard_domain::{compile_rules, evaluate_lines, InputLine};
use diffguard_types::ConfigFile;

let config = ConfigFile::built_in();
let rules = compile_rules(&config.rule)?;

let lines = vec![
    InputLine {
        path: "src/main.rs".to_string(),
        line: 10,
        content: "let x = maybe.unwrap();".to_string(),
    },
];

let evaluation = evaluate_lines(lines, &rules, 200);
println!("findings={}", evaluation.findings.len());
println!("warn={}", evaluation.counts.warn);
println!("error={}", evaluation.counts.error);
println!("suppressed={}", evaluation.counts.suppressed);
```

## Advanced Evaluation Entrypoints

- `evaluate_lines_with_overrides(...)`
- `evaluate_lines_with_overrides_and_language(...)`

These are used by callers that provide compiled directory overrides or a forced
language override for preprocessing/rule language filtering.

## Language and Preprocessing

- `detect_language(&Path) -> Option<&'static str>`
- `Preprocessor` + `PreprocessOptions` for masking comments and/or strings

Masking is intentionally heuristic and deterministic, not a full parser.

## Suppression Directives

Supported inline suppressions include:

- `diffguard: ignore <rule_id>`
- `diffguard: ignore-next-line <rule_id>`
- `diffguard: ignore rule1, rule2`
- `diffguard: ignore *`
- `diffguard: ignore-all`

Suppressed matches are tracked in `VerdictCounts.suppressed`.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
