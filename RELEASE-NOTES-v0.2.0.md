# diffguard v0.2.0

First public release — diff-scoped governance linter for PR automation.

## What's new

### Core
- Diff-scoped linting: only checks added/changed lines
- Deterministic JSON receipts, Markdown summaries, GitHub Actions annotations
- Clean architecture: I/O at edges, pure logic in core crates
- Config inheritance and composition (`includes = [...]`)
- Per-directory rule overrides (`.diffguard.toml` lookup)
- Environment variable expansion in config (`${VAR}`, `${VAR:-default}`)

### Output Formats
- JSON receipts (structured evidence)
- Markdown summaries (PR comments)
- SARIF output (GitHub Code Scanning integration)
- JUnit XML (CI integration)
- CSV/TSV export
- Sensor report envelope (sensor.report.v1)

### Rule System
- Inline suppression comments (`# diffguard:disable=rule.id`)
- Rule tagging/grouping for selective enable/disable
- Multi-line pattern matching
- Negative patterns (flag if pattern NOT present)
- Context requirements
- Semantic severity escalation
- Rule dependencies

### Language Support
- Rust, Python, JavaScript/TypeScript, Go, Java, C#, C/C++
- Shell/Bash, PHP, Swift, Scala, SQL, XML/HTML, YAML/TOML/JSON
- Language override flag (`--language=rust`)

### Built-in Rules
- Security-focused rules pack (hardcoded IPs, suspicious URLs, secret patterns)
- Credential detection
- Language-specific rules (no_unwrap, no_breakpoint, no_sout, etc.)

### Integration
- LSP server for editor integration
- VS Code extension
- pre-commit hook integration
- GitHub Actions reusable workflow
- GitLab CI template
- Azure DevOps pipeline template

### Analytics
- Trend history and analytics across runs
- False positive tracking
- Rule hit statistics

## Install

```bash
cargo install diffguard
```

## Quick start

```bash
# Check diff against main
diffguard check --base origin/main

# Generate config
diffguard init --preset conveyor
```

## License

MIT OR Apache-2.0
