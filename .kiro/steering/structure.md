# Project Structure

## Workspace Layout

```
diffguard/
├── crates/
│   ├── diffguard/          # CLI binary - clap wiring and I/O
│   ├── diffguard-app/      # Application layer - orchestration
│   ├── diffguard-diff/     # Unified diff parsing
│   ├── diffguard-domain/   # Core logic - rule evaluation, preprocessing
│   └── diffguard-types/    # DTOs - config and receipt types
├── xtask/                  # Repo automation (ci, schema generation)
├── fuzz/                   # Fuzz testing targets
├── schemas/                # Generated JSON schemas
└── Cargo.toml              # Workspace root
```

## Crate Responsibilities

### `diffguard-types`
Pure data types with serde + schemars. No logic, just DTOs for:
- `ConfigFile`, `RuleConfig`, `Defaults`
- `CheckReceipt`, `Finding`, `Verdict`
- Enums: `Severity`, `Scope`, `FailOn`, `VerdictStatus`

### `diffguard-diff`
Unified diff parsing. Extracts added/changed lines from `git diff` output.
- `parse_unified_diff()` → `Vec<DiffLine>`, `DiffStats`
- I/O-free, designed for fuzz testing

### `diffguard-domain`
Core business logic, I/O-free and highly testable:
- `rules.rs`: Compile `RuleConfig` → `CompiledRule` with regex/glob
- `evaluate.rs`: Match rules against input lines, produce findings
- `preprocess.rs`: Mask comments/strings for ignore options

### `diffguard-app`
Application orchestration layer:
- `check.rs`: `run_check()` - ties diff parsing + rule evaluation + verdict
- `render.rs`: Markdown summary generation

### `diffguard` (CLI)
Thin CLI wrapper:
- Clap argument parsing
- Config file loading and merging
- Git diff invocation
- File I/O for receipts and markdown

## Design Principles

1. **Layered architecture**: Types → Domain → App → CLI
2. **I/O at the edges**: Domain and diff crates are pure logic
3. **Testability**: Core logic is unit-testable without mocks
4. **Stable outputs**: JSON receipts have versioned schemas
