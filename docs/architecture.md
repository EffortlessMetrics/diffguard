# diffguard Architecture

This document describes the crate structure and architectural decisions in diffguard.

## Clean Architecture

diffguard follows clean architecture principles with dependency inversion:

```
                              I/O Boundary
    +-----------------------------------------------------------------+
    |                        diffguard (CLI)                          |
    |  - Argument parsing (clap)                                      |
    |  - Config file loading                                          |
    |  - Git subprocess invocation                                    |
    |  - File system output                                           |
    |  - Environment variable access                                  |
    +-----------------------------------------------------------------+
                                    |
                                    | depends on
                                    v
    +-----------------------------------------------------------------+
    |                      diffguard-core                             |
    |  - Use-case orchestration (run_check, run_sensor)              |
    |  - Verdict computation                                          |
    |  - Markdown/annotation rendering                                |
    +-----------------------------------------------------------------+
                    |                               |
                    | depends on                    | depends on
                    v                               v
    +-----------------------------+   +-----------------------------+
    |     diffguard-domain        |   |      diffguard-diff         |
    |  - Rule compilation         |   |  - Unified diff parsing     |
    |  - Line evaluation          |   |  - Hunk header parsing      |
    |  - Comment/string masking   |   |  - Special case detection   |
    |  - Language detection       |   |    (binary, submodule, etc) |
    +-----------------------------+   +-----------------------------+
                    |                               |
                    +---------------+---------------+
                                    |
                                    | depends on
                                    v
    +-----------------------------------------------------------------+
    |                      diffguard-types                            |
    |  - Pure DTOs (data transfer objects)                           |
    |  - Serde serialization/deserialization                         |
    |  - JSON schema generation (schemars)                            |
    |  - Built-in rule definitions                                    |
    +-----------------------------------------------------------------+
```

## Dependency Direction

Dependencies flow **downward only**:

- CLI depends on core, domain, diff, types
- Core depends on domain, diff, types
- Domain depends on types
- Diff depends on types
- Types depends on nothing (except serde/schemars)

This ensures:
- Core logic is testable without I/O
- Changes to CLI don't affect business logic
- Domain crates can be reused in other contexts

## Crate Descriptions

### `diffguard-types`

**Purpose:** Pure data structures with serialization.

**Key types:**
- `ConfigFile`, `Defaults`, `RuleConfig` - Configuration model
- `CheckReceipt`, `Finding`, `Verdict` - Output model
- `Severity`, `Scope`, `FailOn` - Enums
- `CHECK_SCHEMA_V1` - Schema version constant

**Dependencies:** Only `serde`, `schemars`

**I/O:** None (this crate is I/O-free)

### `diffguard-diff`

**Purpose:** Parse unified diff format into structured data.

**Key functions:**
- `parse_unified_diff(text, scope) -> (Vec<DiffLine>, DiffStats)`

**Key types:**
- `DiffLine` - Path, line number, content, change kind
- `ChangeKind` - Added vs Changed

**Detection functions:**
- `is_binary_file()`, `is_submodule()`, `is_deleted_file()`
- `is_mode_change_only()`, `parse_rename_from()`, `parse_rename_to()`

**Dependencies:** `diffguard-types`, `anyhow`, `thiserror`

**I/O:** None (operates on string input)

### `diffguard-domain`

**Purpose:** Business logic for rule evaluation.

**Modules:**

1. **rules.rs** - Rule compilation
   - `compile_rules(configs) -> Vec<CompiledRule>`
   - `detect_language(path) -> Option<&str>`
   - Path glob compilation with `globset`
   - Pattern compilation with `regex`

2. **preprocess.rs** - Comment/string masking
   - `Preprocessor` - Stateful, language-aware
   - `Language` enum with syntax variants
   - `PreprocessOptions` - What to mask

3. **evaluate.rs** - Line evaluation
   - `evaluate_lines(lines, rules, max) -> Evaluation`
   - First-match semantics for patterns
   - Per-line preprocessing with language detection

**Dependencies:** `diffguard-types`, `regex`, `globset`, `anyhow`, `thiserror`

**I/O:** None (operates on in-memory data)

### `diffguard-core`

**Purpose:** Core engine and application-level orchestration.

**Modules:**

1. **check.rs** - Main use-case
   - `run_check(plan, config, diff_text) -> CheckRun`
   - Coordinates parsing, evaluation, verdict
   - Computes exit codes

2. **sensor_api.rs** - R2 Library Contract
   - `run_sensor(settings, substrate) -> SensorReport`
   - Entry point for Cockpit/BusyBox integration

3. **sensor.rs** - Sensor report rendering
   - `render_sensor_report(receipt, context) -> SensorReport`
   - Produces `sensor.report.v1` envelope

4. **render.rs** - Output formatting
   - `render_markdown_for_receipt(receipt) -> String`
   - GitHub annotation formatting

5. **sarif.rs** - SARIF output
   - `render_sarif_for_receipt(receipt) -> SarifReport`

6. **junit.rs** - JUnit XML output
   - `render_junit_for_receipt(receipt) -> String`

7. **csv.rs** - CSV/TSV output
   - `render_csv_for_receipt(receipt) -> String`
   - `render_tsv_for_receipt(receipt) -> String`

8. **fingerprint.rs** - Finding fingerprints
   - `compute_fingerprint(finding) -> String` (SHA-256, 64 hex chars)
   - Stable identifier for deduplication and tracking

**Key types:**
- `CheckPlan` - Input parameters for a check run
- `CheckRun` - Output including receipt, markdown, annotations, exit code
- `Settings` - Consolidated input for `run_sensor()`
- `Substrate` - Optional shared substrate trait from Cockpit runtime
- `SensorReportContext` - Timing, capabilities, artifacts for sensor envelope

**Dependencies:** All domain crates, `globset` for path filtering, `sha2`/`hex` for fingerprinting

**I/O:** None (returns data for CLI to write)

### `diffguard` (CLI)

**Purpose:** Command-line interface and I/O operations.

**Responsibilities:**
- Parse CLI arguments with `clap`
- Load and merge configuration files (with include resolution and env expansion)
- Invoke `git diff` subprocess
- Write output files (JSON, Markdown, SARIF, JUnit, CSV/TSV)
- Print GitHub annotations to stdout
- Set exit code
- Structured logging via `tracing` (`--verbose`, `--debug`)

**Key modules:**
- `main.rs` - CLI definition, command handlers
- `config_loader.rs` - Config loading with include resolution and circular detection
- `env_expand.rs` - Environment variable expansion (`${VAR}`, `${VAR:-default}`)
- `presets.rs` - Starter configuration generators

**Key functions:**
- `cmd_check(args)` - Main check workflow
- `cmd_rules(args)` - Print effective rules
- `load_config_with_includes(path, expand_fn)` - Config loading with include merge
- `expand_env_vars(text)` - Environment variable expansion
- `git_diff(base, head, context)` - Git subprocess

**Dependencies:** All crates, `clap`, `anyhow`, `toml`, `serde_json`, `tracing`, `chrono`

**I/O:** Yes (this is the I/O boundary)

### `diffguard-testkit`

**Purpose:** Shared test utilities across crates.

**Usage:** `#[cfg(test)]` and integration tests only

### `xtask`

**Purpose:** Repository automation tasks.

**Commands:**
- `cargo run -p xtask -- ci` - Full CI suite
- `cargo run -p xtask -- schema` - Generate JSON schemas
- `cargo run -p xtask -- conform` - Run conformance tests (schema validation for all output formats)

## Ports and Adapters Pattern

The architecture implements ports and adapters (hexagonal architecture):

### Ports (Interfaces)

**Inbound ports** (how the world talks to us):
- CLI arguments (implemented by `clap`)
- Configuration file (implemented by TOML parsing)

**Outbound ports** (how we talk to the world):
- Git diff acquisition (implemented by subprocess)
- File output (implemented by `std::fs`)
- Console output (implemented by `println!`)

### Adapters (Implementations)

All adapters live in the `diffguard` CLI crate:

```rust
// Git adapter
fn git_diff(base: &str, head: &str, context: u32) -> Result<String>

// File adapter
fn write_json(path: &Path, value: &impl Serialize) -> Result<()>
fn write_text(path: &Path, text: &str) -> Result<()>

// Config adapter
fn load_config(path: Option<PathBuf>, no_defaults: bool) -> Result<ConfigFile>
```

## Schema-First Approach

Output schemas are defined in Rust types with automatic JSON Schema generation:

```rust
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CheckReceipt {
    pub schema: String,
    pub tool: ToolMeta,
    pub diff: DiffMeta,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}
```

Benefits:
- Types and schemas are always in sync
- Schema validation is automatic via serde
- JSON Schema can be exported for external tooling

Schema generation:
```bash
cargo run -p xtask -- schema
```

## Testing Strategy

Each crate has appropriate test coverage:

| Crate | Unit Tests | Integration | Snapshot | Property | Fuzz |
|-------|------------|-------------|----------|----------|------|
| types | Yes | - | - | Yes | - |
| diff | Yes | - | Yes | Yes | Yes |
| domain | Yes | - | - | Yes | Yes |
| core | Yes | Yes | Yes | Yes | - |
| CLI | Yes | Yes (BDD) | - | - | - |

**Test locations:**
- Unit tests: `#[cfg(test)]` modules in source files
- Integration tests: `tests/` directories per crate
- Snapshot tests: Using `insta` crate
- Property tests: Using `proptest` crate
- Fuzz tests: `fuzz/fuzz_targets/` directory

## Invariants

These architectural invariants MUST be maintained:

1. **Domain crates are I/O-free**
   - `diffguard-types`, `diffguard-diff`, `diffguard-domain` MUST NOT use:
     - `std::fs` (file system)
     - `std::process` (subprocesses)
     - `std::env` (environment variables)
     - Network operations

2. **Dependency direction is strict**
   - No cycles in the dependency graph
   - Lower crates never depend on higher crates

3. **Exit codes are stable API**
   - Exit codes are documented and tested
   - Changes to exit code semantics are breaking changes

4. **Schema versioning**
   - Receipt schema version MUST be updated for breaking changes
   - Old schema versions SHOULD remain parseable when possible
