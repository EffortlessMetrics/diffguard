# ADR: Inline Named Format Arguments in `bail!` Macro Calls

## Status
**Accepted**

## Context

The `xtask/src/conform_real.rs` file contains 5 `bail!` macro invocations that use old-style positional format arguments (`{}` with a trailing separate argument) instead of Rust 2021+ inline named format syntax.

The affected calls are:

| Line | Current Pattern | Issue |
|------|----------------|-------|
| 368-371 | `bail!("...{}", String::from_utf8_lossy(&output.stderr))` | Positional `{}` |
| 620-623 | `bail!("sensor report failed schema validation:\n{}", error_messages.join("\n"))` | Positional `{}` |
| 769-772 | `bail!("cockpit mode did not exit 0: {}", String::from_utf8_lossy(&output.stderr))` | Positional `{}` |
| 1105-1108 | `bail!("cockpit mode did not exit 0: {}", String::from_utf8_lossy(&output.stderr))` | Positional `{}` |
| 1167 | `bail!("expected 7 artifacts, got {}: {:?}", artifacts.len(), paths)` | Positional `{}` and `{:?}` |

The project uses Rust 2024 edition (MSRV Rust 1.92), which fully supports inline named format arguments. The `anyhow::bail!` macro supports named inline format arguments via `bail!("message {var}", var = expr)` syntax, which forwards directly to `format_args!()`.

## Decision

Convert all 5 `bail!` calls to use inline named format arguments:

```rust
// Before
bail!("cockpit mode did not exit 0: {}", String::from_utf8_lossy(&output.stderr));

// After
bail!("cockpit mode did not exit 0: {stderr}", stderr = String::from_utf8_lossy(&output.stderr));
```

For the single call with two placeholders (line 1167):
```rust
// Before
bail!("expected 7 artifacts, got {}: {:?}", artifacts.len(), paths);

// After
bail!("expected 7 artifacts, got {n}: {paths:?}", n = artifacts.len(), paths = paths);
```

## Consequences

### Benefits
1. **Improved readability**: Named placeholders make it immediately clear which variable maps to which placeholder without counting positional arguments
2. **Resolves style-check CI failures**: If the project has a lint enforcing inline format arguments, this resolves those failures
3. **Modern Rust idiom**: Consistent with Rust 2021+ conventions and the project's stated trajectory toward clean, modern code

### Tradeoffs
1. **Minor reformatting**: Four of the five calls are multi-line. Converting to named-argument syntax will change line breaks; `cargo fmt` will handle this automatically
2. **No semantic change**: The transformation is purely syntactic — expression evaluation order and borrowing semantics are unchanged

## Alternatives Considered

### 1. No change (leave positional format args)
Rejected because:
- The issue title implies a style lint flags these calls
- Modern Rust idiom strongly favors named inline format arguments
- The codebase uses Rust 2024 edition, making positional args an anomaly

### 2. Fix entire codebase in a single PR
Rejected because:
- Issue scope is explicitly limited to `xtask/conform_real.rs`
- A follow-up issue/PR should address other files
- Keeping scope narrow reduces review burden and blast radius

## Scope Boundaries

**In scope:**
- `xtask/src/conform_real.rs` — the 5 `bail!` calls listed above

**Out of scope:**
- `format!()` calls inside `.context()` invocations (e.g., `.context(format!("get findings[{i}].severity"))?;`) — these are a separate code smell and should be addressed in a follow-up issue
- Any other files in the codebase
- Any `bail!` calls that already use inline format syntax

## Verification

After the fix:
```bash
cargo check -p xtask && cargo fmt -- --check
```

Both commands must pass for the PR to be mergeable.