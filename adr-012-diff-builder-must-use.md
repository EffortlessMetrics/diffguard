# ADR-012: Add #[must_use] to Self-returning builder methods in diff_builder.rs

## Status
Accepted

## Context
GitHub issue #512 reports that builder methods in `crates/diffguard-testkit/src/diff_builder.rs` that return `Self` lack `#[must_use]`. When callers invoke these methods without chaining (e.g., `file_builder.new_file()` instead of `file_builder = file_builder.new_file()`), the returned builder is silently dropped and the state change is lost.

The structs `FileBuilderInProgress` and `HunkBuilderInProgress` already carry `#[must_use]` at the struct level (lines 90 and 150), but this attribute on the struct type only applies to the constructor-like entry points — it does NOT propagate to Self-returning method calls. Each method that returns `Self` and whose result should not be silently dropped needs its own `#[must_use]` annotation.

## Decision
Add `#[must_use]` to the 8 Self-returning builder methods on `FileBuilderInProgress` and `HunkBuilderInProgress`:

**FileBuilderInProgress** (impl block at line 97):
- `binary(self) -> Self` (line ~113)
- `deleted(self) -> Self` (line ~119)
- `new_file(self) -> Self` (line ~125)
- `mode_change(self, ...) -> Self` (line ~131)
- `rename_from(self, ...) -> Self` (line ~137)

**HunkBuilderInProgress** (impl block at line 157):
- `context(self, ...) -> Self` (line ~159)
- `add_line(self, ...) -> Self` (line ~165)
- `remove(self, ...) -> Self` (line ~171)

## Consequences

### Benefits
- Calling any of these 8 methods without using the returned value produces a compiler warning, preventing silent state-loss bugs at zero runtime cost.
- Aligns with the Rust standard library convention (e.g., `BufWriter::flush`, `HashSet::insert` carry per-method `#[must_use]`).
- Consistent with the struct-level `#[must_use]` already present on `FileBuilderInProgress` and `HunkBuilderInProgress`.

### Tradeoffs / Risks
- The `#[must_use]` attribute produces a warning (not an error) when the return value is unused, so misapplying it cannot break builds — it only creates a warning.
- Scope is tightly limited to the 8 methods listed. Other types (`FileBuilder`, `HunkBuilder`) and extension trait methods have the same pattern but are explicitly out of scope.
- Adding `#[must_use]` to methods that callers sometimes intentionally ignore (using `_ = builder.method()`) would introduce new warnings, but this is a desirable signal — callers should be explicit about intentional drops.

## Alternatives Considered

### 1. Struct-level `#[must_use = "..."]` instead of per-method attributes
The structs already carry `#[must_use]`. Replacing the struct-level attribute with `#[must_use = "builder methods should be chained"]` was considered but rejected because struct-level `#[must_use]` applies only to the constructor/entry-point, not to all Self-returning method calls. This is a fundamental Rust semantics limitation, not a formatter issue.

### 2. Do nothing (leave as-is)
Accepting the silent-drop behavior was rejected because it allows real bugs in test code where state-loss is invisible and hard to debug. The `#[must_use]` attribute is the idiomatic Rust solution for this class of problem.

### 3. Extend fix to FileBuilder and HunkBuilder types
The same `#[must_use]` gap exists on `FileBuilder` and `HunkBuilder` Self-returning methods. These were explicitly excluded from scope to keep the change minimal and focused. A follow-up issue should address them separately.
