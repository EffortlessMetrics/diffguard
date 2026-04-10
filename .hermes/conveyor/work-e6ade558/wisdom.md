# Wisdom — work-e6ade558

## What Went Well

1. **Clean module extraction**: Extracted `escape_xml` to a shared `xml_utils.rs` module rather than keeping duplicate implementations in `junit.rs` and `checkstyle.rs`. This improved code reuse and maintainability.

2. **Proper XML spec compliance**: The fix correctly handles illegal XML control characters (0x00–0x1F except tab/LF/CR) by encoding them as `&#xNN;` hex character references, complying with XML 1.0 specification.

3. **Preserved legal control characters**: Tab (0x09), LF (0x0A), and CR (0x0D) are correctly preserved as-is since they are allowed in XML character content.

4. **Comprehensive tests**: Added property-based tests (proptest) alongside unit tests for thorough coverage of control character edge cases.

5. **ADR documentation**: Created ADR explaining the architectural decision to extract the function and the XML spec rationale.

6. **Documentation clarity**: Added doc comments explaining the encoding approach for future maintainers.

7. **Clippy hygiene**: Fixed clippy warnings (`useless-format`, `needless-borrow`) in tests before INTEGRATED gate.

## What Was Hard

1. **No friction log for this work item**: The friction log directory `friction-logs/work-e6ade558` does not exist. This makes it difficult to track pipeline friction for this specific work item.

2. **Branching confusion**: The work appears to span multiple work IDs (work-e6ade558 and work-93f8df2f), making artifact tracing confusing.

3. **Mutation testing artifacts committed**: The commit included `mutants.out.old/` directory with thousands of files. This should be in `.gitignore`.

## What to Do Differently

1. **Ensure friction logging**: Agents should call `gates.py friction <work-id>` during the run so friction patterns can be analyzed at wisdom time.

2. **Add mutation testing dirs to `.gitignore`**: Files like `mutants.out.old/` and `mutants.out/` should be gitignored to prevent accidental commits of large artifact directories.

3. **Single work ID scope**: Try to keep a work item focused on a single issue/PR rather than spanning multiple work IDs.

4. **Gate artifact naming consistency**: Ensure artifact type names match what the gate checker expects (e.g., `security_review` vs `security-review`, etc.).

## Agent Performance

- **code-builder**: Produced the module extraction cleanly with proper tests
- **green-test-builder**: Added comprehensive proptest coverage for control characters
- **red-test-builder**: Provided adversarial cases that caught edge cases
- **plan-reviewer**: Identified the clippy issues that needed fixing
- **test-reviewer**: Verified test coverage was sufficient before INTEGRATED gate

## Key Learnings

- XML control character handling (0x00–0x1F except tab/LF/CR) is a real compliance issue that can break XML parsers
- Extracting shared utilities into dedicated modules prevents code duplication
- Proptest-based property testing is valuable for character encoding functions with many edge cases
- Clippy warnings should be resolved before attempting HARDENED/INTEGRATED gates
- Large artifact directories (mutation testing output) must be gitignored to prevent accidental commits

## Recommendations for Next Run

1. Add `mutants.out*/` to `.gitignore` in workspace templates
2. Ensure agents log friction with `gates.py friction <work-id>` throughout the run
3. Keep work item scope focused on a single PR/issue when possible
4. Run clippy as part of the HARDENED gate pre-checks to catch lints before submission
