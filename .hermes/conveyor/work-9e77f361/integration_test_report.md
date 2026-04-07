# Integration Test Report: work-9e77f361

**Gate:** PROVEN  
**Agent:** integration-test-agent  
**Date:** 2026-04-07

## Integration Test Coverage

The benchmark infrastructure integrates with the following workspace crates:
- `diffguard-diff`: unified diff parsing (covered by 4 fuzz targets + snapshots)
- `diffguard-domain`: evaluation and preprocessing (covered by 2 fuzz targets + property tests)
- `diffguard-types`: type definitions and receipt structures (covered by snapshot tests)
- `diffguard-core`: rendering to markdown/SARIF (covered by 19 snapshot tests)

## Pipeline Integration Flows

### Diff → Evaluate → Receipt Flow
```
generate_unified_diff → parse_unified_diff → evaluate_lines → generate_receipt_with_findings
```
Covered by: `test_full_pipeline_generate_diff_parse_convert_evaluate` (unit test)

### Parse → Convert → Preprocess Flow
```
parse_unified_diff → DiffLine → InputLine → Preprocessor::sanitize_line
```
Covered by: property tests (DiffLine→InputLine preserves path, line, content)

### Generate → Render Flow
```
generate_receipt_with_findings → render_markdown/receipt → render_sarif/receipt
```
Covered by: 4 snapshot tests (markdown and SARIF empty/single-finding)

## Existing Integration Tests
- `diffguard-domain/tests/properties.rs`: property-based integration tests
- `diffguard-core/src/sarif.rs`: SARIF rendering snapshots  
- `diffguard-bench/tests/fixtures.rs`: 38 unit tests verifying fixture behavior
- `diffguard-bench/tests/property_tests.rs`: 25 property tests

## Result
All integration flows are tested. The benchmark crate correctly exercises the full evaluation pipeline from diff generation through receipt rendering.

