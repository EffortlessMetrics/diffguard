# Snapshot Test Report: work-9e77f361

**Gate:** PROVEN
**Agent:** snapshot-agent
**Date:** 2026-04-07

## Snapshots Created (19 total)

Benchmark fixture output snapshots:
- snapshot_generate_input_lines_5.snap
- snapshot_generate_input_lines_empty.snap
- snapshot_generate_lines_density_0_rust.snap
- snapshot_generate_lines_density_100_python.snap
- snapshot_generate_lines_density_50_rust.snap
- snapshot_generate_mixed_unified_diff_10_lines.snap
- snapshot_generate_receipt_empty.snap
- snapshot_generate_receipt_multiple_findings.snap
- snapshot_generate_receipt_single_finding.snap
- snapshot_generate_unified_diff_10_lines.snap
- snapshot_generate_unified_diff_single_line.snap
- snapshot_generate_mixed_unified_diff_empty.snap
- snapshot_generate_unified_diff_empty.snap

Rendering output snapshots:
- snapshot_parse_unified_diff_small.snap
- render_markdown_empty.snap
- render_markdown_with_finding.snap
- render_sarif_empty.snap
- render_sarif_with_finding.snap

## Result
All 19 snapshot tests PASS. These establish golden baselines for all major fixture generators and rendering functions.
