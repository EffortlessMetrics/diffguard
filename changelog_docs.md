# Changelog Docs Summary

## Work Item: work-e6ade558

**Description:** XML output: escape_xml doesn't handle control characters (0x00–0x1F)

**Gate:** INTEGRATED

**Status:** CHANGELOG entry already exists

## Summary

The CHANGELOG.md already contains a proper entry for this fix in the `[Unreleased]` → `### Fixed` section:

```
- **`escape_xml` control character handling** — XML output formats (JUnit, Checkstyle) now properly escape XML control characters (0x00–0x1F) as character references (e.g., `&#x0;`), except tab, LF, and CR which are allowed in XML content. This prevents malformed XML when findings contain control characters.
```

## Fix Details

- **Component:** `escape_xml` function in XML output utilities
- **Affected formats:** JUnit XML, Checkstyle XML
- **Problem:** Control characters (0x00–0x1F) were not being escaped, causing malformed XML output when findings contained such characters
- **Solution:** Control characters are now escaped as XML character references (e.g., `&#x0;`), with exception for tab (0x09), LF (0x0A), and CR (0x0D) which are valid in XML content

## Verification

- CHANGELOG.md updated: ✓
- Entry location: Line 12 of CHANGELOG.md (under `[Unreleased]` → `### Fixed`)
