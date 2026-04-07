# Changelog & Docs Update — work-fe471ba3

## Summary
Updated user-facing documentation for the new `diffguard doctor` subcommand.

## Changes Made

### CHANGELOG.md
- Added entry under `[Unreleased]` → `### Added` section documenting the `diffguard doctor` subcommand, covering:
  - Git availability and version check
  - Git work tree validation
  - Configuration file presence and validity check
  - `--config` flag support

### README.md
- Added a new "Commands" table between the presets line and the "Exit codes" section, documenting all CLI subcommands:
  - `doctor` — Check environment prerequisites
  - `check` — Run diff-scoped lint checks
  - `rules` — List available rules
  - `init` — Initialize config file
  - `validate` — Validate configuration
  - `explain` — Rule explanations with fuzzy matching

### ROADMAP.md
- No ROADMAP.md found in repository — no action needed.
