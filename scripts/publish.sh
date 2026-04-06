#!/usr/bin/env bash
set -euo pipefail

# Publish diffguard v0.2.0 to crates.io
# Run from repo root. Requires: cargo login (already authenticated)

VERSION="0.2.0"
ORDER=(
  diffguard-types
  diffguard-diff
  diffguard-domain
  diffguard-core
  diffguard-analytics
  diffguard
  diffguard-lsp
)

echo "=== Publishing diffguard $VERSION to crates.io ==="
echo ""

for crate in "${ORDER[@]}"; do
  echo "--- Publishing $crate ---"
  cargo publish -p "$crate"
  # Wait for crates.io to index (needed for dependency resolution)
  echo "  Waiting 30s for crates.io indexing..."
  sleep 30
done

echo ""
echo "=== All crates published ==="
echo "Published: ${ORDER[*]}"
