#!/usr/bin/env bash
# sync-docs-corpus.sh — mirror the docs-portal markdown into the backend's
# embedded AI corpus (src/backend/ai/docs_corpus). go:embed can only reach files
# inside the package tree, so the corpus is a checked-in mirror; this script is
# the ONLY way it should be updated. A drift test (ai/docs_corpus_drift_test.go)
# fails CI whenever the mirror and docs-portal/docs disagree, so a docs edit
# can't silently leave the assistant answering from stale pages.
#
# Usage: scripts/sync-docs-corpus.sh   (from the NetOps_Observability root)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/docs-portal/docs"
DST="$ROOT/src/backend/ai/docs_corpus"

[ -d "$SRC" ] || { echo "docs-portal/docs not found at $SRC" >&2; exit 1; }
mkdir -p "$DST"

# Markdown only — images/assets stay in the portal; the AI index is text.
rsync -a --delete \
  --include='*/' --include='*.md' --exclude='*' \
  "$SRC/" "$DST/"

echo "synced $(find "$DST" -name '*.md' | wc -l) markdown pages → src/backend/ai/docs_corpus"
