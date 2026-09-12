#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# bundle-staleness.sh — FAIL VISIBLY when the customer bundle lags the code (#97).
#
# The offline customer bundle (scripts/make-installer.sh -> dist/correlix-*/) is
# built on this dev host and shipped manually; nothing used to tell anyone it
# had drifted behind HEAD (it once drifted 300 commits / 13 days unnoticed).
# This check closes that gap: it reads the newest bundle's MANIFEST git_sha and
# counts the SHIPPABLE commits (src/ deployment/ scripts/ telemetry-catalog/)
# HEAD has that the bundle does not. Docs-only drift does not stale a bundle.
#
# Usage:
#   scripts/bundle-staleness.sh                 report; exit 1 if stale
#   scripts/bundle-staleness.sh --quiet         print nothing when fresh (hook mode)
#   scripts/bundle-staleness.sh --max-commits N tolerate up to N shippable commits
#
# Exit codes: 0 fresh · 1 stale (or unverifiable stamp) · 2 no bundle / bad args
#
# Wired into: scripts/git-hooks/pre-push (warn-only, every push) and
# `make bundle-status`. Rebuild with `bash scripts/make-installer.sh` (full) or
# `bash scripts/make-installer.sh --core` — the make targets wrap exactly those,
# and make is not installed on every build host.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUIET=0
MAX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet)       QUIET=1; shift ;;
    --max-commits) MAX="$2"; shift 2 ;;
    *) echo "bundle-staleness: unknown arg: $1" >&2; exit 2 ;;
  esac
done

newest="$(ls -1dt "$ROOT"/dist/correlix-*/MANIFEST 2>/dev/null | head -1 || true)"
if [ -z "$newest" ]; then
  echo "bundle-staleness: NO customer bundle found under $ROOT/dist — build one: bash scripts/make-installer.sh" >&2
  exit 2
fi
bundle_name="$(basename "$(dirname "$newest")")"
sha="$(sed -n 's/^git_sha:[[:space:]]*//p' "$newest" | head -1)"
built="$(sed -n 's/^built:[[:space:]]*//p' "$newest" | head -1)"
head_sha="$(git -C "$ROOT" rev-parse --short HEAD)"

if [ -z "$sha" ] || ! git -C "$ROOT" cat-file -e "${sha}^{commit}" 2>/dev/null; then
  echo "bundle-staleness: newest bundle $bundle_name has an unverifiable git_sha ('${sha:-<missing>}') — rebuild: bash scripts/make-installer.sh" >&2
  exit 1
fi

# Shippable drift only: commits under paths that end up in the bundle
# (source tree, compose/deploy configs, installer scripts, telemetry catalog).
behind="$(git -C "$ROOT" rev-list --count "$sha..HEAD" -- src deployment scripts telemetry-catalog)"
total="$(git -C "$ROOT" rev-list --count "$sha..HEAD")"

if [ "$behind" -le "$MAX" ]; then
  if [ "$QUIET" != 1 ]; then
    echo "bundle-staleness: OK — $bundle_name (git_sha $sha, built $built) is current with HEAD $head_sha ($behind shippable / $total total commit(s) since stamp)"
  fi
  exit 0
fi

{
  echo "bundle-staleness: STALE customer bundle"
  echo "  newest bundle : $bundle_name  (git_sha $sha, built $built)"
  echo "  HEAD          : $head_sha"
  echo "  drift         : $behind shippable commit(s) ($total total) are NOT in the customer package"
  echo "  rebuild       : bash scripts/make-installer.sh          # full (base + add-on packs)"
  echo "                  bash scripts/make-installer.sh --core   # smallest eval bundle"
} >&2
exit 1
