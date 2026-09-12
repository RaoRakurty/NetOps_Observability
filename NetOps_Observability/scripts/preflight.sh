#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# preflight.sh — run ALL fresh-install / deploy guardrails before shipping.
#
# The umbrella for the "I am ok with bugs but not THESE bugs" gate: the class where
# a change ships fine on the running dev stack but a restart or a clean install on a
# new server silently breaks. Two layers:
#
#   1. preflight-install.py  — STATIC: does a clean `install.py` provision every env
#      var, config file, and data dir the compose stack requires? (compose ↔ install.py)
#   2. preflight-configs.sh  — RUNTIME: does every committed service config survive a
#      FRESH LOAD with its real binary? (catches the vector-E651 class)
#
# Run before committing config/compose/install changes, or wire as a git hook:
#   ln -sf ../../NetOps_Observability/scripts/preflight.sh .git/hooks/pre-push
# Also run in CI (.github/workflows/fresh-install-integrity.yml) and by install.py.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0

echo "########## 1/2  fresh-install integrity (static) ##########"
python3 "$HERE/preflight-install.py" || rc=1

echo ""
echo "########## 2/2  config fresh-load (real runtime) ##########"
if command -v docker >/dev/null 2>&1; then
  bash "$HERE/preflight-configs.sh" || rc=1
else
  echo "  — docker not available; skipping the runtime config-load checks" >&2
fi

echo ""
if [ "$rc" -ne 0 ]; then
  echo "preflight: FAILED — do not ship; a fresh install/restart would break (see ✗ above)." >&2
  exit 1
fi
echo "preflight: PASS — a clean install provisions everything and every config boots."
