#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# fetch-appid-feeds.sh — download the free, vendor-published IP-range feeds the
# Application Identification resolver (#81 P1) loads. Deliberately OUT-OF-BAND and
# opt-in so the build stays offline: run this on a host with internet, point
# APPID_FEEDS_DIR at the output dir, and restart the API (it loads the snapshot at
# startup). Re-run on a cron (feeds change ~daily) to refresh.
#
# Usage:
#   scripts/fetch-appid-feeds.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to ./data/appid-feeds
#
# The resolver reads these exact filenames; a missing file is simply skipped.
#   aws.json    — https://ip-ranges.amazonaws.com/ip-ranges.json
#   gcp.json    — https://www.gstatic.com/ipranges/cloud.json
#   m365.json   — Microsoft 365 endpoints API (Worldwide instance)
#   azure.json  — Azure Service Tags (NOTE: download manually, see below)

set -euo pipefail

OUT="${1:-./data/appid-feeds}"
mkdir -p "$OUT"

fetch() {
  local name="$1" url="$2"
  printf 'fetching %-10s <- %s\n' "$name" "$url"
  if curl -fsSL --retry 3 --max-time 60 "$url" -o "$OUT/$name.tmp"; then
    mv "$OUT/$name.tmp" "$OUT/$name"
  else
    echo "  WARN: failed to fetch $name (leaving any existing snapshot in place)" >&2
    rm -f "$OUT/$name.tmp"
  fi
}

fetch aws.json  "https://ip-ranges.amazonaws.com/ip-ranges.json"
fetch gcp.json  "https://www.gstatic.com/ipranges/cloud.json"

# Microsoft 365 endpoints API needs a stable client GUID (any UUID works).
M365_GUID="${M365_CLIENT_GUID:-b10c5ed1-bad1-445f-b386-b919946339a7}"
fetch m365.json "https://endpoints.office.com/endpoints/worldwide?clientrequestid=${M365_GUID}"

# Azure Service Tags are published behind a dated download page, not a stable URL.
# Grab the latest "ServiceTags_Public_*.json" from
#   https://www.microsoft.com/en-us/download/details.aspx?id=56519
# and save it as "$OUT/azure.json". (Left manual on purpose — no stable direct URL.)
if [ ! -f "$OUT/azure.json" ]; then
  echo "NOTE: azure.json not present — download Azure Service Tags manually and save as $OUT/azure.json" >&2
fi

echo "done. point APPID_FEEDS_DIR at: $(cd "$OUT" && pwd)"
