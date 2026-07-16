#!/usr/bin/env python3
"""refresh_provider_ranges — refresh the bundled cloud-provider CIDR snapshot.

The segment classifier (path-causality RCA P0, src/correlation/segment_classifier.py +
src/backend/segment_classifier.go) classifies a hop into cloud/lan/wan/... by longest-prefix
match over a BUNDLED snapshot of the providers' published IP-range feeds. The classifier NEVER
fetches at runtime — it reads the local snapshot. This job refreshes that snapshot out-of-band
(run weekly on a cron; the feeds change several times a week).

It writes TWO byte-identical copies from ONE fetch so Python and the Go embed never drift:
  * src/correlation/segmentdata/provider_ip_ranges.json (Python reads this)
  * src/backend/segmentdata/provider_ip_ranges.json (go:embed reads this)

Offline-safe: if a provider feed can't be fetched (no network, TLS interception, feed down),
that provider is SKIPPED and its prefixes are preserved from the existing snapshot — the job
never destroys the bundled offline baseline. Stdlib-only (urllib), matching the repo's posture.

Cron (weekly, Monday 04:17):
    17 4 * * 1  cd /opt/netops/NetOps_Observability && python3 scripts/refresh_provider_ranges.py >> /var/log/netops/provider-ranges-refresh.log 2>&1

Usage:
    python3 scripts/refresh_provider_ranges.py            # fetch live + rewrite both snapshots
    python3 scripts/refresh_provider_ranges.py --dry-run  # fetch + report counts, write nothing
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)  # .../NetOps_Observability
PY_SNAPSHOT = os.path.join(_ROOT, "src", "correlation", "segmentdata", "provider_ip_ranges.json")
GO_SNAPSHOT = os.path.join(_ROOT, "src", "backend", "segmentdata", "provider_ip_ranges.json")

AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
# Azure Service Tags have no stable auto-serving URL (the 56519 download rotates a dated
# filename). Set AZURE_SERVICE_TAGS_URL to the current JSON to include Azure; otherwise the
# existing Azure prefixes from the bundled snapshot are preserved.
AZURE_URL = os.environ.get("AZURE_SERVICE_TAGS_URL", "")

TIMEOUT_S = 30


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "netops-provider-ranges-refresh"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310 (fixed https feeds)
        return json.load(resp)


def _valid_prefix(p: str) -> bool:
    try:
        ipaddress.ip_network(p, strict=False)
        return True
    except ValueError:
        return False


def _from_aws(doc: dict) -> list[dict]:
    out: list[dict] = []
    for key, fam in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for e in doc.get(key, []):
            pfx = str(e.get(fam, "")).strip()
            if _valid_prefix(pfx):
                out.append({"prefix": pfx, "provider": "aws",
                            "region": str(e.get("region", "")), "service": str(e.get("service", ""))})
    return out


def _from_gcp(doc: dict) -> list[dict]:
    out: list[dict] = []
    for e in doc.get("prefixes", []):
        pfx = str(e.get("ipv4Prefix") or e.get("ipv6Prefix") or "").strip()
        if _valid_prefix(pfx):
            out.append({"prefix": pfx, "provider": "gcp",
                        "region": str(e.get("scope", "")), "service": str(e.get("service", "Google Cloud"))})
    return out


def _from_azure(doc: dict) -> list[dict]:
    out: list[dict] = []
    for tag in doc.get("values", []):
        props = tag.get("properties", {}) or {}
        region = str(props.get("region", ""))
        service = str(props.get("systemService", "") or tag.get("name", ""))
        for pfx in props.get("addressPrefixes", []) or []:
            pfx = str(pfx).strip()
            if _valid_prefix(pfx):
                out.append({"prefix": pfx, "provider": "azure", "region": region, "service": service})
    return out


def _existing(provider: str, snap: dict) -> list[dict]:
    return [p for p in snap.get("prefixes", []) if p.get("provider") == provider]


def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh the bundled cloud-provider CIDR snapshot.")
    ap.add_argument("--dry-run", action="store_true", help="fetch + report, write nothing")
    args = ap.parse_args()

    try:
        with open(PY_SNAPSHOT, "r", encoding="utf-8") as fh:
            base = json.load(fh)
    except (OSError, ValueError):
        base = {"prefixes": []}

    feeds = [("aws", AWS_URL, _from_aws), ("gcp", GCP_URL, _from_gcp)]
    if AZURE_URL:
        feeds.append(("azure", AZURE_URL, _from_azure))

    merged: list[dict] = []
    kept_offline: list[str] = []
    for provider, url, parse in feeds:
        try:
            doc = _fetch_json(url)
            got = parse(doc)
            if got:
                merged += got
                print(f"[{provider}] fetched {len(got)} prefixes from {url}")
            else:
                merged += _existing(provider, base)
                kept_offline.append(provider)
                print(f"[{provider}] feed parsed to 0 prefixes — kept {len(_existing(provider, base))} bundled")
        except Exception as exc:  # noqa: BLE001 (any fetch/parse failure → preserve offline)
            merged += _existing(provider, base)
            kept_offline.append(provider)
            print(f"[{provider}] fetch failed ({exc}) — kept {len(_existing(provider, base))} bundled prefixes")

    # Providers never listed in `feeds` (e.g. Azure with no URL set) keep their bundled rows.
    covered = {p for p, _, _ in feeds}
    for p in ("aws", "azure", "gcp"):
        if p not in covered:
            merged += _existing(p, base)
            kept_offline.append(p)

    snapshot = {
        "schema_version": 1,
        "synced_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_note": base.get("source_note", "Bundled offline snapshot; refresh with scripts/refresh_provider_ranges.py."),
        "sources": {"aws": AWS_URL, "azure": AZURE_URL or "(set AZURE_SERVICE_TAGS_URL)", "gcp": GCP_URL},
        "prefixes": merged,
    }

    print(f"total {len(merged)} prefixes; offline-preserved providers: {sorted(set(kept_offline)) or 'none'}")
    if args.dry_run:
        print("--dry-run: no files written")
        return 0

    payload = json.dumps(snapshot, indent=2) + "\n"
    for path in (PY_SNAPSHOT, GO_SNAPSHOT):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
