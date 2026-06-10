#!/usr/bin/env python3
"""Prepare the device-OS vulnerability feed for Vulnerability Management.

Converts NVD CVE data (and optionally the CISA KEV catalog) into the compact
CSV the API's /api/vulns matcher reads:

    vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary

Only network-OS applicability rows are kept: CPE part o/h (operating system /
hardware) from the vendors the platform identifies via SNMP (Cisco, Juniper,
Arista, Fortinet, Palo Alto, Nokia, Huawei, MikroTik, …) — so the full NVD
corpus boils down to a few MB the API holds in memory.

Accepted inputs (one or more, auto-detected .json / .json.gz):
  * NVD CVE feed files, schema 2.0 — download per year from
    https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<YEAR>.json.gz
    (NVD data is US-government work, free to use; we still don't bundle or
    auto-download it — the stack must build and run fully offline.)
  * --kev <file>: CISA Known Exploited Vulnerabilities catalog
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Flags matching rows kev=1 for prioritization.

Output (atomic temp+rename, so the mtime bump is the reload signal):
    data/vuln/advisories.csv   (operator-owned; mounted read-only into the
    API at /data/vuln — the service can read but never alter its own feed)

The API lazy-loads the feed and hot-reloads on mtime change — re-run this
script to pick up new advisories; the board updates on its next refresh, no
restarts. Stdlib only, like everything else in scripts/.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "data" / "vuln" / "advisories.csv"

# NVD CPE vendor → the platform's normalized vendor name (collectors/vendor.go).
VENDOR_MAP = {
    "cisco": "cisco",
    "juniper": "juniper",
    "arista": "arista",
    "fortinet": "fortinet",
    "paloaltonetworks": "paloalto",
    "nokia": "nokia",
    "huawei": "huawei",
    "mikrotik": "mikrotik",
    "extremenetworks": "extreme",
    "f5": "f5",
    "dell": "dell",
    "hp": "hp",
    "hpe": "hp",
    "checkpoint": "checkpoint",
    "linux": "linux",
}

CSV_HEADER = [
    "vendor", "product", "cve", "severity", "cvss",
    "ver_start_incl", "ver_start_excl", "ver_end_incl", "ver_end_excl",
    "ver_exact", "kev", "published", "summary",
]
MAX_SUMMARY = 280


def load_json(path: Path) -> dict:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def split_cpe23(criteria: str) -> list[str]:
    """Split a CPE 2.3 formatted string on unescaped colons."""
    fields, cur, esc = [], [], False
    for ch in criteria:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    return fields


def unescape(v: str) -> str:
    """Drop CPE escaping backslashes: 15.2\\(4\\)e10 → 15.2(4)e10."""
    out, esc = [], False
    for ch in v:
        if esc:
            out.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        else:
            out.append(ch)
    return "".join(out)


def severity_of(cve: dict) -> tuple[str, float]:
    """Best available CVSS: v4 → v3.1 → v3.0 → v2, Primary entries first."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in sorted(entries, key=lambda e: e.get("type") != "Primary"):
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or entry.get("baseSeverity") or ""
            if score is not None:
                return str(sev).lower(), float(score)
    return "", 0.0


def summary_of(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            s = " ".join((d.get("value") or "").split())
            return s[:MAX_SUMMARY]
    return ""


def rows_from_nvd(doc: dict, kev_ids: set[str]) -> Iterator[list[str]]:
    vulns = doc.get("vulnerabilities")
    if vulns is None:
        sys.exit("error: not an NVD 2.0 document (no 'vulnerabilities' key) — "
                 "use the nvdcve-2.0-<YEAR>.json.gz feeds")
    for item in vulns:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or ""
        if not cve_id.startswith("CVE-") or cve.get("vulnStatus") == "Rejected":
            continue
        sev, score = severity_of(cve)
        published = (cve.get("published") or "")[:10]
        summary = summary_of(cve)
        kev = "1" if cve_id in kev_ids else "0"
        for conf in cve.get("configurations") or []:
            for node in conf.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    if not m.get("vulnerable"):
                        continue
                    f = split_cpe23(m.get("criteria") or "")
                    # cpe:2.3:part:vendor:product:version:update:…
                    if len(f) < 7 or f[0] != "cpe" or f[2] not in ("o", "h"):
                        continue
                    vendor = VENDOR_MAP.get(unescape(f[3]).lower())
                    if not vendor:
                        continue
                    product = unescape(f[4]).lower()
                    version, update = unescape(f[5]), unescape(f[6])
                    si = m.get("versionStartIncluding") or ""
                    se = m.get("versionStartExcluding") or ""
                    ei = m.get("versionEndIncluding") or ""
                    ee = m.get("versionEndExcluding") or ""
                    exact = ""
                    if version not in ("*", "-"):
                        exact = version
                        if update not in ("*", "-", ""):
                            exact += update  # junos 21.4 + r3-s4 → 21.4r3-s4
                    if not exact and not (si or se or ei or ee):
                        continue  # wildcard with no range — unmatchable, drop
                    yield [vendor, product, cve_id, sev, f"{score:g}",
                           si, se, ei, ee, exact, kev, published, summary]


def kev_ids_from(path: Path | None) -> set[str]:
    if path is None:
        return set()
    doc = load_json(path)
    ids = {v.get("cveID") for v in doc.get("vulnerabilities") or []}
    ids.discard(None)
    if not ids:
        sys.exit(f"error: {path} doesn't look like the CISA KEV catalog")
    return ids


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("nvd", nargs="+", type=Path,
                    help="NVD 2.0 feed file(s): nvdcve-2.0-<YEAR>.json[.gz]")
    ap.add_argument("--kev", type=Path, default=None,
                    help="CISA known_exploited_vulnerabilities.json[.gz]")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"output CSV (default {DEFAULT_OUT})")
    args = ap.parse_args()

    kev_ids = kev_ids_from(args.kev)
    seen: set[tuple[str, ...]] = set()
    rows: list[list[str]] = []
    for path in args.nvd:
        if not path.exists():
            sys.exit(f"error: {path} not found")
        doc = load_json(path)
        for row in rows_from_nvd(doc, kev_ids):
            key = tuple(row[:10])  # identity = applicability, not metadata
            if key not in seen:
                seen.add(key)
                rows.append(row)
        print(f"  {path.name}: {len(rows)} rows so far")

    if not rows:
        sys.exit("error: no network-OS applicability rows found — wrong input files?")

    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=args.out.parent, suffix=".tmp")
    except PermissionError:
        sys.exit(f"error: cannot write under {args.out.parent} — the data/ tree "
                 "may be root-owned from install. Create the feed dir once with\n"
                 f"  sudo mkdir -p {args.out.parent} && sudo chown $(id -u) {args.out.parent}\n"
                 "then re-run (or pass --out elsewhere and adjust VULN_FEED_PATH).")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(CSV_HEADER)
            w.writerows(rows)
        # mkstemp creates 0600; the API container runs as a different (nonroot)
        # uid and only needs read — make it world-readable before the swap.
        os.chmod(tmp, 0o644)
        os.replace(tmp, args.out)  # atomic: the mtime bump is the reload signal
    except BaseException:
        os.unlink(tmp)
        raise

    kev_rows = sum(1 for r in rows if r[10] == "1")
    vendors = sorted({r[0] for r in rows})
    print(f"wrote {args.out}: {len(rows)} advisory rows "
          f"({kev_rows} known-exploited) across {', '.join(vendors)}")
    print("The API hot-reloads the feed — the Vulnerability Management board "
          "updates on its next refresh.")


if __name__ == "__main__":
    main()
