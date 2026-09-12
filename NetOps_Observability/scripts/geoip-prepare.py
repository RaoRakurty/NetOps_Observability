#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Prepare an IP→country dataset for the platform's Geo IP flow analytics.

Converts a publicly obtainable GeoIP database into the canonical CSV the
ClickHouse `netops.geoip_country` ip_trie dictionary reads:

    network,country
    1.0.0.0/24,AU
    2001:200::/32,JP

Accepted inputs (auto-detected):
  * MaxMind GeoLite2 Country CSV zip  (GeoLite2-Country-CSV_*.zip from
    maxmind.com — free with a MaxMind account; their EULA forbids us
    redistributing it, so you download it yourself)
  * DB-IP Country Lite CSV            (dbip-country-lite-*.csv[.gz] from
    db-ip.com — CC BY 4.0, no account needed)

Output goes to ClickHouse's user_files so the dictionary can read it:
    data/clickhouse/user_files/geoip/country.csv

The dictionary is created by the API's self-healing bootstrap and lazy-loads,
so the Geo IP panels light up on their next refresh after this script runs —
no restarts. The dictionary re-reads the file when its mtime changes
(LIFETIME 1-2h), so re-run this script to pick up dataset updates.

Stdlib only, like everything else in scripts/.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import ipaddress
import os
import sys
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

Row = tuple[str, str]  # (cidr_network, iso_country)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "data" / "clickhouse" / "user_files" / "geoip" / "country.csv"


def rows_from_geolite2_zip(path: Path) -> Iterator[Row]:
    """GeoLite2 Country CSV zip: join Blocks-IPv4/IPv6 to Locations-en.

    Blocks rows carry geoname ids; the en locations file maps those to ISO
    country codes. geoname_id is the located country; fall back to
    registered_country_geoname_id (the registrar) when location is absent.
    """
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()

        def member(suffix: str) -> str | None:
            return next((n for n in names if n.endswith(suffix)), None)

        loc_name = member("Country-Locations-en.csv")
        if loc_name is None:
            sys.exit("error: zip has no GeoLite2-Country-Locations-en.csv — is this the Country (not City/ASN) CSV bundle?")

        geoname_to_iso: dict[str, str] = {}
        with zf.open(loc_name) as f:
            for rec in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8")):
                iso = (rec.get("country_iso_code") or "").strip()
                if iso:
                    geoname_to_iso[rec["geoname_id"]] = iso

        for suffix in ("Country-Blocks-IPv4.csv", "Country-Blocks-IPv6.csv"):
            blocks_name = member(suffix)
            if blocks_name is None:
                continue  # v6-only or v4-only bundles are still useful
            with zf.open(blocks_name) as f:
                for rec in csv.DictReader(io.TextIOWrapper(f, encoding="utf-8")):
                    geoname = rec.get("geoname_id") or rec.get("registered_country_geoname_id") or ""
                    iso = geoname_to_iso.get(geoname.strip())
                    if iso:
                        yield rec["network"], iso


def rows_from_dbip_csv(path: Path) -> Iterator[Row]:
    """DB-IP Country Lite: headerless ip_start,ip_end,country range rows.

    ip_trie wants CIDR prefixes, so each range is split into the minimal
    covering set of networks (stdlib summarize_address_range).
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:  # type: ignore[operator]
        for rec in csv.reader(f):
            if len(rec) < 3:
                continue
            start_s, end_s, country = rec[0].strip(), rec[1].strip(), rec[2].strip()
            if not country or country == "ZZ":  # ZZ = unknown/reserved
                continue
            try:
                start, end = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
            except ValueError:
                continue  # tolerate stray header/comment lines
            if start.version != end.version:
                continue
            for net in ipaddress.summarize_address_range(start, end):
                yield str(net), country


def detect_reader(path: Path) -> Iterator[Row]:
    if zipfile.is_zipfile(path):
        return rows_from_geolite2_zip(path)
    if path.suffix in (".csv", ".gz"):
        return rows_from_dbip_csv(path)
    sys.exit(f"error: can't tell what {path.name} is — expected a GeoLite2 Country CSV .zip or a DB-IP country .csv[.gz]")


def write_atomic(rows: Iterator[Row], out: Path) -> int:
    """Write header+rows to a temp file, then rename over the target.

    Atomic so ClickHouse never reloads a half-written file; the rename also
    bumps mtime, which is what triggers the dictionary's reload.
    """
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=out.parent, suffix=".tmp")
    except PermissionError:
        sys.exit(
            f"error: cannot write under {out.parent}\n"
            "data/clickhouse is owned by the ClickHouse container user; re-run with sudo:\n"
            f"  sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}"
        )
    count = 0
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["network", "country"])
            for network, country in rows:
                w.writerow([network, country])
                count += 1
        if count == 0:
            sys.exit("error: input parsed but produced no usable network→country rows")
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, out)
    finally:
        try:
            os.unlink(tmp_name)  # no-op after a successful replace
        except FileNotFoundError:
            pass
    return count


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="GeoLite2 Country CSV .zip, or DB-IP country lite .csv[.gz]")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output CSV (default: {DEFAULT_OUT})")
    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"error: {args.input} not found")

    count = write_atomic(detect_reader(args.input), args.out)
    print(f"wrote {count:,} networks → {args.out}")
    print("the Geo IP flow panels pick this up automatically (dictionary lazy-load / mtime reload).")


if __name__ == "__main__":
    main()
