#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Prepare the IP -> AS number dataset for flow analytics (tracker 387 PR 13d).

The lab's exporters send no AS numbers (cflowd's template has no BGP AS
elements): 100 % of flows read src_as = dst_as = 0. This fills them at QUERY
time from iptoasn.com's ip2asn-combined dataset, through the ClickHouse
`netops.ip_asn` ip_trie dictionary, which reads:

    network,asn
    1.0.0.0/24,13335
    2001:200::/32,2500

The exporter's own AS always wins; the dataset only answers where the exporter
sent none, and the flows API labels each answer as_basis = exporter | dataset |
absent. "Not routed" ranges (AS 0) are left out, so private and unrouted space
stays absent: never a guessed AS.

LICENCE. iptoasn.com: "Licensed under Public Domain (PDDL v1.0)", Open Data
Commons Public Domain Dedication and License v1.0
(https://opendatacommons.org/licenses/pddl/1-0/), verified 2026-11-10. No
obligation; recorded in scripts/license-data.json. The dataset is fetched by the
operator, never shipped in the repository or the images.

PINNING. The source is refreshed hourly, so a fixed digest cannot pin "the
latest". Pin the copy you reviewed instead: --sha256 HEX refuses any other
bytes. Without it the digest is computed, printed and recorded beside the
output (asn.csv.source), so what is loaded is always traceable.

Output goes to ClickHouse's user_files, which the dictionary reads:
    data/clickhouse/user_files/asn/asn.csv
That directory belongs to the ClickHouse container user, so a host run needs
sudo (the script says so). The dictionary re-reads the file when it changes
(LIFETIME 1-2 h). Until a file exists the dictionary reads FAILED and the API
reports the dataset as absent (netops_flow_dataset_status), and AS numbers
read as_basis=absent: never silent, never invented.

Usage:
    python3 scripts/asn-prepare.py --fetch                       # download, prepare, record the digest
    python3 scripts/asn-prepare.py --input ip2asn-combined.tsv.gz --sha256 <hex>
Stdlib only, like everything else in scripts/.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "data" / "clickhouse" / "user_files" / "asn" / "asn.csv"
SOURCE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
LICENCE = "PDDL-1.0 (https://opendatacommons.org/licenses/pddl/1-0/)"

# Bounds: the real dataset is ~11 MB compressed and ~720k ranges.
MAX_SOURCE_BYTES = 64 << 20
MAX_RANGES = 3_000_000
FETCH_TIMEOUT_S = 120

Row = tuple[str, int]  # (cidr network, asn)


class PrepareError(Exception):
    """The input, the pin or the output is not what it must be."""


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_input(path: Path) -> bytes:
    try:
        with open(path, "rb") as fh:
            body = fh.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise PrepareError(f"cannot read {path}: {exc}") from exc
    if len(body) > MAX_SOURCE_BYTES:
        raise PrepareError(f"{path} is over {MAX_SOURCE_BYTES} bytes")
    return body


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "correlix-asn-prepare"})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:  # a fixed https URL
            body = resp.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise PrepareError(f"fetch {url} failed: {exc}") from exc
    if len(body) > MAX_SOURCE_BYTES:
        raise PrepareError(f"{url} returned over {MAX_SOURCE_BYTES} bytes")
    return body


def rows_from_tsv(body: bytes) -> Iterator[Row]:
    """ip2asn-combined: range_start, range_end, AS number, country, description.

    ip_trie wants CIDR prefixes, so each range becomes its minimal covering set
    (summarize_address_range). AS 0 ("Not routed") and malformed lines are
    skipped: the first is absence, the second is not data.
    """
    raw = gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body
    if len(raw) > 8 * MAX_SOURCE_BYTES:
        raise PrepareError("the decompressed dataset is implausibly large")
    n = 0
    for line in io.StringIO(raw.decode("utf-8", errors="replace")):
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 3 or not cols[2].strip().isdigit():
            continue
        asn = int(cols[2])
        if asn == 0 or asn > 4294967295:
            continue
        try:
            start, end = ipaddress.ip_address(cols[0].strip()), ipaddress.ip_address(cols[1].strip())
        except ValueError:
            continue
        if start.version != end.version or end < start:
            continue
        n += 1
        if n > MAX_RANGES:
            raise PrepareError(f"more than {MAX_RANGES} ranges: not the dataset this script knows")
        for net in ipaddress.summarize_address_range(start, end):
            yield str(net), asn


def write_atomic(rows: Iterator[Row], out: Path, provenance: dict) -> int:
    """Header and rows to a temp file, renamed over the target, so ClickHouse
    never reloads a half-written file. The provenance sidecar is written last."""
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=out.parent, suffix=".tmp")
    except PermissionError as exc:
        raise PrepareError(
            f"cannot write under {out.parent}: data/clickhouse belongs to the ClickHouse "
            f"container user. Re-run with sudo: sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}") from exc
    except OSError as exc:
        raise PrepareError(f"cannot write under {out.parent}: {exc}") from exc
    count = 0
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["network", "asn"])
            for network, asn in rows:
                w.writerow([network, asn])
                count += 1
        if count == 0:
            raise PrepareError("the input parsed but produced no routed network -> AS rows")
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, out)
        side = out.with_name(out.name + ".source")
        side.write_text(json.dumps({**provenance, "networks": count}, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise PrepareError(f"cannot write {out}: {exc}") from exc
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)  # only a failed run leaves it; a successful replace moved it
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", type=Path, help="a downloaded ip2asn-combined.tsv[.gz]")
    src.add_argument("--fetch", action="store_true", help=f"download {SOURCE_URL}")
    ap.add_argument("--sha256", help="refuse any input whose sha256 is not this (the copy you reviewed)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output CSV (default: {DEFAULT_OUT})")
    args = ap.parse_args(argv)
    try:
        if args.sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
            raise PrepareError("--sha256 must be 64 lowercase hex characters")
        body = fetch(SOURCE_URL) if args.fetch else read_input(args.input)
        digest = sha256_hex(body)
        if args.sha256 is not None and digest != args.sha256:
            raise PrepareError(f"input sha256 is {digest}, pinned {args.sha256}: not the copy you reviewed")
        provenance = {
            "source": SOURCE_URL if args.fetch else str(args.input),
            "sha256": digest,
            "pinned": args.sha256 is not None,
            "licence": LICENCE,
            "prepared_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        count = write_atomic(rows_from_tsv(body), args.out, provenance)
    except PrepareError as exc:
        print(f"asn-prepare: {exc}", file=sys.stderr)
        return 2
    print(f"asn-prepare: wrote {count:,} networks to {args.out} (source sha256 {digest}"
          f"{', pinned' if args.sha256 else ', recorded in ' + args.out.name + '.source'})")
    print("asn-prepare: the flows API picks it up when the dictionary reloads (within 2 hours); "
          "netops_flow_dataset_status{dataset=\"asn\"} reads loaded once it has.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
