#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""gen-iana-tables.py: the IANA protocol and service names the flows API shows
(tracker 387 PR 13).

Two IANA registries name what a flow's numbers mean:

  protocol-numbers        IP protocol number -> keyword  (17 -> UDP)
  service-names-port-numbers  (transport, port) -> service name (udp/161 -> snmp)

They are fetched, sha256-pinned and reduced at BUILD time into two small tables
the backend embeds (src/backend/internal/iana/*.tsv), the same pin-and-verify
model as the MIB FETCH_PINS (tracker 377). Nothing is fetched at run time and a
customer install never reaches iana.org.

LICENCE. IANA and the IETF dedicate the Protocol Registries to the public domain
under CC0 1.0 (https://www.iana.org/help/licensing-terms, revised 2021-11-10),
recorded in scripts/license-data.json. The reduced tables keep only the number,
transport and name columns; the registry's contact and assignee columns are never
copied.

A service name is a HEURISTIC wherever it is shown: a port says what is usually
there, not what a flow carried (the flows API labels it so).

Usage:
    python3 scripts/gen-iana-tables.py --fetch   # download into the cache, verify the pins
    python3 scripts/gen-iana-tables.py           # regenerate the tables from the cache
    python3 scripts/gen-iana-tables.py --check   # exit 1 if a table is stale or unpinned

--check works offline: it verifies each table's header names the pinned source
digest and that the body digest the header states is the body it carries. When
the pinned sources are in the cache it also regenerates and compares byte for byte.
Re-pinning (IANA updates the service registry often) is: --fetch with --repin,
review the diff, commit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import sys
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
OUT_DIR_REL = os.path.join("src", "backend", "internal", "iana")

# The pins. `fetched` is the UTC date the digest was taken; a re-pin changes all three.
PINS: dict[str, dict[str, str]] = {
    "protocols": {
        "url": "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv",
        "file": "protocol-numbers-1.csv",
        "sha256": "ba37fe0a4e01e45fe172f212ade37b908f4d56bbab0be9a97423bcfb9b8271a9",
        "fetched": "2026-11-09",
    },
    "services": {
        "url": "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
        "file": "service-names-port-numbers.csv",
        "sha256": "9824a8e9d6a6fc86b4f5400894802224b8c12f81a54b60741db11b9e30fe1b10",
        "fetched": "2026-11-09",
    },
}

# The transports a flow record can carry a port for, by IP protocol number.
TRANSPORTS = {"tcp": 6, "udp": 17, "dccp": 33, "sctp": 132}

# Bounds: a registry that grew past these is a parse fault, not a bigger table.
MAX_SOURCE_BYTES = 8 << 20
MAX_PROTOCOL_ROWS = 256
MAX_SERVICE_ROWS = 40000
FETCH_TIMEOUT_S = 60


class GenerationError(Exception):
    """A pin, a source or a table is not what it must be."""


def cache_dir() -> str:
    return os.environ.get("IANA_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "correlix", "iana")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_source(name: str) -> bytes | None:
    """The cached source for a pin, verified; None when it is not cached."""
    pin = PINS[name]
    path = os.path.join(cache_dir(), pin["file"])
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            body = fh.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise GenerationError(f"{name}: cannot read the cached source {path}: {exc}") from exc
    if len(body) > MAX_SOURCE_BYTES:
        raise GenerationError(f"{name}: cached source {path} is over {MAX_SOURCE_BYTES} bytes")
    got = sha256_bytes(body)
    if got != pin["sha256"]:
        raise GenerationError(
            f"{name}: cached {path} has sha256 {got}, pinned {pin['sha256']}: the cache is "
            "stale or tampered. Delete it and --fetch, or --fetch --repin after review.")
    return body


def fetch(repin: bool) -> None:
    os.makedirs(cache_dir(), exist_ok=True)
    for name, pin in sorted(PINS.items()):
        req = urllib.request.Request(pin["url"], headers={"User-Agent": "correlix-gen-iana-tables"})
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:  # a pinned https URL
                body = resp.read(MAX_SOURCE_BYTES + 1)
        except OSError as exc:
            raise GenerationError(f"{name}: fetch {pin['url']} failed: {exc}") from exc
        if len(body) > MAX_SOURCE_BYTES:
            raise GenerationError(f"{name}: {pin['url']} returned over {MAX_SOURCE_BYTES} bytes")
        got = sha256_bytes(body)
        if got != pin["sha256"] and not repin:
            raise GenerationError(
                f"{name}: {pin['url']} now has sha256 {got}, pinned {pin['sha256']}. IANA "
                "updated the registry: review it and re-run with --fetch --repin.")
        dest = os.path.join(cache_dir(), pin["file"])
        tmp = dest + ".part"
        try:
            with open(tmp, "wb") as fh:
                fh.write(body)
            os.replace(tmp, dest)  # a partial download never becomes the cache
        except OSError as exc:
            raise GenerationError(f"{name}: cannot write the cache {dest}: {exc}") from exc
        if got != pin["sha256"]:
            print(f"gen-iana-tables: {name}: REPIN sha256 {got} (was {pin['sha256']}); "
                  "update PINS in this file with it and today's date", file=sys.stderr)


def _clean(s: str) -> str:
    """One registry cell as a single TSV-safe token."""
    return " ".join(s.replace("\t", " ").split())


def protocol_rows(body: bytes) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    seen: set[int] = set()
    for rec in csv.DictReader(io.StringIO(body.decode("utf-8-sig"))):
        dec = (rec.get("Decimal") or "").strip()
        if not dec.isdigit():
            continue  # a range ("146-252") names nothing
        n = int(dec)
        if n > 255 or n in seen:
            continue
        name = _clean(rec.get("Keyword") or "") or _clean(rec.get("Protocol") or "")
        if not name:
            continue
        seen.add(n)
        rows.append((n, name))
    if not rows or len(rows) > MAX_PROTOCOL_ROWS:
        raise GenerationError(f"protocols: {len(rows)} rows parsed, want 1..{MAX_PROTOCOL_ROWS}")
    if dict(rows).get(17) != "UDP" or dict(rows).get(6) != "TCP":
        raise GenerationError("protocols: 6 and 17 must read TCP and UDP; the registry layout changed")
    return sorted(rows)


def service_rows(body: bytes) -> list[tuple[int, int, str]]:
    """The FIRST registered name per (transport, port), in registry order."""
    first: dict[tuple[int, int], str] = {}
    for rec in csv.DictReader(io.StringIO(body.decode("utf-8-sig"))):
        name = _clean(rec.get("Service Name") or "")
        port = (rec.get("Port Number") or "").strip()
        proto = TRANSPORTS.get((rec.get("Transport Protocol") or "").strip().lower())
        if not name or proto is None or not port.isdigit():
            continue  # unnamed, another transport, or a range
        p = int(port)
        if p > 65535:
            continue
        first.setdefault((proto, p), name)
    if not first or len(first) > MAX_SERVICE_ROWS:
        raise GenerationError(f"services: {len(first)} rows parsed, want 1..{MAX_SERVICE_ROWS}")
    if first.get((17, 161)) != "snmp" or first.get((6, 443)) != "https":
        raise GenerationError("services: udp/161 and tcp/443 must read snmp and https; the layout changed")
    return sorted((proto, port, name) for (proto, port), name in first.items())


def render(name: str, columns: str, lines: list[str]) -> str:
    body = "".join(line + "\n" for line in lines)
    pin = PINS[name]
    head = (
        f"# GENERATED by scripts/gen-iana-tables.py from the IANA registry. DO NOT EDIT.\n"
        f"# source: {pin['url']}\n"
        f"# source-sha256: {pin['sha256']}\n"
        f"# fetched: {pin['fetched']}\n"
        f"# licence: CC0-1.0 (IANA Protocol Registries, https://www.iana.org/help/licensing-terms)\n"
        f"# body-sha256: {sha256_bytes(body.encode('utf-8'))}\n"
        f"# columns: {columns}\n"
    )
    return head + body


def build(protocols: bytes, services: bytes) -> dict[str, str]:
    return {
        "protocols.tsv": render("protocols", "number\tname",
                                [f"{n}\t{name}" for n, name in protocol_rows(protocols)]),
        "services.tsv": render("services", "ip_protocol\tport\tname",
                               [f"{p}\t{port}\t{name}" for p, port, name in service_rows(services)]),
    }


def check_offline(out_dir: str) -> list[str]:
    """Header and body consistency of the checked-in tables, without the sources."""
    problems: list[str] = []
    for fname, pin_name in (("protocols.tsv", "protocols"), ("services.tsv", "services")):
        path = os.path.join(out_dir, fname)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise GenerationError(f"cannot read {path}: {exc}") from exc
        head: dict[str, str] = {}
        body_lines: list[str] = []
        for line in text.splitlines(keepends=True):
            if line.startswith("# ") and ": " in line and not body_lines:
                k, v = line[2:].rstrip("\n").split(": ", 1)
                head[k] = v
            elif line.startswith("#") and not body_lines:
                continue
            else:
                body_lines.append(line)
        body = "".join(body_lines)
        if head.get("source-sha256") != PINS[pin_name]["sha256"]:
            problems.append(f"{fname}: source-sha256 {head.get('source-sha256')!r} is not the pin")
        if head.get("body-sha256") != sha256_bytes(body.encode("utf-8")):
            problems.append(f"{fname}: body-sha256 does not match the body (hand-edited?)")
        for i, line in enumerate(body_lines, 1):
            cols = line.rstrip("\n").split("\t")
            want = 2 if pin_name == "protocols" else 3
            if len(cols) != want or not all(c for c in cols) or not all(c.isdigit() for c in cols[:-1]):
                problems.append(f"{fname}: body line {i} is malformed: {line!r}")
                break
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a table is stale or unpinned")
    ap.add_argument("--fetch", action="store_true", help="download the pinned sources into the cache")
    ap.add_argument("--repin", action="store_true", help="with --fetch: accept a changed source digest")
    ap.add_argument("--root", default=REPO_ROOT, help="the tree to read and write")
    args = ap.parse_args(argv)
    out_dir = os.path.join(args.root, OUT_DIR_REL)
    try:
        if args.fetch:
            fetch(args.repin)
            if args.repin:
                return 0
        problems = check_offline(out_dir) if args.check else []
        protos, svcs = read_source("protocols"), read_source("services")
        if protos is None or svcs is None:
            if args.check:
                for p in problems:
                    print(f"gen-iana-tables: {p}", file=sys.stderr)
                if not problems:
                    print("gen-iana-tables: tables consistent with the pins (sources not cached, "
                          "so not regenerated)")
                return 1 if problems else 0
            raise GenerationError(f"the pinned sources are not in {cache_dir()}: run --fetch first")
        stale: list[str] = []
        for fname, content in build(protos, svcs).items():
            path = os.path.join(out_dir, fname)
            cur = None
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    cur = fh.read()
            if cur == content:
                continue
            if args.check:
                stale.append(fname)
                continue
            os.makedirs(out_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"gen-iana-tables: wrote {os.path.join(OUT_DIR_REL, fname)}")
        for p in problems:
            print(f"gen-iana-tables: {p}", file=sys.stderr)
        if stale:
            print(f"gen-iana-tables: STALE {stale}: re-run scripts/gen-iana-tables.py", file=sys.stderr)
        return 1 if (stale or problems) else 0
    except GenerationError as exc:
        print(f"gen-iana-tables: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # A table that cannot be read or written is a failed run, never a pass.
        raise SystemExit(f"gen-iana-tables: {exc}") from exc


if __name__ == "__main__":
    sys.exit(main())
