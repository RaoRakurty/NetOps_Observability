# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""scripts/asn-prepare.py (tracker 387 PR 13d): the iptoasn dataset becomes the
CIDR -> AS CSV the netops.ip_asn ip_trie dictionary reads. Values, not presence:
unrouted space never gets an AS, a pinned digest refuses other bytes, and what
was loaded is always traceable."""

from __future__ import annotations

import csv
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "asn-prepare.py"

SAMPLE = (
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n"
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    "1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP\n"
    "8.8.8.0\t8.8.8.10\t15169\tUS\tGOOGLE\n"
    "garbage line\n"
    "2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n"
    "9.9.9.9\t9.9.9.0\t19281\tUS\treversed range\n"
)


def _mod():
    spec = importlib.util.spec_from_file_location("asn_prepare", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


def _input(tmp_path: Path) -> tuple[Path, str]:
    p = tmp_path / "ip2asn-combined.tsv.gz"
    body = gzip.compress(SAMPLE.encode())
    p.write_bytes(body)
    return p, hashlib.sha256(body).hexdigest()


def test_ranges_become_cidrs_and_unrouted_space_gets_no_as(tmp_path):
    m = _mod()
    src, digest = _input(tmp_path)
    out = tmp_path / "uf" / "asn.csv"
    assert m.main(["--input", str(src), "--sha256", digest, "--out", str(out)]) == 0
    rows = list(csv.reader(out.open()))
    assert rows[0] == ["network", "asn"]
    got = {tuple(r) for r in rows[1:]}
    assert ("1.0.0.0/24", "13335") in got and ("1.0.4.0/22", "38803") in got
    assert ("2001:4860::/32", "15169") in got
    # 8.8.8.0-8.8.8.10 is not one prefix: its minimal covering set.
    assert {("8.8.8.0/29", "15169"), ("8.8.8.8/31", "15169"), ("8.8.8.10/32", "15169")} <= got
    assert not any(n.startswith(("1.0.1.", "1.0.2.")) for n, _ in got), "AS 0 is absence"
    assert not any(a == "19281" for _, a in got), "a reversed range is not data"
    prov = json.loads((tmp_path / "uf" / "asn.csv.source").read_text())
    assert prov["sha256"] == digest and prov["pinned"] is True and prov["licence"].startswith("PDDL-1.0")
    assert prov["networks"] == len(rows) - 1


def test_a_pin_refuses_other_bytes_and_writes_nothing(tmp_path, capsys):
    m = _mod()
    src, _ = _input(tmp_path)
    out = tmp_path / "uf" / "asn.csv"
    assert m.main(["--input", str(src), "--sha256", "0" * 64, "--out", str(out)]) == 2
    assert "not the copy you reviewed" in capsys.readouterr().err
    assert not out.exists()


def test_unpinned_input_records_its_digest(tmp_path):
    m = _mod()
    src, digest = _input(tmp_path)
    out = tmp_path / "asn.csv"
    assert m.main(["--input", str(src), "--out", str(out)]) == 0
    prov = json.loads((tmp_path / "asn.csv.source").read_text())
    assert prov["sha256"] == digest and prov["pinned"] is False


def test_an_input_with_no_routed_rows_is_refused(tmp_path, capsys):
    m = _mod()
    p = tmp_path / "empty.tsv"
    p.write_text("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n")
    assert m.main(["--input", str(p), "--out", str(tmp_path / "asn.csv")]) == 2
    assert "no routed" in capsys.readouterr().err
    assert not (tmp_path / "asn.csv").exists()


@pytest.mark.parametrize("bad", ["ABC", "g" * 64, "0" * 63])
def test_a_malformed_pin_is_refused(tmp_path, bad):
    m = _mod()
    src, _ = _input(tmp_path)
    assert m.main(["--input", str(src), "--sha256", bad, "--out", str(tmp_path / "a.csv")]) == 2
