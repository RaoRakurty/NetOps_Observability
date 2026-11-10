# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The embedded IANA tables are what their pins say (tracker 387 PR 13).

`scripts/gen-iana-tables.py --check` verifies, offline, that each table's header
names the pinned source digest and that its body digest matches the body. A
hand edit or a stale pin fails here, in the never-skipped `tests/` lane.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "scripts" / "gen-iana-tables.py"
TABLES = ROOT / "src" / "backend" / "internal" / "iana"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_iana_tables", GEN)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_check_passes_on_the_committed_tables() -> None:
    proc = subprocess.run([sys.executable, str(GEN), "--check"], capture_output=True, text=True,
                          timeout=120, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_hand_edit_fails_the_check(tmp_path: Path) -> None:
    out = tmp_path / "src" / "backend" / "internal" / "iana"
    out.mkdir(parents=True)
    for name in ("protocols.tsv", "services.tsv"):
        (out / name).write_text((TABLES / name).read_text(encoding="utf-8"), encoding="utf-8")
    text = (out / "services.tsv").read_text(encoding="utf-8")
    (out / "services.tsv").write_text(text.replace("17\t161\tsnmp", "17\t161\tnot-snmp"), encoding="utf-8")
    proc = subprocess.run([sys.executable, str(GEN), "--check", "--root", str(tmp_path)],
                          capture_output=True, text=True, timeout=120, check=False,
                          env={"IANA_CACHE": str(tmp_path / "no-cache"), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "body-sha256 does not match" in proc.stderr


def test_the_values_flows_show() -> None:
    """Values, not presence: the rows the lab's traffic resolves through."""
    protos = (TABLES / "protocols.tsv").read_text(encoding="utf-8").splitlines()
    svcs = (TABLES / "services.tsv").read_text(encoding="utf-8").splitlines()
    assert "17\tUDP" in protos and "6\tTCP" in protos
    for row in ("17\t161\tsnmp", "17\t162\tsnmptrap", "17\t514\tsyslog", "6\t830\tnetconf-ssh"):
        assert row in svcs, row


def test_reduction_keeps_only_number_transport_and_name() -> None:
    gen = _gen()
    csv_body = (
        b"Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,"
        b"Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes\n"
        b"snmp,161,udp,SNMP,Some Person,mailto:person@example.org,,,,,,\n"
        b"snmp,161,tcp,SNMP,,,,,,,,\n"
        b"dup,161,udp,second name,,,,,,,,\n"
        b"https,443,tcp,http over tls,,,,,,,,\n"
        b"x11,6000-6063,tcp,range,,,,,,,,\n"
        b",9,udp,unnamed,,,,,,,,\n"
    )
    rows = gen.service_rows(csv_body)
    assert rows == [(6, 161, "snmp"), (6, 443, "https"), (17, 161, "snmp")]
    rendered = gen.render("services", "ip_protocol\tport\tname", [f"{p}\t{q}\t{n}" for p, q, n in rows])
    assert "person" not in rendered and "example.org" not in rendered
