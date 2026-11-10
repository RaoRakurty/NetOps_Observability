# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The engine reads the wider registry row exactly as it read the old one (tracker 387).

Lives in this suite because importing main needs the engine's dependencies, which the
ingest-contract job does not install.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

CORRELATION = Path(__file__).resolve().parent
FACT_COLUMNS = ("device_id", "vendor", "model", "site", "role")
HEADER = ("identity", "tenant_id") + FACT_COLUMNS


_ENGINE_PROBE = textwrap.dedent("""\
    import json, os, sys
    sys.argv = ["probe"]
    import main as M
    M.TENANT_ENRICHMENT_FILE = os.environ["PROBE_FILE"]
    M._tenant_mtime = -1.0
    M._tenant_map = {}
    M._tenant_stat_at = -1e9
    out = {"registry": M._tenant_registry()}
    for ident in json.loads(os.environ["PROBE_IDS"]):
        out[ident] = M.tenant_lookup(ident)
    try:
        M.verified_tenant("", "shared-name", "syslog", registry_anchored=True)
        out["verified_shared"] = "accepted"
    except M.TenantClaimRefused as exc:
        out["verified_shared"] = exc.reason
    out["verified_known"] = M.verified_tenant("", "arista-leaf1", "syslog", registry_anchored=True)
    print("PROBE" + json.dumps(out))
""")


def _engine_read(tmp_path: Path, lines: list[str], ids: list[str]) -> dict:
    path = tmp_path / "device_tenant.csv"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-c", _ENGINE_PROBE], capture_output=True, text=True, check=False,
        cwd=CORRELATION,
        env={"PYTHONPATH": str(CORRELATION), "PATH": "/usr/bin:/bin",
             "PROBE_FILE": str(path), "PROBE_IDS": json.dumps(ids)},
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    marker = [ln for ln in proc.stdout.splitlines() if ln.startswith("PROBE")]
    assert marker, proc.stdout[-500:]
    return json.loads(marker[-1][len("PROBE"):])


def _seven_columns() -> list[str]:
    return [
        ",".join(HEADER),
        "arista-leaf1,lab,arista-leaf1-id,arista,DCS-7050,dc1,leaf",
        'with-comma,lab,x,cisco,"M,1","a, b",core',
        "platform-box,,plat-1,cisco,M2,,",
        # The writer omits a shared identity; the reader re-asserts it for a file
        # something else wrote, and extra columns must not defeat that.
        "shared-name,acme,a,cisco,M,,",
        "shared-name,globex,b,juniper,N,,",
    ]


def test_the_engine_reads_tenant_by_position_past_the_new_columns(tmp_path):
    got = _engine_read(tmp_path, _seven_columns(),
                       ["arista-leaf1", "with-comma", "platform-box", "shared-name", "nobody"])
    assert got["registry"] == {"arista-leaf1": "lab", "with-comma": "lab", "platform-box": ""}
    assert got["arista-leaf1"] == "lab"
    assert got["with-comma"] == "lab"
    assert got["platform-box"] == ""        # a hit, platform-owned
    assert got["nobody"] is None            # a miss, not ""
    assert got["verified_known"] == "lab"


def test_an_identity_two_tenants_claim_stays_a_miss_with_extra_columns(tmp_path):
    got = _engine_read(tmp_path, _seven_columns(), ["shared-name"])
    assert got["shared-name"] is None
    assert got["verified_shared"] == "identity_unattributable"


def test_the_engine_reads_a_file_from_before_the_columns(tmp_path):
    got = _engine_read(tmp_path, ["identity,tenant_id", "arista-leaf1,lab"], ["arista-leaf1"])
    assert got["registry"] == {"arista-leaf1": "lab"}
    assert got["verified_known"] == "lab"


def test_the_columns_after_tenant_never_reach_the_engine_map(tmp_path):
    """A fact equal to a real tenant id is still not a tenant."""
    got = _engine_read(tmp_path, [",".join(HEADER), "edge,lab,globex,globex,globex,globex,globex",
                                  "arista-leaf1,lab,,,,,"], ["edge"])
    assert got["edge"] == "lab"
