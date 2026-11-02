# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Syslog keeps its sender's network address (tracker 371, P0.5).

syslog-ng relays every message to the aggregator over its own TCP connection,
so Vector's syslog source recorded syslog-ng's container as `source_ip` — every
syslog document in the lab said 172.18.0.12 and the device's address was lost
at that hop. syslog-ng now stamps `${SOURCEIP}` into the RFC 5424 `origin`
element and the aggregator's `syslog_sender` transform restores it.

This file proves both halves:
  * the syslog-ng side, statically: the rewrite exists, writes origin.ip from
    SOURCEIP, and BOTH relay variants (plain and TLS) run it before the
    destination; the Helm chart carries byte-identical copies;
  * the Vector side, by running the EXACT `syslog_sender` program extracted
    from vector.yaml under `vector test` on the pinned image: a valid v4 / v6
    sender is restored, anything else leaves source_ip as received.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parents[1]
SYSLOG_NG = ROOT / "deployment" / "docker" / "syslog-ng"
HELM_SYSLOG_NG = ROOT / "deployment" / "helm" / "correlix" / "files" / "syslog-ng"
AGG = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"  # in sync with docker-compose.yml


# ── syslog-ng ──────────────────────────────────────────────────────────────────

def test_syslog_ng_stamps_the_sender_into_origin_ip() -> None:
    core = (SYSLOG_NG / "core.conf").read_text()
    m = re.search(r"rewrite\s+r_sender_address\s*\{(.*?)\};", core, re.S)
    assert m, "core.conf defines no r_sender_address rewrite"
    assert re.search(r'set\(\s*"\$\{SOURCEIP\}"\s+value\(\s*"\.SDATA\.origin\.ip"\s*\)\s*\)', m.group(1)), \
        "r_sender_address must write ${SOURCEIP} to .SDATA.origin.ip"


@pytest.mark.parametrize("variant", ["syslog-ng.conf", "syslog-ng-tls.conf"])
def test_every_relay_variant_runs_the_rewrite_before_the_destination(variant: str) -> None:
    conf = (SYSLOG_NG / variant).read_text()
    log = re.search(r"log\s*\{(.*?)\};", conf, re.S)
    assert log, f"{variant}: no log path"
    body = log.group(1)
    assert "rewrite(r_sender_address)" in body, f"{variant}: the sender rewrite is not in the log path"
    assert body.index("rewrite(r_sender_address)") < body.index("destination(d_vector)"), \
        f"{variant}: the rewrite must run before the message leaves for the aggregator"


@pytest.mark.parametrize("name", ["core.conf", "syslog-ng.conf", "syslog-ng-tls.conf"])
def test_helm_carries_the_same_syslog_ng_config(name: str) -> None:
    assert (HELM_SYSLOG_NG / name).read_bytes() == (SYSLOG_NG / name).read_bytes(), \
        f"helm copy of {name} is stale — run deployment/helm/stage-configs.sh"


# ── Vector ─────────────────────────────────────────────────────────────────────

def test_the_aggregator_routes_syslog_through_the_sender_transform() -> None:
    t = yaml.safe_load(AGG.read_text())["transforms"]
    assert t["syslog_sender"]["inputs"] == ["syslog_in"]
    assert t["syslog_normalized"]["inputs"] == ["syslog_sender"], \
        "syslog_normalized must read the restored stream, not syslog_in"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


CASES = [
    # (name, origin ip in the event or None, source_ip received, source_ip expected)
    ("v4 sender restored", "192.168.222.107", "172.18.0.12", "192.168.222.107"),
    ("v6 sender restored", "2001:db8::7", "172.18.0.12", "2001:db8::7"),
    ("non-address left as received", "not-an-ip", "172.18.0.12", "172.18.0.12"),
    ("empty left as received", "", "172.18.0.12", "172.18.0.12"),
    ("absent left as received", None, "172.18.0.12", "172.18.0.12"),
]


def _suite(program: str) -> str:
    tests = []
    for name, origin, received, expected in CASES:
        fields = {"message": "x", "source_ip": received}
        if origin is not None:
            fields["origin.ip"] = origin  # vector test takes a dotted path, not a nested map
        tests.append({
            "name": name,
            "inputs": [{"insert_at": "syslog_sender", "type": "log", "log_fields": fields}],
            "outputs": [{"extract_from": "syslog_sender", "conditions": [{
                "type": "vrl", "source": f'assert_eq!(.source_ip, "{expected}")'}]}],
        })
    return yaml.safe_dump({"transforms": {"syslog_sender": {"type": "remap", "inputs": [], "source": program}},
                           "tests": tests}, sort_keys=False)


@pytest.mark.skipif(not _docker_available(), reason="docker is required to run `vector test`")
def test_the_exact_sender_program_restores_only_valid_addresses(tmp_path: Path) -> None:
    program = yaml.safe_load(AGG.read_text())["transforms"]["syslog_sender"]["source"]
    suite = tmp_path / "syslog-sender.yaml"
    suite.write_text(_suite(program))
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector", "-v", f"{tmp_path}:/t:ro",
           VECTOR_IMAGE, "test", "/t/syslog-sender.yaml"]
    run = run_vector_test(cmd, label="syslog-sender", timeout=600)
    out = run.output
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert out.count("... passed") == len(CASES), out
