# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Masked sender detection (tracker 373) — never silent again.

A device's syslog / trap / flow that reaches a receiver re-sourced from the
Docker bridge gateway (a stale UDP conntrack entry after a recreate, or an IPv6
sender relayed to the IPv4 network) has lost its sender address: device and
tenant attribution are impossible. The gateway can never be a real device, so
each receiver stamps `source_masked`, vector-router counts it per topic
(netops_ingest_source_masked_events) and IngestSenderAddressMasked alerts
(rules-tests/ingest-source-masked.test.yaml).

Here: the Vector wrapper derives the gateway (and says so either way), the
exact syslog_sender program stamps only the gateway, and the router / compose
wiring is in place. The Go trap receiver is covered by
src/backend/collectors/masked_source_test.go.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "deployment" / "docker"
WRAPPER = DOCKER / "vector" / "cx-enrichment-reload.sh"
AGG = DOCKER / "vector" / "vector.yaml"
ROUTER = DOCKER / "vector-router" / "vector.yaml"
COMPOSE = DOCKER / "docker-compose.yml"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"  # in sync with docker-compose.yml

BRIDGE_ROUTES = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
                 "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\n"
                 "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n")


def _wrapper(tmp_path: Path, routes: str | None, mode: str | None) -> subprocess.CompletedProcess:
    """Run the real wrapper with a stub vector that prints what it inherited."""
    stub = tmp_path / "vector-stub"
    stub.write_text('#!/bin/sh\necho "GW=${CX_BRIDGE_GATEWAY:-}"\n')
    stub.chmod(0o755)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CX_VECTOR_BIN": str(stub),
           "CX_ENRICHMENT_CSV": str(tmp_path / "absent.csv"), "CX_ENRICHMENT_POLL_SECONDS": "1"}
    if routes is not None:
        (tmp_path / "route").write_text(routes)
        env["CX_ROUTE_TABLE"] = str(tmp_path / "route")
    if mode is not None:
        env["CX_MASKED_SOURCE_DETECT"] = mode
    return subprocess.run(["sh", str(WRAPPER)], env=env, capture_output=True, text=True, timeout=60, check=False)


# ── the wrapper derives the gateway, and says so either way ─────────────────

def test_the_wrapper_exports_the_bridge_gateway(tmp_path: Path) -> None:
    run = _wrapper(tmp_path, BRIDGE_ROUTES, "docker-bridge")
    assert "GW=172.18.0.1" in run.stdout, run.stdout + run.stderr
    assert "masked-source detection on (bridge gateway 172.18.0.1)" in run.stderr


def test_the_wrapper_says_when_detection_cannot_run(tmp_path: Path) -> None:
    run = _wrapper(tmp_path, "Iface\tDestination\tGateway\n", "docker-bridge")
    assert "GW=\n" in run.stdout
    assert "masked-source detection OFF" in run.stderr, "never silent"


def test_the_wrapper_does_nothing_outside_docker_bridge(tmp_path: Path) -> None:
    run = _wrapper(tmp_path, BRIDGE_ROUTES, None)
    assert "GW=\n" in run.stdout, "on host networking the default gateway is a real router"
    assert "masked-source" not in run.stderr


# ── the exact syslog_sender program ─────────────────────────────────────────

def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


CASES = [
    # (name, origin ip, expected source_masked)
    ("the gateway is masked", "172.18.0.1", True),
    ("a real sender is not", "192.168.222.107", False),
    ("another container is not", "172.18.0.21", False),
    ("no origin is not", None, False),
]


def _suite(program: str, cases: list[tuple[str, str | None, bool]]) -> str:
    tests = []
    for name, origin, masked in cases:
        fields = {"message": "x", "source_ip": "172.18.0.12"}
        if origin is not None:
            fields["origin.ip"] = origin
        cond = "assert_eq!(.source_masked, true)" if masked else "assert!(!exists(.source_masked))"
        tests.append({
            "name": name,
            "inputs": [{"insert_at": "syslog_sender", "type": "log", "log_fields": fields}],
            "outputs": [{"extract_from": "syslog_sender", "conditions": [{"type": "vrl", "source": cond}]}],
        })
    return yaml.safe_dump({"transforms": {"syslog_sender": {"type": "remap", "inputs": [], "source": program}},
                           "tests": tests}, sort_keys=False)


@pytest.mark.skipif(not _docker_available(), reason="docker is required to run `vector test`")
@pytest.mark.parametrize("gateway", ["172.18.0.1", ""])
def test_the_exact_syslog_program_stamps_only_the_gateway(tmp_path: Path, gateway: str) -> None:
    program = yaml.safe_load(AGG.read_text())["transforms"]["syslog_sender"]["source"]
    # Detection off (no gateway): nothing is ever stamped, not even the gateway.
    cases = CASES if gateway else [(n, o, False) for n, o, _ in CASES]
    suite = tmp_path / "masked.yaml"
    suite.write_text(_suite(program, cases))
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector", "-v", f"{tmp_path}:/t:ro"]
    if gateway:
        cmd += ["-e", f"CX_BRIDGE_GATEWAY={gateway}"]
    cmd += [VECTOR_IMAGE, "test", "/t/masked.yaml"]
    run = run_vector_test(cmd, label=f"syslog-masked-{gateway or 'off'}", timeout=600)
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == len(cases), run.output


# ── wiring ──────────────────────────────────────────────────────────────────

def test_the_router_stamps_flows_and_counts_every_lane() -> None:
    t = yaml.safe_load(ROUTER.read_text())
    tr = t["transforms"]
    assert 'get_env_var("CX_BRIDGE_GATEWAY")' in tr["flows_decoded"]["source"]
    assert ".source_masked = true" in tr["flows_decoded"]["source"]
    assert set(tr["source_masked_events"]["inputs"]) == {"syslog_tagged", "snmptrap_tagged", "flows_decoded"}
    metric = tr["source_masked_metric"]["metrics"][0]
    assert metric["name"] == "netops_ingest_source_masked_events"
    assert set(metric["tags"]) == {"topic"}, "per topic only — no device or tenant label"
    exporters = [s for s in t["sinks"].values() if s.get("type") == "prometheus_exporter"]
    assert any("source_masked_metric" in s["inputs"] for s in exporters), "the counter must be scraped"


def test_compose_turns_detection_on_for_every_receiver() -> None:
    svcs = yaml.safe_load(COMPOSE.read_text())["services"]
    for name in ("api", "vector-aggregator", "vector-router"):
        assert svcs[name]["environment"]["CX_MASKED_SOURCE_DETECT"] == "docker-bridge", name


def test_the_alert_has_a_runbook_that_exists() -> None:
    rules = yaml.safe_load((ROOT / "src" / "config" / "rules.yaml").read_text())
    alert = next(r for g in rules["groups"] for r in g["rules"] if r.get("alert") == "IngestSenderAddressMasked")
    assert (ROOT / alert["annotations"]["runbook"]).is_file()
    assert alert["labels"]["severity"] == "warning", "the page tier stays at exactly four conditions"
