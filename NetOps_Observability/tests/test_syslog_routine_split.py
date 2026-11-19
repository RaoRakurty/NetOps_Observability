# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Tracker 410 — the router's write-time routine split (owner 2026-11-19).

Routine management-session syslog goes to netops-syslogroutine-* (its own,
shorter ISM window); everything else to netops-syslog-* exactly as before.

Config pins run everywhere. The docker-gated tests run the SHIPPED router
config: a `vector test` suite is GENERATED from the same fixture the Go twin
reads (tests/fixtures/logroutine/static.json → internal/logroutine/static_test.go),
so the VRL and logroutine.StaticRoutine cannot disagree on a case without one of
the two suites going red. The kill switch is proved the same way.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test  # tracker 350

ROOT = Path(__file__).resolve().parent.parent
ROUTER_DIR = ROOT / "deployment" / "docker" / "vector-router"
ROUTER = ROUTER_DIR / "vector.yaml"
FIXTURE = ROOT / "tests" / "fixtures" / "logroutine" / "static.json"
CLAUSE_GO = ROOT / "src" / "backend" / "internal" / "logroutine" / "clause.go"
ENRICH = ROOT / "deployment" / "docker" / "vector" / "tests" / "fixtures"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"   # in sync with docker-compose.yml

needs_docker = pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")


def _router() -> dict:
    return yaml.safe_load(ROUTER.read_text(encoding="utf-8"))


def _cases() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def _go_list(name: str) -> list[str]:
    src = CLAUSE_GO.read_text(encoding="utf-8")
    m = re.search(r"var %s = \[\]string\{(.*?)\n\}" % name, src, re.S) or \
        re.search(r"var %s = \[\]string\{(.*?)\}" % name, src, re.S)
    assert m, f"{name} not found in {CLAUSE_GO}"
    return re.findall(r'"([^"]+)"', m.group(1))


# ── config pins ──────────────────────────────────────────────────────────────

def test_routine_route_carries_every_word_of_the_go_rule():
    cond = _router()["transforms"]["syslog_store_route"]["route"]["routine"]
    for name in ("sessionDetailTypes", "sessionDetailPrefixes", "failureWords"):
        for v in _go_list(name):
            assert f'"{v}"' in cond, f"the router's routine condition lacks {name} entry {v!r}"
    assert '"management_audit"' in cond
    assert '"snmp"' in cond and '"snmp_"' in cond
    # A quarantine envelope must never be routine (it would be stored twice).
    assert "cx_quarantine" in cond


def test_kill_switch_defaults_on_and_compares_exactly():
    cond = _router()["transforms"]["syslog_store_route"]["route"]["routine"]
    assert cond.lstrip().startswith('"${SYSLOG_ROUTINE_SPLIT:-on}" == "on"'), cond[:80]


def test_routine_sink_mirrors_the_syslog_sink():
    sinks = _router()["sinks"]
    main, routine = sinks["opensearch_syslog"], sinks["opensearch_syslog_routine"]
    assert routine["inputs"] == ["syslog_store_route.routine"]
    assert main["inputs"] == ["syslog_store_route._unmatched"], \
        "routine records must leave the main family, not be stored twice"
    assert routine["bulk"]["index"] == "netops-syslogroutine-{{ tenant_seg }}-%Y.%m.%d"
    for key in ("id_key", "request_retry_partial", "batch", "request", "buffer", "encoding", "auth",
                "endpoints", "healthcheck", "mode", "api_version"):
        assert routine.get(key) == main.get(key), f"opensearch_syslog_routine.{key} drifted from opensearch_syslog"
    assert routine["buffer"]["when_full"] == "block"


def test_bootstrap_verifier_derives_a_covered_lane():
    """scripts/bootstrap-opensearch.sh --verify takes split('-')[1] of every
    router sink index: the dash-free family base must come out whole, and
    netops_writer must name it."""
    index = _router()["sinks"]["opensearch_syslog_routine"]["bulk"]["index"]
    assert index.split("-")[1] == "syslogroutine"
    roles = (ROOT / "deployment" / "docker" / "opensearch" / "security" / "roles.yml").read_text()
    writer = roles.split("\nnetops_writer:\n", 1)[1].split("\n\n", 1)[0]
    assert '"netops-syslogroutine-*"' in writer


# ── `vector test` over the shipped config ────────────────────────────────────

ENV_STUBS = ["CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x"]


def _suite(cases: list[dict], force: str | None = None) -> dict:
    tests = []
    for c in cases:
        routine = c["routine"] if force is None else (force == "routine" and c["routine"])
        want, other = ("syslog_store_route.routine", "syslog_store_route._unmatched") if routine \
            else ("syslog_store_route._unmatched", "syslog_store_route.routine")
        fields = dict(c["record"])
        fields.update({"message": "fixture: " + c["name"], "tenant_seg": "acme"})
        tests.append({
            "name": ("split " if force is None else "split off ") + c["name"],
            "inputs": [{"insert_at": "syslog_rules", "type": "log", "log_fields": fields}],
            "outputs": [{"extract_from": want, "conditions": [{
                "type": "vrl", "source": 'assert_eq!(.message, "fixture: %s")' % c["name"]}]}],
            "no_outputs_from": [other],
        })
    return {"tests": tests}


def _run(tmp_path: Path, suite: dict, env: list[str]):
    (tmp_path / "suite.yaml").write_text(yaml.safe_dump(suite, sort_keys=False))
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS + env:
        cmd += ["-e", kv]
    for src, dst in [
        (ROUTER, "/etc/vector/vector.yaml"),
        (ROUTER_DIR / "processors-default.yaml", "/etc/vector/processors/processors.yaml"),
        (tmp_path / "suite.yaml", "/etc/vector/tests/suite.yaml"),
        (ENRICH, "/etc/vector/enrichment"),
    ]:
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml",
            "/etc/vector/processors/processors.yaml", "/etc/vector/tests/suite.yaml"]
    return run_vector_test(cmd, label="router routine split", timeout=900)


@needs_docker
def test_vrl_split_agrees_with_the_go_rule_on_every_fixture_case(tmp_path):
    cases = _cases()
    run = _run(tmp_path, _suite(cases), [])
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == len(cases), run.output


@needs_docker
def test_kill_switch_sends_everything_to_the_main_family(tmp_path):
    cases = _cases()
    run = _run(tmp_path, _suite(cases, force="main"), ["SYSLOG_ROUTINE_SPLIT=off"])
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == len(cases), run.output


# ── the kill switches must actually reach the containers ─────────────────────
# They were read (router vector.yaml, api logs.go) but passed by no compose
# `environment:` and no Helm template, so "set SYSLOG_ROUTINE_SPLIT=off" in the
# runbook changed nothing (docs audit 2026-11-19). These pin the passthrough.
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
HELM = ROOT / "deployment" / "helm" / "correlix"


def _compose_env(service: str) -> dict:
    svc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"][service]
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env)
    return env


def test_compose_passes_the_routine_split_switch_to_the_router():
    assert _compose_env("vector-router").get("SYSLOG_ROUTINE_SPLIT") == "${SYSLOG_ROUTINE_SPLIT:-on}"


def test_compose_passes_the_rollup_switch_to_the_api():
    assert _compose_env("api").get("ROUTINE_SYSLOG_ROLLUP") == "${ROUTINE_SYSLOG_ROLLUP:-on}"


def test_helm_carries_both_switches_with_on_defaults():
    values = yaml.safe_load((HELM / "values.yaml").read_text(encoding="utf-8"))
    assert values["vectorRouter"]["routineSplit"] == "on"
    assert values["api"]["routineSyslogRollup"] == "on"
    pipeline = (HELM / "templates" / "pipeline.yaml").read_text(encoding="utf-8")
    core = (HELM / "templates" / "core.yaml").read_text(encoding="utf-8")
    assert re.search(r"name: SYSLOG_ROUTINE_SPLIT, value: \{\{ \.Values\.vectorRouter\.routineSplit", pipeline)
    assert re.search(r"name: ROUTINE_SYSLOG_ROLLUP, value: \{\{ \.Values\.api\.routineSyslogRollup", core)


def test_the_api_reads_the_rollup_switch_it_is_given():
    logs_go = (ROOT / "src" / "backend" / "logs.go").read_text(encoding="utf-8")
    assert 'envOr("ROUTINE_SYSLOG_ROLLUP", "on")' in logs_go
