# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Inventory-driven vendor (tracker 387 PR 12, plan §6a layer 2).

The registry row gained `device_id, vendor, model, site, role`. These tests hold
the three things that must stay true as a result:

  * vendor from discovery beats the text guess in every executor, and a sender not
    in inventory falls back to format matching, recorded as such (`vector test` on
    the shipped transform, plus the engine's own executor);
  * every other reader of the file keeps working: the engine's positional loader,
    the scale harness, and the Vector tables on a file from before these columns;
  * tenant is untouched: an identity two tenants claim stays a miss everywhere.

The docker legs are the only ones that run the shipped VRL; without docker they
skip loudly, the same as the other Vector suites in this directory.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parent.parent
AGG_DIR = ROOT / "deployment" / "docker" / "vector"
ROUTER_DIR = ROOT / "deployment" / "docker" / "vector-router"
TEMPLATES = ROOT / "deployment" / "docker" / "opensearch" / "index-templates.json"
FIXTURES = AGG_DIR / "tests" / "fixtures"
MINILADDER = ROOT / "scripts" / "scale-miniladder.py"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "DB_HOST=x", "DB_USER=x", "DB_PASSWORD=x",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]
FACT_COLUMNS = ("device_id", "vendor", "model", "site", "role")
HEADER = ("identity", "tenant_id") + FACT_COLUMNS

_SKIP = ("docker is unavailable, so the inventory suite DID NOT RUN against the shipped "
         "transform. Run it before shipping.")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _vector_test(label: str, config: Path, suite_dir: Path, suite: str,
                 fixtures: Path, expected: int) -> None:
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS:
        cmd += ["-e", kv]
    for src, dst in ((config, "/etc/vector/vector.yaml"),
                     (suite_dir, "/etc/vector/tests"),
                     (fixtures, "/etc/vector/enrichment")):
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml", f"/etc/vector/tests/{suite}"]
    run = run_vector_test(cmd, label=label, timeout=900)
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == expected, run.output


# ── the shipped transforms ───────────────────────────────────────────────────

def test_inventory_suite_on_the_shipped_transform():
    if not _docker_available():
        pytest.skip(_SKIP)
    suite = AGG_DIR / "tests" / "inventory-vendor.yaml"
    cases = len(yaml.safe_load(suite.read_text(encoding="utf-8"))["tests"])
    _vector_test("inventory vendor", AGG_DIR / "vector.yaml", AGG_DIR / "tests",
                 "inventory-vendor.yaml", FIXTURES, cases)


def test_a_file_from_before_the_columns_still_loads_and_reads_as_no_facts(tmp_path):
    """Upgrade order: the new config can meet the old two-column file, and the
    install seed is still that shape until the api's first write."""
    if not _docker_available():
        pytest.skip(_SKIP)
    fixtures = tmp_path / "enrichment"
    fixtures.mkdir()
    (fixtures / "device_tenant.csv").write_text("identity,tenant_id\narista-leaf1,lab\n",
                                                encoding="utf-8")
    suites = tmp_path / "tests"
    suites.mkdir()
    (suites / "old.yaml").write_text(textwrap.dedent("""\
        tests:
          - name: "the tenant still resolves and no fact is invented"
            inputs:
              - insert_at: syslog_normalized
                type: log
                log_fields:
                  hostname: "arista-leaf1"
                  appname: "Rib"
                  severity: "notice"
                  message: "%BGP-3-NOTIFICATION: a line"
            outputs:
              - extract_from: syslog_normalized
                conditions:
                  - type: vrl
                    source: |
                      assert_eq!(.tenant_id, "lab")
                      assert_eq!(.tenant_registry, "hit")
                      assert_eq!(.vendor, "cisco")
                      assert_eq!(.vendor_source, "format")
                      assert!(!exists(.device_id))
                      assert!(!exists(.model))
        """), encoding="utf-8")
    _vector_test("old registry file", AGG_DIR / "vector.yaml", suites, "old.yaml", fixtures, 1)


# ── every other reader of the file ───────────────────────────────────────────

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


def test_the_scale_harness_reads_the_tenant_not_the_rest_of_the_row(monkeypatch):
    """`line.split(",", 1)` would have returned "lab,arista-leaf1-id,arista,...":
    keying a run's events by that re-splits the stream it measures."""
    spec = importlib.util.spec_from_file_location("scale_miniladder_iv", MINILADDER)
    ml = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ml
    spec.loader.exec_module(ml)
    st = ml.Stack.__new__(ml.Stack)
    st.cid = lambda name: "c1"
    body = "\n".join(_seven_columns()) + "\n"
    monkeypatch.setattr(ml, "run", lambda cmd, timeout, input_text=None: (0, body, ""))
    assert st.registry_tenant("arista-leaf1") == "lab"
    assert st.registry_tenant("with-comma") == "lab"
    assert st.registry_tenant("platform-box") == "global"
    assert st.registry_missing(["arista-leaf1", "absent"]) == ["absent"]


def test_both_vector_tiers_declare_the_whole_file():
    for path in (AGG_DIR / "vector.yaml", ROUTER_DIR / "vector.yaml"):
        text = path.read_text(encoding="utf-8")
        start = text.index("  device_tenant:")
        block = text[start:text.index("\n\n", start)]
        for col in HEADER:
            assert f"      {col}: string" in block, f"{path}: {col} not in the table schema"


def test_the_lanes_that_read_only_the_tenant_do_not_copy_the_facts():
    """The metric and flow lanes are the hottest in the pipeline: the columns must not
    cost them a bigger row per record. The log lanes read the facts, so they do not."""
    selected = 'select: ["tenant_id"]'
    agg = yaml.safe_load((AGG_DIR / "vector.yaml").read_text(encoding="utf-8"))["transforms"]
    router = yaml.safe_load((ROUTER_DIR / "vector.yaml").read_text(encoding="utf-8"))["transforms"]
    for name, src in (("metrics_normalized", agg["metrics_normalized"]["source"]),
                      ("probe_normalized", agg["probe_normalized"]["source"]),
                      ("flows_decoded", router["flows_decoded"]["source"]),
                      ("flows_rekey", router["flows_rekey"]["source"])):
        assert selected in src, f"{name} copies the whole registry row per record"
    for name in ("syslog_normalized", "snmptrap_normalized"):
        assert selected not in agg[name]["source"], f"{name} needs the facts"


def test_identity_and_tenant_stay_the_first_two_columns():
    """The engine reads them by position (main._tenant_registry)."""
    go = (ROOT / "src" / "backend" / "telemetry_enrichment.go").read_text(encoding="utf-8")
    want = ", ".join(f'"{c}"' for c in HEADER)
    assert f"enrichmentCSVHeader = []string{{{want}}}" in go
    with (FIXTURES / "device_tenant.csv").open(encoding="utf-8") as fh:
        assert tuple(next(csv.reader(fh))) == HEADER


# ── storage ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("lane", ["netops-syslog", "netops-snmptrap"])
def test_the_new_fields_are_declared_on_the_lanes_that_carry_them(lane):
    """Both templates are dynamic:false: an undeclared field lands in _source and
    cannot be filtered or aggregated, which is the failure mode this plan is about."""
    props = json.loads(TEMPLATES.read_text(encoding="utf-8"))["templates"][lane][
        "template"]["mappings"]["properties"]
    for field in ("vendor", "vendor_source", "device_id", "model", "site", "role"):
        assert props.get(field) == {"type": "keyword"}, f"{lane}: {field} = {props.get(field)}"
