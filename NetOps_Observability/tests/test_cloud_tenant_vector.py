# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 392 — the cloud metric lane's tenant, on the shipped Vector configs.

Before 392 `metrics_normalized` stamped EVERY metric's tenant by looking its
`device` up in device_tenant.csv. A cloud sample's `device` is the resource
NAME, so tenant B's device named like tenant A's resource stamped A's cloud
series as B's in netops.metrics and VictoriaMetrics.

Pinned here:
  * static (always runs): both shipped copies route a cloud sample through
    `cloud:<index>` only, never through `.device`; only an attributed cloud
    sample reaches the VictoriaMetrics bridge; the transient marker never rides
    the bus;
  * docker (skips loudly without docker): `vector test` of
    deployment/docker/vector/tests/cloud-tenant.yaml on the shipped transform.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_harness import run_vector_test

ROOT = Path(__file__).resolve().parent.parent
AGG = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
HELM = ROOT / "deployment" / "helm" / "correlix" / "files" / "vector" / "vector.yaml"
AGG_DIR = AGG.parent
FIXTURES = AGG_DIR / "tests" / "fixtures"
VECTOR_IMAGE = "timberio/vector:0.40.0-alpine"
ENV_STUBS = [
    "CLICKHOUSE_USER=x", "CLICKHOUSE_PASSWORD=x", "OPENSEARCH_URL=http://x:9200",
    "DB_HOST=x", "DB_USER=x", "DB_PASSWORD=x",
    "INGEST_TOKEN=preflight-stub", "INGEST_TOKEN_TRAPS=preflight-stub",
    "INGEST_TOKEN_PROBES=preflight-stub", "INGEST_TOKEN_METRICS=preflight-stub",
    "INGEST_TOKEN_BUS=preflight-stub",
]


def _cfg(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", [AGG, HELM], ids=["compose", "helm"])
def test_the_cloud_branch_never_reads_the_device_identity(path: Path) -> None:
    src = _cfg(path)["transforms"]["metrics_normalized"]["source"]
    m = re.search(r'if \(string\(\.signal_family\) \?\? ""\) == "cloud_resource" \{(.*?)\n\s*\} else if',
                  src, re.S)
    assert m, "metrics_normalized must branch the cloud lane before the device lookup"
    cloud_branch = m.group(1)
    assert '"cloud:" + rid' in cloud_branch and "string(.index)" in cloud_branch
    assert "dev" not in re.findall(r"\b\w+\b", cloud_branch), \
        "the cloud branch must never key on the device NAME"
    assert '.__cloud_registry = "miss"' in cloud_branch  # a miss is explicit, never platform


@pytest.mark.parametrize("path", [AGG, HELM], ids=["compose", "helm"])
def test_only_an_attributed_cloud_sample_reaches_victoriametrics(path: Path) -> None:
    cond = _cfg(path)["transforms"]["cloud_metrics_only"]["condition"]
    assert '.__cloud_registry == "hit"' in cond, cond


@pytest.mark.parametrize("path", [AGG, HELM], ids=["compose", "helm"])
def test_the_transient_marker_never_rides_the_bus(path: Path) -> None:
    sinks = _cfg(path)["sinks"]
    bus = [s for s in sinks.values()
           if s.get("topic") == "netops.metrics" and "metrics_normalized" in s.get("inputs", [])]
    assert bus, "the netops.metrics sink moved — update this guard"
    for s in bus:
        assert "__cloud_registry" in s["encoding"]["except_fields"]


def test_both_shipped_copies_are_identical() -> None:
    assert AGG.read_bytes() == HELM.read_bytes()


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def test_cloud_tenant_suite_on_the_shipped_transform() -> None:
    if not _docker_available():
        pytest.skip("docker is unavailable, so the cloud-tenant suite DID NOT RUN against "
                    "the shipped transform. Run it before shipping.")
    suite = AGG_DIR / "tests" / "cloud-tenant.yaml"
    cases = len(yaml.safe_load(suite.read_text(encoding="utf-8"))["tests"])
    cmd = ["docker", "run", "--rm", "--entrypoint", "vector"]
    for kv in ENV_STUBS:
        cmd += ["-e", kv]
    for src, dst in ((AGG, "/etc/vector/vector.yaml"),
                     (AGG_DIR / "tests", "/etc/vector/tests"),
                     (FIXTURES, "/etc/vector/enrichment")):
        cmd += ["-v", f"{src}:{dst}:ro"]
    cmd += [VECTOR_IMAGE, "test", "/etc/vector/vector.yaml", "/etc/vector/tests/cloud-tenant.yaml"]
    run = run_vector_test(cmd, label="cloud tenant", timeout=900)
    assert run.final.returncode == 0, f"vector test failed:\n{run.report()}"
    assert run.output.count("... passed") == cases, run.output
