"""Step-2 assurance contracts stay pinned to the as-built truth (tracker #151).

mtls-edges.yaml and telemetry-lanes.yaml are THIN OVERLAYS: they must never
drift from the sources they overlay — the transport inventory (edge ids), the
kafka-init topic list (lane topics), and the workload identity registry
(SPIFFE service names). Drift here would hand step 2 a test plan for a mesh
that does not exist.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEC = ROOT / "docs" / "security"


def _load(name: str) -> dict:
    return json.loads((SEC / name).read_text())


def test_mtls_edges_reference_real_inventory_edges():
    inv_ids = {e["id"] for e in _load("transport-inventory.yaml")["edges"]}
    rows = _load("mtls-edges.yaml")["edges"]
    assert rows, "mtls-edges.yaml has no rows"
    bad = [r["edge"] for r in rows if r["edge"] not in inv_ids]
    assert not bad, f"contract rows referencing nonexistent inventory edges: {bad}"


def test_every_tls_profile_edge_has_a_contract_row():
    inv = _load("transport-inventory.yaml")["edges"]
    covered = {r["edge"] for r in _load("mtls-edges.yaml")["edges"]}
    missing = [
        e["id"] for e in inv
        if "tls" in (e.get("security_profile", {}).get("transport") or "").lower()
        and e["id"] not in covered
    ]
    assert not missing, (
        f"TLS-profile inventory edges with NO assurance contract: {missing} — "
        "add a row to mtls-edges.yaml (the coverage rule in its header)")


def test_contract_identities_are_registry_services():
    """Every spiffe id named in either contract must belong to a service the
    workload registry actually issues (regex over workloadid.go — the same
    cross-language pinning preflight uses on compose)."""
    src = (ROOT / "src" / "backend" / "internal" / "workloadid" / "workloadid.go").read_text()
    services = set(re.findall(r'\{Service:\s*"([a-z0-9-]+)"', src))
    assert len(services) >= 25, "workloadid parse drift"
    spiffe_re = re.compile(r"spiffe://netops/ns/default/sa/([a-z0-9-]+)")
    for fname in ("mtls-edges.yaml", "telemetry-lanes.yaml"):
        text = (SEC / fname).read_text()
        named = set(spiffe_re.findall(text))
        unknown = named - services
        assert not unknown, f"{fname} names identities the registry does not issue: {sorted(unknown)}"


def test_lane_topics_are_created_by_kafka_init():
    """Every literal netops.* topic a lane names must be in kafka-init's
    creation list (auto-create is OFF — an uncreated topic is a dead lane)."""
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    init = compose[compose.index("kafka-init:"):]
    init = init[:init.index("networks:")]
    created = set(re.findall(r"(netops\.[a-z_.0-9]+)", init))
    assert len(created) >= 14, f"kafka-init parse drift: {sorted(created)}"
    lanes = _load("telemetry-lanes.yaml")["lanes"]
    named: set[str] = set()
    for lane in lanes:
        for field in (lane.get("topic", ""), lane.get("entry", "")):
            named |= set(re.findall(r"(netops\.[a-z_.0-9]+)", field))
    missing = named - created
    assert not missing, f"lanes name topics kafka-init never creates: {sorted(missing)}"


def test_consumer_groups_match_asbuilt_names():
    lanes = _load("telemetry-lanes.yaml")["lanes"]
    groups = {c["group"] for lane in lanes for c in lane.get("consumers", [])}
    for g in groups:
        assert g == "netops-correlation" or g.startswith("netops-router-"), (
            f"unexpected consumer-group naming: {g}")


def test_schema_versions():
    for fname in ("mtls-edges.yaml", "telemetry-lanes.yaml"):
        assert _load(fname)["schema_version"] == 1
