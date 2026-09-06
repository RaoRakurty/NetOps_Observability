# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Path-causality P1 discovery WIRING — main.discovery_paths_for fusing the flow /
cloud-inventory / DNS feeds into the live attribution pass (the plumbing slice the P2
integration left as a follow-up).

The contract these tests hold (the whole point of the slice):

  * CLOUD-WITHOUT-TRACEROUTE — a cloud incident with FLOW + INVENTORY evidence but NO
    measured run still yields a typed SRC→DST path (a CLOUD segment with the LB as a
    key device); driven through the REAL engine an on-path cloud LB fault now ATTRIBUTES
    and lifts the verdict — exactly what a missing traceroute used to block.
  * ADDITIVE / NO-OP — when NONE of the four feeds yields anything, discovery_paths_for
    returns () (byte-identical to the pre-fusion no-op) and the engine object is
    byte-for-byte unchanged.
  * PER-TENANT ISOLATION (§3a) — another tenant's flow pairs / inventory topology never
    enter this tenant's path; inventory is tenant-gated to CLOUD_LOGS_TENANT; flow reads
    strictly this tenant's own map (never the "" global).
  * FEED LOADERS — the flow / inventory / DNS loaders each read the REAL live source and
    stay tenant-scoped and exception-safe.

Offline + pure: bundled provider snapshot via the P0 classifier, a temp topology file
for the inventory source, no wall clock, no ClickHouse.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import main
from catalog import builtin_catalog
from cloud_producers import cloud_signal
from engine import EngineConfig, run_window
from path_assembly import DnsHead
from path_graph import PathGraphView
from segment_classifier import DeviceRole, SegmentType
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    ProbeIntent,
    Severity,
    Signal,
    Source,
    VantageType,
    derive_probe_authority,
)
from verdicts import VerdictTier

CAT = builtin_catalog()
T0 = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)

TENANT = "acme"
# Public AWS addresses (the S3 us-east-1 range the bundled snapshot classifies CLOUD/aws).
PUB_SUBNET = "52.216.100.0"   # the public subnet network address (inventory upstream anchor)
LB_IP = "52.216.100.5"
HOST_IP = "52.216.100.6"
LB_NAME = "correlix-edge-urlmap"
APP = "checkout"


# ── globals fixture: save/restore every main global these tests touch ─────────


@pytest.fixture()
def clean_main(tmp_path):
    saved = {
        "CLOUD_TOPOLOGY_DIR": main.CLOUD_TOPOLOGY_DIR,
        "CLOUD_LOGS_TENANT": main.CLOUD_LOGS_TENANT,
        "CORR_PATH_ATTRIBUTION": main.CORR_PATH_ATTRIBUTION,
        "flow_dir": dict(main._FLOW_DIR),
    }
    main._FLOW_DIR.clear()
    main._cloud_topo_cache.clear()
    main._cloud_topo_mtimes.clear()
    main.CORR_PATH_ATTRIBUTION = True
    main.CLOUD_TOPOLOGY_DIR = ""
    main.CLOUD_LOGS_TENANT = ""
    try:
        yield
    finally:
        main.CLOUD_TOPOLOGY_DIR = saved["CLOUD_TOPOLOGY_DIR"]
        main.CLOUD_LOGS_TENANT = saved["CLOUD_LOGS_TENANT"]
        main.CORR_PATH_ATTRIBUTION = saved["CORR_PATH_ATTRIBUTION"]
        main._FLOW_DIR.clear()
        main._FLOW_DIR.update(saved["flow_dir"])
        main._cloud_topo_cache.clear()
        main._cloud_topo_mtimes.clear()


def _write_topology(dir_path: str, name: str = "aws-topology.json") -> None:
    """A minimal cloud topology fixture: one public subnet whose declared next hop is the
    edge LB — the inventory source the correlation service reads WITHOUT a traceroute."""
    topo = {
        "provider": "aws",
        "account_id": "1234",
        "region": "us-east-1",
        "subnets": [{"id": "subnet-pub", "cidr": "52.216.100.0/24", "name": "correlix-public-a"}],
        "nodes": [{"id": "lb-1", "kind": "instance", "name": LB_NAME, "private_ip": LB_IP}],
        "edges": [{"from_subnet": "subnet-pub", "to": "lb-1", "to_kind": "lb",
                   "via_route_table": "rtb-pub"}],
    }
    with open(os.path.join(dir_path, name), "w", encoding="utf-8") as f:
        json.dump(topo, f)


# ── incident signals (an app symptom + an on-path cloud LB 5xx) ───────────────


def app_symptom(tenant: str = TENANT, ts: datetime = T0) -> Signal:
    authority = derive_probe_authority(ProbeIntent.CUSTOMER_PATH, VantageType.ENTERPRISE_AGENT)
    return Signal(
        tenant_id=tenant, ts=ts, source=Source.PROBE, kind="synthetic_http_5xx",
        observer=Observer(observer_id="vantage-nyc", observer_type=ObserverType.VANTAGE_AGENT,
                          collection_path="direct"),
        modality_class=ModalityClass.ACTIVE_PROBE, entity_type=EntityType.APP, entity_id=APP,
        severity=Severity.HIGH, native_id="symptom|1", entity_tokens=(f"app:{APP}",),
        attrs={"probe_authority": authority.value},
    )


def lb_5xx_fault(tenant: str = TENANT, ts: datetime = T0 + timedelta(seconds=10)) -> Signal:
    """An AWS ALB access-log 5xx for the edge LB — a PASSIVE_FLOW cloud witness
    (independent of the probe vantage). The ALB log carries the LB's address, which is
    how it lands ON the discovered inventory/flow path (the LB node's IP)."""
    return cloud_signal(
        tenant, ts, "cloud_lb_log", app=APP, resource_id=LB_NAME,
        account="1234", region="us-east-1", severity=Severity.HIGH,
        attrs={"http_status": 502, "address": LB_IP},
    )


def _run(window, discovery=()):
    snaps = run_window(window, CAT, (), EngineConfig(), discovery=discovery)
    assert len(snaps) == 1, f"fixture must be one object, got {len(snaps)}"
    return snaps[0]


# ── 1. CLOUD attributes WITHOUT a traceroute (flow + inventory, no measured) ───


def test_cloud_incident_attributes_without_traceroute(clean_main, tmp_path):
    # INVENTORY feed: a topology snapshot (no measured run anywhere).
    main.CLOUD_TOPOLOGY_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = TENANT
    _write_topology(str(tmp_path))
    # FLOW feed: this tenant's directed NetFlow pair LB→host (the ordering edge).
    main._FLOW_DIR[TENANT] = {(LB_IP, HOST_IP): 5000.0}

    empty_view = PathGraphView.from_dict({})   # NO measured observations
    paths = main.discovery_paths_for(TENANT, empty_view, [])
    assert paths, "flow + inventory must yield a discovered path without a traceroute"

    # the discovered path is a CLOUD segment carrying the LB as a key device.
    the_path = next(p for p in paths if any(
        kd.role == DeviceRole.LOAD_BALANCER.value
        for s in p.segments for kd in s.key_devices))
    assert SegmentType.CLOUD.value in {s.segment_type for s in the_path.segments}
    lb_labels = {kd.label for s in the_path.segments for kd in s.key_devices
                 if kd.role == DeviceRole.LOAD_BALANCER.value}
    assert LB_IP in lb_labels

    # drive it through the REAL engine: the on-path LB fault now ATTRIBUTES + lifts.
    snap = _run([app_symptom(), lb_5xx_fault()], discovery=paths)
    a = snap.attribution
    assert a is not None and a.attributed is not None, "on-path cloud LB must attribute"
    assert a.attributed.device.role == DeviceRole.LOAD_BALANCER.value
    assert a.attributed.kind == "cloud_lb_log"
    # independent cross-modality pair (probe vantage ⟂ cloud API) → confirmed, uncapped.
    assert a.verdict.tier is VerdictTier.CONFIRMED
    assert a.confidence_lifted and not a.capped


# ── 2. ADDITIVE / NO-OP: no feed → () and the engine object is byte-identical ──


def test_no_feeds_is_a_pure_no_op(clean_main):
    # nothing configured: no measured obs, no flow, no inventory (dir unset), no dns.
    empty_view = PathGraphView.from_dict({})
    assert main.discovery_paths_for(TENANT, empty_view, []) == ()

    # and the engine object is byte-for-byte what it is with no discovery at all.
    window = [app_symptom(), lb_5xx_fault()]
    base = _run(window)
    same = _run(window, discovery=main.discovery_paths_for(TENANT, empty_view, []))
    assert same.attribution is None
    assert same.content_hash() == base.content_hash()
    assert same.to_object_row(1) == base.to_object_row(1)
    assert same.to_object_row(1)["attribution"] == "{}"


def test_attribution_flag_off_yields_nothing(clean_main, tmp_path):
    main.CORR_PATH_ATTRIBUTION = False
    main.CLOUD_TOPOLOGY_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = TENANT
    _write_topology(str(tmp_path))
    main._FLOW_DIR[TENANT] = {(LB_IP, HOST_IP): 5000.0}
    assert main.discovery_paths_for(TENANT, PathGraphView.from_dict({}), []) == ()


# ── 3. PER-TENANT ISOLATION (§3a) ─────────────────────────────────────────────


def test_flow_feed_is_strictly_this_tenant(clean_main):
    # acme's own pair + an "" global pair + evil's pair. Only acme's own contributes.
    main._FLOW_DIR["acme"] = {("10.0.0.1", "10.0.0.2"): 100.0}
    main._FLOW_DIR[""] = {("10.9.9.1", "10.9.9.2"): 100.0}
    main._FLOW_DIR["evil"] = {("10.6.6.1", "10.6.6.2"): 100.0}
    edges = main._flow_discovery_edges("acme")
    pairs = {(e.upstream.address, e.downstream.address) for e in edges}
    assert pairs == {("10.0.0.1", "10.0.0.2")}
    assert all(e.tenant_id == "acme" for e in edges)


def test_inventory_feed_is_tenant_gated(clean_main, tmp_path):
    main.CLOUD_TOPOLOGY_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = "acme"
    _write_topology(str(tmp_path))
    # the owning tenant gets inventory edges...
    assert main._inventory_discovery_edges("acme"), "owning tenant sees the topology"
    assert all(e.tenant_id == "acme" for e in main._inventory_discovery_edges("acme"))
    # ...every OTHER tenant sees NONE (a fixture belongs to CLOUD_LOGS_TENANT only).
    assert main._inventory_discovery_edges("evil") == ()


def test_cross_tenant_flow_never_enters_this_tenant_path(clean_main):
    # evil owns a flow pair; acme has its own. acme's discovered paths never contain
    # evil's addresses — a path can only carry this tenant's evidence.
    main._FLOW_DIR["acme"] = {("10.0.0.1", "10.0.0.2"): 100.0}
    main._FLOW_DIR["evil"] = {("10.6.6.1", "10.6.6.2"): 100.0}
    paths = main.discovery_paths_for("acme", PathGraphView.from_dict({}), [])
    all_addrs = {a for p in paths for s in p.segments for a in s.member_addresses}
    assert "10.6.6.1" not in all_addrs and "10.6.6.2" not in all_addrs
    assert all(p.tenant_id == "acme" for p in paths)


# ── 4. FEED LOADERS — DNS head + inventory snapshot loader ─────────────────────


def _dns_signal(tenant: str, name: str, ts: datetime = T0) -> Signal:
    return cloud_signal(
        tenant, ts, "cloud_dns_log", resource_id=name, account="vpc-1", region="",
        severity=Severity.WARN, metric_name="dns_resolution_failed", value=3.0,
        attrs={"rcode": "SERVFAIL", "provider": "aws"},
    )


def test_dns_head_loader_builds_head_from_window(clean_main):
    sig = _dns_signal(TENANT, "app.example.com")
    heads = main._dns_heads_from_window(TENANT, [sig])
    assert "app.example.com" in heads
    h = heads["app.example.com"]
    assert isinstance(h, DnsHead)
    assert h.tenant_id == TENANT and h.query_name == "app.example.com"
    # a FAILED resolution carries no answer — resolved_address stays empty (honest).
    assert h.resolved_address == ""


def test_dns_head_loader_is_tenant_scoped(clean_main):
    mine = _dns_signal("acme", "mine.example.com")
    theirs = _dns_signal("evil", "evil.example.com")
    heads = main._dns_heads_from_window("acme", [mine, theirs])
    assert set(heads) == {"mine.example.com"}
    assert all(h.tenant_id == "acme" for h in heads.values())


def test_dns_head_attaches_to_scope_when_frontend_matches():
    heads = {HOST_IP: DnsHead(TENANT, query_name="app.example.com", resolved_address=HOST_IP)}
    assert main._head_for_scope(heads, PUB_SUBNET, HOST_IP) is heads[HOST_IP]  # dst match
    assert main._head_for_scope(heads, PUB_SUBNET, "1.2.3.4") is None          # no match


def test_inventory_snapshot_loader_reads_and_caches(clean_main):
    with tempfile.TemporaryDirectory() as d:
        main.CLOUD_TOPOLOGY_DIR = d
        _write_topology(d, "aws-topology.json")
        snaps = main.cloud_topology_snapshots()
        assert "aws-topology.json" in snaps
        assert snaps["aws-topology.json"]["provider"] == "aws"
        # unset dir → empty (default-closed), never a crash.
        main.CLOUD_TOPOLOGY_DIR = ""
        assert main.cloud_topology_snapshots() == {}


def test_discovery_survives_a_broken_topology_file(clean_main, tmp_path):
    # a malformed topology must degrade the inventory feed to empty, never break the
    # cycle — flow still contributes and a path is still produced.
    main.CLOUD_TOPOLOGY_DIR = str(tmp_path)
    main.CLOUD_LOGS_TENANT = TENANT
    with open(os.path.join(str(tmp_path), "aws-topology.json"), "w", encoding="utf-8") as f:
        f.write("{ this is not json")
    main._FLOW_DIR[TENANT] = {("10.0.0.1", "10.0.0.2"): 100.0}
    paths = main.discovery_paths_for(TENANT, PathGraphView.from_dict({}), [])
    # inventory yielded nothing; flow still made a path.
    addrs = {a for p in paths for s in p.segments for a in s.member_addresses}
    assert "10.0.0.1" in addrs
