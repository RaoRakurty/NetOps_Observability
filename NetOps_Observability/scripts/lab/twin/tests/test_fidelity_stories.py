"""Fidelity-wave plan building: trap/flow lanes in stories + baseline,
traffic_drop suppression, and BACK-COMPAT — a T1-core scenario (no new
constructs) builds the exact same plan as before the wave."""
import copy
import json
import os

from conftest import REPO_ROOT
from scenario import load_scenario, validate_scenario
from stories import build_run_plan

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")


def _example() -> dict:
    return load_scenario(EXAMPLE)


def test_t1_core_scenario_without_new_constructs_is_unchanged():
    """Strip the fidelity-wave constructs (baseline.flows) — the remaining
    T1-core scenario must produce a plan with ONLY T1-core lanes and no
    trap/flow items, i.e. old scenarios run exactly as they did."""
    sc = _example()
    del sc["baseline"]["flows"]
    plan = build_run_plan(sc, 600.0)
    lanes = {it["lane"] for it in plan["baseline"]}
    for stx in plan["stories"]:
        lanes |= {it["lane"] for it in stx["items"]}
    assert lanes <= {"syslog", "probes", "cloud", "metrics"}


def test_baseline_flows_expand_per_edge_device():
    sc = _example()
    plan = build_run_plan(sc, 60.0)
    flow_items = [it for it in plan["baseline"] if it["lane"] == "flows"]
    edges = {d["name"] for d in sc["devices"] if d["role"] == "edge"}
    assert {it["device"] for it in flow_items} == edges
    # 5 fps × 60 s per edge device, one compact item per second
    per_dev = [it for it in flow_items if it["device"] == "edge-a1"]
    assert len(per_dev) == 60
    assert all(it["count"] == 5 for it in per_dev)
    # deterministic: two builds byte-identical
    again = build_run_plan(load_scenario(EXAMPLE), 60.0)
    assert (json.dumps(plan, sort_keys=True)
            == json.dumps(again, sort_keys=True))


def test_with_trap_adds_link_and_bgp_traps():
    sc = _example()
    sc["stories"].append({
        "id": "ld-1", "template": "link_down_cascade",
        "trigger": {"at": "+10s"},
        "affected": {"devices": ["core-a1"], "tenants": ["acme"]},
        "params": {"with_trap": True},
        "expect": {"rca": {"affected_includes": ["core-a1"]}},
    })
    sc["stories"].append({
        "id": "bf-1", "template": "bgp_flap",
        "trigger": {"at": "+20s"},
        "affected": {"devices": ["br-b1"], "tenants": ["bluesky"]},
        "params": {"flap_count": 2, "with_trap": True},
        "expect": {"rca": {}},
    })
    validate_scenario(sc, name="with-trap")
    plan = build_run_plan(sc, 60.0)
    by_id = {s["id"]: s for s in plan["stories"]}
    ld_traps = [it for it in by_id["ld-1"]["items"] if it["lane"] == "trap"]
    assert [t["trap"] for t in ld_traps] == ["linkDown"]
    assert ld_traps[0]["ifname"] == "Ethernet1" and ld_traps[0]["ifindex"] == 1
    bf_traps = [it["trap"] for it in by_id["bf-1"]["items"]
                if it["lane"] == "trap"]
    assert bf_traps.count("bgpBackwardTransition") == 2
    assert bf_traps.count("bgpEstablished") == 2
    peer = next(it for it in by_id["bf-1"]["items"] if it["lane"] == "trap")
    assert peer["peer_ip"] == "203.0.113.1"


def test_without_with_trap_no_trap_items():
    sc = _example()
    plan = build_run_plan(sc, 600.0)
    for stx in plan["stories"]:
        assert not [it for it in stx["items"] if it["lane"] == "trap"]


def test_device_restart_plan_shape():
    sc = _example()
    sc["stories"].append({
        "id": "restart-1", "template": "device_restart",
        "trigger": {"at": "+30s"},
        "affected": {"devices": ["core-a1"], "tenants": ["acme"]},
        "params": {"reboot_s": 40},
        "expect": {"rca": {"affected_includes": ["core-a1"]}},
    })
    plan = build_run_plan(sc, 120.0)
    stx = next(s for s in plan["stories"] if s["id"] == "restart-1")
    traps = [it for it in stx["items"] if it["lane"] == "trap"]
    assert traps[0]["trap"] == "coldStart" and traps[0]["t"] == 30.0
    linkups = [t for t in traps if t["trap"] == "linkUp"]
    assert len(linkups) == 3          # one per core-a1 interface
    assert all(t["t"] >= 30.0 + 40 for t in linkups)
    up_logs = [it for it in stx["items"] if it["lane"] == "syslog"]
    assert all("changed state to up" in it["message"] for it in up_logs)


def test_traffic_drop_suppresses_baseline_and_emits_residual():
    sc = _example()
    sc["stories"].append({
        "id": "drop-1", "template": "traffic_drop",
        "trigger": {"at": "+20s"},
        "affected": {"devices": ["edge-a1"], "tenants": ["acme"]},
        "params": {"drop_pct": 80, "duration_s": 30, "probe_loss_pct": 40},
        "expect": {"forbid": {"cross_tenant_merge": True}},
    })
    plan = build_run_plan(sc, 60.0)
    # baseline flow items for edge-a1 inside [20, 50) are suppressed
    for it in plan["baseline"]:
        if it["lane"] == "flows" and it["device"] == "edge-a1":
            assert not (20.0 <= it["t"] < 50.0), it
    # other devices keep their baseline inside the window
    assert any(it for it in plan["baseline"]
               if it["lane"] == "flows" and it["device"] == "br-b1"
               and 20.0 <= it["t"] < 50.0)
    stx = next(s for s in plan["stories"] if s["id"] == "drop-1")
    story_flows = [it for it in stx["items"] if it["lane"] == "flows"]
    assert story_flows and all(it["count"] == 1 for it in story_flows)  # 20% of 5
    assert [it for it in stx["items"] if it["lane"] == "probes"]


def test_traffic_drop_full_stop_emits_no_flows():
    sc = _example()
    sc["stories"].append({
        "id": "drop-2", "template": "traffic_drop",
        "trigger": {"at": "+5s"},
        "affected": {"devices": ["edge-a2"], "tenants": ["acme"]},
        "params": {"drop_pct": 100, "duration_s": 10},
        "expect": {"forbid": {}},
    })
    plan = build_run_plan(sc, 30.0)
    stx = next(s for s in plan["stories"] if s["id"] == "drop-2")
    assert not [it for it in stx["items"] if it["lane"] == "flows"]
    for it in plan["baseline"]:
        if it["lane"] == "flows" and it["device"] == "edge-a2":
            assert not (5.0 <= it["t"] < 15.0)


def test_ground_truth_record_shape_is_unchanged(tmp_path):
    """The fidelity wave must not change ground-truth record shape: the
    stories carry the same {id, template, t0, affected, expect} envelope."""
    sc = _example()
    plan = build_run_plan(sc, 600.0)
    for stx in plan["stories"]:
        assert set(stx) == {"id", "template", "t0", "items", "affected",
                            "expect"}


def test_scenario_deepcopy_safety():
    # build_run_plan must not mutate the scenario (twin.py reuses it)
    sc = _example()
    before = copy.deepcopy(sc)
    build_run_plan(sc, 60.0)
    assert sc == before


# ── link_down_cascade multi-port fault (giant-object scenario) ───────────────

GIANT = os.path.join(REPO_ROOT, "docs", "design", "examples",
                     "twin-scenario-giant-object.yaml")


def test_link_down_cascade_without_interfaces_param_is_unchanged():
    """BACK-COMPAT: absent `interfaces`, the plan must be byte-identical to the
    pre-existing single-port expansion (interfaces[0] only)."""
    sc = _example()
    plan = build_run_plan(sc, 600.0)
    sc2 = _example()
    sc2["stories"][0]["params"].pop("interfaces", None)
    assert json.dumps(plan, sort_keys=True, default=str) == json.dumps(
        build_run_plan(sc2, 600.0), sort_keys=True, default=str)


def test_interfaces_param_faults_every_named_port_on_every_device():
    sc = _example()
    sc["stories"] = [{
        "id": "fold-1", "template": "link_down_cascade",
        "trigger": {"at": "+60s"},
        "affected": {"devices": ["edge-a1", "core-a1"], "tenants": ["acme"]},
        "params": {"interfaces": ["Ethernet1", "Ethernet2"],
                   "probe_loss_pct": 90},
        "expect": {"forbid": {"cross_tenant_merge": True}},
    }]
    validate_scenario(sc, name="fold")
    items = build_run_plan(sc, 600.0)["stories"][0]["items"]
    syslog = [i for i in items if i["lane"] == "syslog"]
    # per device per port: LINK-3-UPDOWN + LINEPROTO-5-UPDOWN. edge-a1 also has
    # 2 bgp_neighbors and core-a1 has 2 -> 4 BGP lines, once per device (the
    # sessions ride the device, not a single port).
    link = [i for i in syslog if i["appname"] == "LINK-3-UPDOWN"]
    proto = [i for i in syslog if i["appname"] == "LINEPROTO-5-UPDOWN"]
    bgp = [i for i in syslog if i["appname"] == "BGP-5-ADJCHANGE"]
    assert len(link) == 4      # 2 devices x 2 ports
    assert len(proto) == 4
    assert len(bgp) == 4
    for port in ("Ethernet1", "Ethernet2"):
        for dev in ("edge-a1", "core-a1"):
            assert any(i["device"] == dev and port in i["message"]
                       for i in link)
    # one probe per device regardless of port count
    assert len([i for i in items if i["lane"] == "probes"]) == 2


def test_giant_object_plan_yields_the_intended_graph_arithmetic():
    """The scenario's whole purpose is a specific object SIZE. Pin the event
    arithmetic that produces it, so a regression in the expander cannot quietly
    shrink the object the live proof depends on.

    nodes = H hosts x I ports (LINK and LINEPROTO both classify to
    kind='link_state_change' on '<device>:<port>', so a (device, port) pair is
    one node); edges = I*C(H,2) + H*C(I,2).
    """
    sc = load_scenario(GIANT)
    plan = build_run_plan(sc, 700.0)
    folds = [s for s in plan["stories"] if s["id"].startswith("fold-")]
    assert len(folds) == 3, "three firings drive re-serialization past damping"

    hosts = {d["name"] for d in sc["devices"] if d["tenant"] == "bigfold"}
    ports = [i["name"] for i in next(d for d in sc["devices"]
                                     if d["name"] in hosts)["interfaces"]]
    h, i = len(hosts), len(ports)
    assert (h, i) == (130, 6)

    for stx in folds:
        syslog = [x for x in stx["items"] if x["lane"] == "syslog"]
        probes = [x for x in stx["items"] if x["lane"] == "probes"]
        # 2 lines per (host, port); no bgp_neighbors on the folding switches
        assert len(syslog) == h * i * 2
        assert len(probes) == h
        # every (host, port) pair actually faulted — the node set of the object
        faulted = {(x["device"], p) for x in syslog for p in ports
                   if p in x["message"]}
        assert len(faulted) == h * i

    nodes = h * i
    edges = i * (h * (h - 1) // 2) + h * (i * (i - 1) // 2)
    assert (nodes, edges) == (780, 52260)
    # elements = nodes + edges must dominate CORR_OFFLOAD_MIN_ELEMENTS (2000),
    # or the object would take the inline path and prove nothing.
    assert nodes + edges > 25 * 2000
