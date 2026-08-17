"""Ground-truth determinism: (scenario, seed) fully determines every event's
content and relative timing (design §3.3). Two plan builds must be
byte-identical; a different seed must produce a different plan; wall-clock
enters only at emission time (build_payload), never in the plan."""
import copy
import json
import os

from conftest import REPO_ROOT
from emitters import build_payload
from scenario import load_scenario
from stories import build_run_plan, plan_end_s

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")


def test_fixed_seed_means_identical_plan():
    sc = load_scenario(EXAMPLE)
    a = build_run_plan(sc, 600.0)
    b = build_run_plan(copy.deepcopy(sc), 600.0)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_different_seed_means_different_schedule():
    sc1 = load_scenario(EXAMPLE)
    sc2 = load_scenario(EXAMPLE)
    sc2["meta"]["seed"] = sc1["meta"]["seed"] + 1
    a = build_run_plan(sc1, 600.0)
    b = build_run_plan(sc2, 600.0)
    # story CONTENT is seed-independent here, but baseline phases/severities
    # are seeded — the overall plan must differ.
    assert (json.dumps(a["baseline"], sort_keys=True)
            != json.dumps(b["baseline"], sort_keys=True))


def test_stories_fire_at_declared_offsets_and_extend_the_plan():
    sc = load_scenario(EXAMPLE)
    plan = build_run_plan(sc, 600.0)
    by_id = {s["id"]: s for s in plan["stories"]}
    assert by_id["dx-flap-1"]["t0"] == 300.0
    assert by_id["no-merge-1"]["t0"] == 330.0
    # dx story: 2 flaps × 45 s hold + probe tail
    assert plan_end_s(plan) >= 300.0 + 2 * 45.0
    # every story item carries its story_id and a resolvable device
    for stx in plan["stories"]:
        for it in stx["items"]:
            assert it["story_id"] == stx["id"]
            assert it["lane"] in ("syslog", "probes", "cloud", "metrics")


def test_dx_story_emits_the_proven_shapes():
    sc = load_scenario(EXAMPLE)
    plan = build_run_plan(sc, 600.0)
    dx = next(s for s in plan["stories"] if s["id"] == "dx-flap-1")
    lanes = {it["lane"] for it in dx["items"]}
    assert lanes == {"syslog", "cloud", "probes"}
    bgp_downs = [it for it in dx["items"] if it["lane"] == "syslog"
                 and "Down" in it["message"]]
    assert len(bgp_downs) == 2  # flap_count=2, final_state=down
    assert all("169.254.100.2" in it["message"] for it in bgp_downs)
    cloud_kinds = [it["kind"] for it in dx["items"] if it["lane"] == "cloud"]
    assert "cloud_bgp_session_down" in cloud_kinds
    assert "cloud_route_count_drop" in cloud_kinds


def test_negative_control_uses_the_proven_cusum_shape():
    sc = load_scenario(EXAMPLE)
    plan = build_run_plan(sc, 600.0)
    neg = next(s for s in plan["stories"] if s["id"] == "no-merge-1")
    metrics = [it for it in neg["items"] if it["lane"] == "metrics"]
    assert len(metrics) == 36  # 26 baseline + 10 peak (correlation_e2e)
    assert sum(1 for it in metrics if it["value"] >= 90) == 10


def test_wire_payloads_apply_prefix_and_explicit_cloud_tenant():
    sc = load_scenario(EXAMPLE)
    plan = build_run_plan(sc, 600.0)
    dx = next(s for s in plan["stories"] if s["id"] == "dx-flap-1")
    tenant_ids = {"acme": "t_A", "bluesky": "t_B", "coyote": "t_C"}
    cloud_item = next(it for it in dx["items"] if it["lane"] == "cloud")
    payload = json.loads(build_payload(cloud_item, "twx-test-", tenant_ids))
    assert payload["tenant_id"] == "t_A"           # explicit — engine drops
    assert payload["resource_id"].startswith("twx-test-")  # untenanted cloud
    syslog_item = next(it for it in dx["items"] if it["lane"] == "syslog")
    payload = json.loads(build_payload(syslog_item, "twx-test-", tenant_ids))
    assert payload["hostname"].startswith("twx-test-edge-a1")
