"""Scenario DSL validation: the shipped example must load; a curated set of
broken scenarios must each fail with an ACTIONABLE error naming the problem."""
import copy
import os

import pytest
from conftest import REPO_ROOT
from scenario import (
    ScenarioError,
    check_budget,
    load_scenario,
    steady_eps,
    validate_scenario,
)

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")


@pytest.fixture()
def example() -> dict:
    return load_scenario(EXAMPLE)


def test_shipped_example_loads_and_validates(example):
    assert example["meta"]["name"] == "acme-dx-demo"
    assert {t["alias"] for t in example["tenants"]} == {"acme", "bluesky",
                                                        "coyote"}
    assert len(example["devices"]) == 11
    assert {s["id"] for s in example["stories"]} == {"dx-flap-1", "no-merge-1"}


def test_shipped_example_fits_t1_budget(example):
    line = check_budget(example)
    # 11 devices × 0.2 syslog eps + 2 probes + 6 edge devices × 5 flow fps
    # (the fidelity wave counts flow records against the ingest budget too)
    assert 30 < steady_eps(example) < 40
    assert "budget" in line


def _mutate(example: dict, fn) -> dict:
    sc = copy.deepcopy(example)
    fn(sc)
    return sc


@pytest.mark.parametrize("mutation,fragment", [
    (lambda sc: sc.update(surprise=1), "unknown top-level key"),
    (lambda sc: sc.update(twin=2), "'twin' must be the integer 1"),
    (lambda sc: sc["meta"].pop("seed"), "missing required key 'seed'"),
    (lambda sc: sc["meta"].update(seed="42"), "seed must be an integer"),
    (lambda sc: sc["devices"][0].update(tenant="ghost"),
     "unknown tenant 'ghost'"),
    (lambda sc: sc["devices"][0].update(role="firewall"), "role"),
    (lambda sc: sc["devices"].append(dict(sc["devices"][0])),
     "duplicate device name"),
    (lambda sc: sc["seams"][0].update(seam_type="MPLS"),
     "the five FINAL types"),
    (lambda sc: sc["stories"][0].update(template="alien_invasion"),
     "template 'alien_invasion' unknown"),
    (lambda sc: sc["stories"][0]["params"].update(warp_factor=9),
     "unknown param(s) ['warp_factor']"),
    # fidelity wave: the new baseline.flows block is schema-checked too
    (lambda sc: sc["baseline"]["flows"].update(protocol="sflow"),
     "protocol 'sflow' invalid"),
    (lambda sc: sc["baseline"]["flows"].update(per_edge_device_fps=-1),
     "non-negative number"),
    (lambda sc: sc["baseline"]["flows"].update(burst=2),
     "unknown flows key(s)"),
    (lambda sc: sc["stories"][1]["params"].update(with_trap=True),
     "unknown param(s) ['with_trap']"),  # only link/bgp templates take it
    (lambda sc: sc["stories"][0]["affected"]["devices"].append("phantom"),
     "unknown device 'phantom'"),
    (lambda sc: sc["stories"][0]["expect"]["rca"].update(
        verdict_tier_at_least="certain"), "verdict_tier_at_least"),
    (lambda sc: sc["stories"][0]["expect"].update(bonus={}),
     "unknown expect key(s)"),
    (lambda sc: sc["stories"][0]["trigger"].update(at="300s"),
     "trigger offset"),
    (lambda sc: sc["stories"][0]["expect"]["seam"].update(seam_id="nope"),
     "not a declared seam"),
    (lambda sc: sc["links"][0].update(a="edge-a1:Ethernet99"),
     "no interface 'Ethernet99'"),
])
def test_broken_scenarios_fail_actionably(example, mutation, fragment):
    sc = _mutate(example, mutation)
    with pytest.raises(ScenarioError) as exc:
        validate_scenario(sc, name="broken")
    assert fragment in str(exc.value), str(exc.value)


def test_seam_type_contradiction_between_expect_and_declaration(example):
    sc = copy.deepcopy(example)
    sc["stories"][0]["expect"]["seam"]["seam_type"] = "VPN"  # declared DX
    with pytest.raises(ScenarioError) as exc:
        validate_scenario(sc, name="broken")
    assert "contradicts the declared type" in str(exc.value)


def test_device_restart_now_validates(example):
    """Fidelity wave: the trap lane exists, so §5.7 device_restart is a legal
    template (it was refused in T1 core)."""
    sc = copy.deepcopy(example)
    sc["stories"].append({
        "id": "restart-1", "template": "device_restart",
        "trigger": {"at": "+60s"},
        "affected": {"devices": ["core-a1"], "tenants": ["acme"]},
        "params": {"reboot_s": 45},
        "expect": {"rca": {"affected_includes": ["core-a1"]},
                   "forbid": {"cross_tenant_merge": True}},
    })
    validate_scenario(sc, name="restart")


def test_traffic_drop_validates_and_refuses_bad_params(example):
    sc = copy.deepcopy(example)
    sc["stories"].append({
        "id": "drop-1", "template": "traffic_drop",
        "trigger": {"at": "+90s"},
        "affected": {"devices": ["edge-a1"], "tenants": ["acme"]},
        "params": {"drop_pct": 95, "duration_s": 60, "probe_loss_pct": 40},
        "expect": {"forbid": {"cross_tenant_merge": True}},
    })
    validate_scenario(sc, name="drop")
    sc["stories"][-1]["params"]["ramp"] = 1
    with pytest.raises(ScenarioError) as exc:
        validate_scenario(sc, name="drop")
    assert "unknown param(s) ['ramp']" in str(exc.value)


def test_budget_refusal_is_actionable(example):
    sc = copy.deepcopy(example)
    sc["baseline"]["syslog"]["per_device_eps"] = 100.0  # 1100 EPS steady
    with pytest.raises(ScenarioError) as exc:
        check_budget(sc)
    assert "over budget" in str(exc.value)
    # forced runs are allowed but still reported
    assert "budget" in check_budget(sc, force=True)
