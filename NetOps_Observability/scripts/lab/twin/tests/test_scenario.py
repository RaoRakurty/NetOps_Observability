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


# ── link_down_cascade `interfaces`: the multi-port fault that folds a whole
# access layer into ONE giant correlation object (giant-object scenario) ──────

GIANT = os.path.join(REPO_ROOT, "docs", "design", "examples",
                     "twin-scenario-giant-object.yaml")


@pytest.fixture()
def giant() -> dict:
    return load_scenario(GIANT)


def test_giant_object_scenario_loads_and_fits_budget(giant):
    assert giant["meta"]["name"] == "giant-object-offload"
    # 130 folding switches + 3 control tenants x 2 devices
    assert len(giant["devices"]) == 136
    folding = [d for d in giant["devices"] if d["tenant"] == "bigfold"]
    assert len(folding) == 130
    # Identical port naming across every switch is what makes the shared-token
    # clique quadratic — if this drifts the object stops being giant.
    ports = {tuple(i["name"] for i in d["interfaces"]) for d in folding}
    assert len(ports) == 1
    assert len(ports.pop()) == 6
    assert steady_eps(giant) < 20
    assert "budget" in check_budget(giant)


def _fold_story(devices: list[str], ifaces) -> dict:
    return {
        "id": "fold-1", "template": "link_down_cascade",
        "trigger": {"at": "+60s"},
        "affected": {"devices": devices, "tenants": ["acme"]},
        "params": {"interfaces": ifaces},
        "expect": {"forbid": {"cross_tenant_merge": True}},
    }


def test_interfaces_param_accepts_declared_ports(example):
    sc = copy.deepcopy(example)
    sc["stories"][0] = _fold_story(["edge-a1"], ["Ethernet1", "Ethernet2"])
    validate_scenario(sc, name="fold")


@pytest.mark.parametrize("ifaces,fragment", [
    ([], "at least one interface name"),
    (["Ethernet1", "Ethernet1"], "duplicate interface name"),
    (["Ethernet1", "Ethernet99"], "has no interface(s) ['Ethernet99']"),
    (["Ethernet1", ""], "must be a non-empty string"),
    ("Ethernet1", "params.interfaces must be list"),
])
def test_interfaces_param_refuses_bad_values(example, ifaces, fragment):
    sc = copy.deepcopy(example)
    sc["stories"][0] = _fold_story(["edge-a1"], ifaces)
    with pytest.raises(ScenarioError) as exc:
        validate_scenario(sc, name="fold")
    assert fragment in str(exc.value)


def test_interfaces_param_checks_every_affected_device(example):
    """A port present on the first device but not the second must still be
    refused — otherwise the plan silently under-emits and the object never
    reaches the size the scenario was written to produce."""
    sc = copy.deepcopy(example)
    # edge-a1 declares Management0; edge-a2 does not.
    sc["stories"][0] = _fold_story(["edge-a1", "edge-a2"],
                                   ["Ethernet1", "Management0"])
    with pytest.raises(ScenarioError) as exc:
        validate_scenario(sc, name="fold")
    assert "'edge-a2'" in str(exc.value)
    assert "Management0" in str(exc.value)
