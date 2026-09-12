# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The `enterprise_outage` story template (§5.12) — one causally ordered chain.

WHAT THIS TEMPLATE IS FOR. The owner asked for traffic that simulates a real
enterprise network outage as ONE causal chain rather than a bag of independent
faults: a site's core uplink fails, the IGP loses its adjacency, a second core
port starts flapping, the eBGP session to transit flaps, the routing table
churns, the access layer reconverges (STP) and re-homes hosts (MAC moves), and
then — for most sites — it all comes back.

WHERE IT LIVES. The chain's WIRE VOCABULARY and PHASE TIMELINE are in
`scripts/enterprise_outage_chain.py`, shared with `scripts/scale-miniladder.py`
so the accuracy harness (this one, small topology, scored against
`corr_objects`) and the scale harness (2,500 devices, TTUR/completion) run the
SAME story instead of two copies that drift. These tests therefore pin the
shared definition and this template's use of it.

What they hold:
  * the template is DSL-selectable and its params are validated (a core/dist
    device outside the blast radius, or the two being the same device, is a
    hard parse error — ground truth must never contradict its own events);
  * every phase fires, in causal order, for every seed the ±20 % jitter can
    produce;
  * every emitted line classifies through the REAL correlation producer to
    exactly what `parser_coverage` claims — including the lines it PROVABLY
    drops, which the chain emits on purpose rather than substituting a message
    that happens to classify;
  * the plan is a pure function of (scenario, seed) — the §3.3 rule;
  * `with_trap` adds the §4.0 trap rows for the same two faults (corroboration
    across MODALITIES), and `recover: false` really produces a hard outage;
  * the story publishes `labels` — cause entity, per-phase timeline, coverage
    table — into the run's ground-truth record.

Run:  cd scripts/lab/twin && python3 -m pytest tests/test_enterprise_outage.py -q
"""
from __future__ import annotations

import copy
import json
import os
import sys
from datetime import datetime, timezone

import pytest
from conftest import REPO_ROOT
from scenario import ScenarioError, load_scenario, validate_scenario
from stories import build_run_plan

sys.path.insert(0, os.path.join(REPO_ROOT, "src", "correlation"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import enterprise_outage_chain as chain  # sys.path set just above
import producers  # sys.path set just above

EXAMPLE = os.path.join(REPO_ROOT, "docs", "design", "examples",
                       "twin-scenario-example.yaml")

SITE = ["edge-a1", "core-a1", "edge-a2", "spine-a1"]
PHASES = ("uplink_down", "ospf_neighbor_down", "ospf_interface_flap",
          "bgp_session_flap", "route_churn", "access_layer")


def _story(**params) -> dict:
    p = {"core_device": "edge-a1", "dist_device": "core-a1",
         "flap_cycles": 3, "churn_eps": 8.0, "churn_duration_s": 20.0,
         "stp_share": 0.5, "mac_share": 0.5}
    p.update(params)
    return {
        "id": "ent-1", "template": "enterprise_outage",
        "trigger": {"at": "+30s"},
        "affected": {"devices": list(SITE), "tenants": ["acme"]},
        "params": p,
        "expect": {"rca": {"verdict_tier_at_least": "suspected",
                           "affected_includes": ["edge-a1"]},
                   "forbid": {"cross_tenant_merge": True}},
    }


def _scenario_with(story: dict | None = None) -> dict:
    sc = load_scenario(EXAMPLE)
    sc["stories"].append(story if story is not None else _story())
    return validate_scenario(sc, name="enterprise")


def _plan(story: dict | None = None, duration: float = 600.0) -> dict:
    plan = build_run_plan(_scenario_with(story), duration)
    return next(s for s in plan["stories"] if s["id"] == "ent-1")


@pytest.fixture(scope="module")
def stx() -> dict:
    return _plan()


# ── the DSL surface ─────────────────────────────────────────────────────────

def test_the_template_is_dsl_selectable():
    from scenario import STORY_TEMPLATES
    spec = STORY_TEMPLATES["enterprise_outage"]
    assert spec["lanes"] == {"syslog", "probes"}
    for key in ("core_device", "dist_device", "flap_cycles", "churn_eps",
                "churn_duration_s", "stp_share", "mac_share", "with_trap",
                "recover", "recovery_after_s"):
        assert key in spec["params"], key


def test_a_role_device_outside_the_blast_radius_is_refused():
    """Ground truth names the cause device and the blast radius. A cause that
    sits outside its own blast radius is a contradiction, so it is a parse
    error, not something to discover in the accuracy report."""
    with pytest.raises(ScenarioError, match="affected.devices"):
        _scenario_with(_story(core_device="br-b1"))


def test_one_device_playing_both_roles_is_refused():
    with pytest.raises(ScenarioError, match="second vantage"):
        _scenario_with(_story(core_device="edge-a1", dist_device="edge-a1"))


def test_a_site_of_one_device_is_refused():
    st = _story()
    st["affected"]["devices"] = ["edge-a1"]
    st["params"].pop("dist_device")
    st["params"].pop("core_device")
    with pytest.raises(ScenarioError, match="at least 2 affected devices"):
        _scenario_with(st)


def test_an_out_of_range_share_is_refused():
    with pytest.raises(ScenarioError, match="stp_share"):
        _scenario_with(_story(stp_share=1.7))


def test_an_unknown_param_is_still_a_hard_error():
    with pytest.raises(ScenarioError, match="unknown param"):
        _scenario_with(_story(meteor_strike=True))


# ── determinism (design §3.3) ───────────────────────────────────────────────

def test_two_builds_of_one_scenario_are_byte_identical():
    """(scenario, seed) fully determines content AND relative timing. `_jit`
    must draw from the story's own Random, never the global stream."""
    a, b = _plan(), _plan()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_the_plan_does_not_depend_on_the_process_hash_seed():
    """The MAC addresses key off a checksum of the story id, not `hash()`,
    which is PYTHONHASHSEED-salted and would break §3.3 across processes."""
    import ast
    import inspect

    import stories as stories_mod
    tree = ast.parse(ast.unparse(ast.parse(
        inspect.getsource(stories_mod._tpl_enterprise_outage))))
    calls = [n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert "hash" not in calls, (
        "the template calls hash() — salted per process, so two runs of one "
        "seed would plan different MAC addresses (design §3.3)")


def test_a_different_seed_plans_a_different_chain():
    sc = _scenario_with()
    sc["meta"]["seed"] = int(sc["meta"]["seed"]) + 1
    other = next(s for s in build_run_plan(sc, 600.0)["stories"]
                 if s["id"] == "ent-1")
    assert json.dumps(other["items"], sort_keys=True) != json.dumps(
        _plan()["items"], sort_keys=True)


# ── the chain itself ────────────────────────────────────────────────────────

def test_every_phase_fires_in_causal_order(stx):
    tl = {ph["phase"]: ph for ph in stx["labels"]["timeline"]}
    assert set(PHASES) <= set(tl), sorted(set(PHASES) - set(tl))
    offs = [tl[p]["offset_s"] for p in PHASES]
    assert offs == sorted(offs), list(zip(PHASES, offs))
    assert tl["uplink_down"]["offset_s"] == 0.0


@pytest.mark.parametrize("seed", [1, 7, 20260829, 999983])
def test_causal_order_survives_every_jitter_draw(seed):
    """Offsets are jittered ±20 %, so ordering must come from the monotonic
    clamps, never from the draw happening to land the right way round."""
    sc = _scenario_with()
    sc["meta"]["seed"] = seed
    stx = next(s for s in build_run_plan(sc, 900.0)["stories"]
               if s["id"] == "ent-1")
    tl = {ph["phase"]: ph for ph in stx["labels"]["timeline"]}
    offs = [tl[p]["offset_s"] for p in PHASES]
    assert offs == sorted(offs), f"seed {seed}: {list(zip(PHASES, offs))}"


def test_the_cause_is_the_core_uplink_and_it_goes_first(stx):
    lab = stx["labels"]
    ce = lab["cause_entity"]
    assert ce["device"] == "edge-a1"
    assert ce["entity_id"] == f"edge-a1:{ce['interface']}"
    syslog = [i for i in stx["items"] if i["lane"] == "syslog"]
    first = min(syslog, key=lambda i: i["t"])
    assert first["appname"] == "LINK-3-UPDOWN"
    assert first["device"] == "edge-a1"
    assert ce["interface"] in first["message"]
    assert "changed state to down" in first["message"]
    assert lab["vantages"] == ["core-a1", "edge-a1"], (
        "the two devices that observed the CAUSE; the access layer observed "
        "consequences, which is a blast radius, not a vantage")


def test_the_flap_really_cycles_and_is_seen_from_both_ends(stx):
    tl = {ph["phase"]: ph for ph in stx["labels"]["timeline"]}
    cycles = tl["ospf_interface_flap"]["cycles"]
    assert len(cycles) == 3
    for cyc in cycles:
        assert cyc["up_at"] > cyc["down_at"]
    assert [c["down_at"] for c in cycles] == sorted(
        c["down_at"] for c in cycles)
    ospf = [i for i in stx["items"]
            if i["lane"] == "syslog" and i["appname"] == "OSPF-5-ADJCHG"]
    # both ends of the core↔distribution adjacency log every transition
    assert {i["device"] for i in ospf} == {"edge-a1", "core-a1"}
    downs = [i for i in ospf if "to DOWN" in i["message"]]
    ups = [i for i in ospf if "to FULL" in i["message"]]
    assert len(downs) >= 4 and len(ups) >= 3


def test_the_transit_session_flaps_down_up_down(stx):
    tl = {ph["phase"]: ph for ph in stx["labels"]["timeline"]}
    trans = tl["bgp_session_flap"]["transitions"]
    assert [t["state"] for t in trans] == ["down", "up", "down"]
    assert [t["at"] for t in trans] == sorted(t["at"] for t in trans)


def test_the_access_layer_reconverges_and_re_homes(stx):
    apps = [i["appname"] for i in stx["items"] if i["lane"] == "syslog"]
    assert apps.count("SPANTREE-5-TOPOTRAP") == 2, (
        "a TCN floods the WHOLE STP domain — every access switch logs it")
    assert "SPANTREE-6-PORT_STATE" in apps
    assert "SW_MATM-4-MACFLAP_NOTIF" in apps


def test_recovery_follows_every_fault(stx):
    lab = stx["labels"]
    rec = lab["recovery_offset_s"]
    assert rec is not None and lab["hard_outage"] is False
    ups = [i for i in stx["items"]
           if i["lane"] == "syslog" and "changed state to up" in i["message"]
           and lab["cause_entity"]["interface"] in i["message"]]
    assert ups, "the cause interface never came back up"
    assert max(i["t"] for i in ups) >= rec + stx["t0"]
    # …and nothing that is still a FAULT happens after the recovery
    faults = [i for i in stx["items"]
              if i["lane"] == "syslog" and "state to down" in i["message"]]
    assert max(i["t"] for i in faults) < rec + stx["t0"]


def test_a_hard_outage_never_recovers():
    stx = _plan(_story(recover=False))
    lab = stx["labels"]
    assert lab["recovery_offset_s"] is None and lab["hard_outage"] is True
    ups = [i for i in stx["items"]
           if i["lane"] == "syslog"
           and lab["cause_entity"]["interface"] in i["message"]
           and "changed state to up" in i["message"]]
    assert not ups, "a hard outage brought its uplink back"


def test_with_trap_corroborates_the_same_faults_across_modalities():
    """The trap lane is a SECOND modality reporting the SAME two faults — the
    corroboration structure the owner memo asks for, in lanes the emitters
    already implement."""
    plain = _plan(_story())
    with_trap = _plan(_story(with_trap=True))
    assert not [i for i in plain["items"] if i["lane"] == "trap"]
    traps = [i["trap"] for i in with_trap["items"] if i["lane"] == "trap"]
    assert traps.count("linkDown") == 1 and traps.count("linkUp") == 1
    assert traps.count("bgpBackwardTransition") == 2
    assert traps.count("bgpEstablished") == 2
    link = next(i for i in with_trap["items"]
                if i["lane"] == "trap" and i["trap"] == "linkDown")
    assert link["ifname"] == with_trap["labels"]["cause_entity"]["interface"]
    bgp = next(i for i in with_trap["items"]
               if i["lane"] == "trap" and i["trap"] == "bgpBackwardTransition")
    assert bgp["peer_ip"] == with_trap["labels"]["cause_entity"]["peer"]


def test_the_customer_path_is_lossy_for_the_whole_outage(stx):
    probes = [i for i in stx["items"] if i["lane"] == "probes"]
    assert probes and all(p["loss_pct"] > 0 for p in probes)
    assert max(p["t"] for p in probes) > stx["labels"]["recovery_offset_s"]


# ── the lines are what the coverage table says they are ─────────────────────

def _classify(item: dict):
    now = datetime.now(timezone.utc)
    return producers.syslog_control_signal({
        "hostname": item["device"], "appname": item["appname"],
        "message": item["message"], "severity": item["severity"],
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }, "t1", now)


def _check_coverage(rows) -> None:
    """Assert a coverage table against the REAL producer. Shared with the
    mutant test below, which runs the identical check on a corrupted table."""
    for row in rows:
        if row.exemplar is None:
            assert row.components, f"{row.event_type}: composite with no parts"
            continue
        sig = _classify({"device": "cov-dev-1", "appname": row.exemplar[0],
                         "message": row.exemplar[1],
                         "severity": row.exemplar[2]})
        if row.coverage == chain.NOT_PROMOTED:
            assert sig is None, (
                f"{row.event_type}: declared not_promoted but the classifier "
                f"yields {sig.kind!r}")
            continue
        assert sig is not None, (
            f"{row.event_type}: declared promoted but the classifier drops "
            f"{row.exemplar[1]!r}")
        assert sig.kind == row.kind
        assert (sig.attrs.get("state") or "") == row.state
        ifname = (chain.SAMPLE_IF if chain.SAMPLE_IF in row.exemplar[1]
                  else chain.SAMPLE_IF_B)
        assert sig.entity_id == chain.entity_of(row.event_type, "cov-dev-1",
                                                ifname)


def test_the_coverage_table_is_pinned_against_the_real_parser():
    _check_coverage(chain.CHAIN_SIGNATURES)
    # EMPTY since tracker 184 promoted BGP route/update churn: every symptom
    # this chain emits is now visible to the classifier. Pinned as a set, so a
    # symptom going dark is as loud as one lighting up.
    assert set(chain.not_promoted_types()) == set(), (
        "the not-promoted list changed — an engine improvement worth "
        "recording, or a regression; either way not silent")


def test_a_mutant_message_for_a_promoted_type_is_caught():
    """Proof the check has teeth: an unrecognized mnemonic on a PROMOTED row
    must turn the very same checker red."""
    mutated, done = [], False
    for row in chain.CHAIN_SIGNATURES:
        if (not done and row.coverage == chain.PROMOTED
                and row.exemplar is not None):
            done = True
            mutated.append(row._replace(exemplar=(
                "WIDGET-6-NOTHING", "%WIDGET-6-NOTHING: nothing here", "info")))
            continue
        mutated.append(row)
    assert done
    with pytest.raises(AssertionError, match="declared promoted"):
        _check_coverage(mutated)


def test_every_emitted_line_matches_the_coverage_table(stx):
    """Against the REAL classifier, not a copy: each of the story's syslog
    lines must promote exactly as the table says — and the ones the table calls
    invisible must really produce nothing."""
    by_app: dict[str, str] = {}
    for row in chain.CHAIN_SIGNATURES:
        if row.exemplar is not None:
            by_app.setdefault(row.exemplar[0], row.coverage)
    seen_unpromoted = 0
    for it in stx["items"]:
        if it["lane"] != "syslog":
            continue
        assert it["appname"] in by_app, (
            f"{it['appname']} is not in the shared chain vocabulary — the two "
            f"harnesses have started to drift")
        sig = _classify(it)
        if by_app[it["appname"]] == chain.NOT_PROMOTED:
            assert sig is None, (
                f"{it['appname']} is declared invisible but classified as "
                f"{sig.kind!r}")
            seen_unpromoted += 1
        else:
            assert sig is not None, f"line never promotes: {it['message']!r}"
    # Tracker 184 promoted the last invisible symptom (BGP route/update
    # churn), so a story now emits ZERO unpromotable lines. Asserted as an
    # EQUALITY against the chain's own table rather than a ">0" that would
    # pass whatever the harness happened to emit: the story must still carry
    # the route-churn LINES (checked below), they are simply visible now.
    assert seen_unpromoted == 0 and not chain.not_promoted_types(), (
        f"{seen_unpromoted} invisible lines, but the chain declares "
        f"{chain.not_promoted_types()} — table and story have drifted")
    churn_apps = {chain.CHAIN_BY_TYPE[t].exemplar[0]
                  for t in ("bgp_route_churn", "bgp_router_update_burst")}
    assert churn_apps & {it["appname"] for it in stx["items"]
                         if it["lane"] == "syslog"}, (
        "the chain emitted no BGP route-churn lines — the route-churn phase "
        "is part of the story, not an optional extra")


def test_the_story_publishes_its_coverage_table_into_ground_truth(stx):
    lab = stx["labels"]
    assert lab["parser_coverage"] == chain.parser_coverage()
    assert lab["not_promoted"] == list(chain.not_promoted_types())
    assert lab["chain"] == "enterprise_outage"
    assert lab["source"] == "twin"


def test_ospf_peer_addresses_are_documentation_space(stx):
    """OSPF neighbour ids must be unmistakably synthetic and disjoint from both
    the twin's 198.19/16 aliases and the mini-ladder's 198.18.x.y, or an
    adjacency token could alias a real address."""
    ospf = [i for i in stx["items"]
            if i["lane"] == "syslog" and i["appname"] == "OSPF-5-ADJCHG"]
    assert ospf
    for it in ospf:
        peer = it["message"].split("Nbr ")[1].split(" ")[0]
        assert peer.startswith("192.0.2."), peer


# ── the rest of the twin is untouched ───────────────────────────────────────

def test_stories_without_labels_still_build_and_carry_an_empty_dict():
    """The `labels` return form is ADDITIVE: every pre-existing template keeps
    its plan and simply publishes no labels."""
    sc = load_scenario(EXAMPLE)
    plan = build_run_plan(sc, 600.0)
    assert plan["stories"]
    for s in plan["stories"]:
        assert s["labels"] == {}
        assert s["items"]


def test_the_example_scenarios_still_validate():
    for name in ("twin-scenario-example.yaml", "twin-scenario-fidelity.yaml",
                 "twin-scenario-giant-object.yaml"):
        path = os.path.join(REPO_ROOT, "docs", "design", "examples", name)
        validate_scenario(copy.deepcopy(load_scenario(path)), name=name)


# ══════════════════════════════════════════════════════════════════════════
# THE DECLARED STORM SHAPE (P3, 2026-08-29)
#
# `params.shape` is a `chain.StormShape` knob set — the SAME parameter object
# `scripts/scale-miniladder.py`'s storm profiles carry — so an accuracy run
# and a scale run can be given the identical repetition/dynamics instead of
# two hand-tuned approximations of "a repetitive storm". What these hold:
#   * declaring no shape leaves the template EXACTLY as it was (every existing
#     scenario file and golden fixture is unchanged);
#   * a declared shape round-trips: knobs in ⇒ the same knobs, and their
#     content digest, out in the story's ground-truth labels;
#   * the knobs a declared topology cannot express are REFUSED, not ignored;
#   * the plan stays a pure function of (scenario, seed) with a shape on it.
# ══════════════════════════════════════════════════════════════════════════

SHAPE_KNOBS = {"repeat_factor": 12.0, "repeat_window_s": 60.0,
               "flap_cycles": [2, 5], "churn_density": 20.0,
               "churn_duration_s": [30.0, 45.0], "churn_max_events": 400,
               "recovery_ratio": 1.0, "contradiction_ratio": 0.25}


def _shaped(**over) -> dict:
    knobs = dict(SHAPE_KNOBS)
    knobs.update(over)
    story = _story(shape=knobs)
    # the shape owns these phases now — drop the explicit pins so it can
    del story["params"]["flap_cycles"]
    del story["params"]["churn_eps"]
    del story["params"]["churn_duration_s"]
    return story


def test_shape_is_a_dsl_param_and_its_knobs_are_validated():
    from scenario import STORY_TEMPLATES
    assert "shape" in STORY_TEMPLATES["enterprise_outage"]["params"]
    for bad in ({"nope": 1},
                {"repeat_factor": "many"},
                {"recovery_ratio": 2.0},
                {"flap_cycles": [6, 2]},
                {"churn_duration_s": [90, 30]},
                {"repeat_distribution": "poisson"},
                # fleet-allocation knobs have nothing to act on in a declared
                # topology: refused, never silently ignored
                {"incident_density": 3.0},
                {"storm_share_of_raw": 0.5},
                {"device_budget": 0.9}):
        with pytest.raises(ScenarioError, match="params.shape"):
            _scenario_with(_story(shape=bad))


def test_no_shape_means_the_template_is_exactly_what_it_always_was(stx):
    """The default path must not move: every scenario file in the repo, and
    every golden fixture, was recorded without a shape."""
    assert stx["labels"]["shape"] is None
    assert stx["labels"]["shape_digest"] is None
    assert stx["labels"]["repeat_events"] == 0
    # The unshaped story still re-reports through its FLAP CYCLES (that is the
    # physics, not a repeat knob); what it has none of is the memo §18
    # "repeated confirmation" mass — and a shaped story has strictly more.
    plain = len([i for i in stx["items"] if i["lane"] == "syslog"])
    shaped = _plan(_shaped())
    assert len([i for i in shaped["items"] if i["lane"] == "syslog"]) > plain
    assert shaped["labels"]["repeat_events"] > 0


def test_a_declared_shape_round_trips_into_ground_truth():
    stx = _plan(_shaped())
    got = stx["labels"]["shape"]
    assert got is not None
    shape = chain.shape_from_params(SHAPE_KNOBS, chain.TOPOLOGY_SHAPE_KNOBS)
    assert got == shape.as_dict()
    assert stx["labels"]["shape_digest"] == shape.digest()
    assert len(stx["labels"]["shape_digest"]) == 64
    # the knobs the twin CAN express actually acted
    assert stx["labels"]["repeat_events"] > 0
    assert stx["labels"]["contradictions"]
    cycles = next(p for p in stx["labels"]["timeline"]
                  if p["phase"] == "ospf_interface_flap")["cycles"]
    assert 2 <= len(cycles) <= 5
    churn = next(p for p in stx["labels"]["timeline"]
                 if p["phase"] == "route_churn")
    assert churn["rate_eps"] >= chain.DEFAULT_SHAPE.churn_eps_range()[0]
    assert "truncated_by_throughput_budget" in churn


def test_a_declared_shape_really_makes_the_stream_repetitive():
    """The whole point: the same identity, re-reported inside the repeat
    window, is the mass an Aggregation Plane may collapse. Without a shape the
    twin's chain contains none of it."""
    plain = _plan(_story())
    shaped = _plan(_shaped(repeat_factor=20.0))
    obs_plain = _observations(plain)
    obs_shaped = _observations(shaped)
    m_plain = chain.measure_stream(obs_plain, 600.0)
    m_shaped = chain.measure_stream(obs_shaped, 600.0)
    assert m_plain["classes"]["repeat"] < m_shaped["classes"]["repeat"]
    assert m_plain["reduction_pct"]["K3"] < m_shaped["reduction_pct"]["K3"]
    assert m_shaped["classes"]["recovery"] > 0


def _observations(stx: dict) -> list:
    """The story's syslog lines as `chain.Observation`s, keyed exactly as the
    REAL producer keys them (the classifier runs — this is the accuracy
    harness, where the topology is small enough to parse for real)."""
    out = []
    for it in stx["items"]:
        if it["lane"] != "syslog":
            continue
        sig = _classify(it)
        out.append(chain.Observation(
            t=float(it["t"]), device=it["device"],
            entity_id="" if sig is None else sig.entity_id,
            kind="" if sig is None else sig.kind,
            severity=str(it.get("severity") or ""),
            state="" if sig is None else str(sig.attrs.get("state", "")),
            promoted=sig is not None))
    return out


def test_a_shaped_plan_is_still_a_pure_function_of_scenario_and_seed():
    a, b = _plan(_shaped()), _plan(_shaped())
    assert json.dumps(a["items"], sort_keys=True) == json.dumps(
        b["items"], sort_keys=True)
    assert a["labels"]["shape_digest"] == b["labels"]["shape_digest"]


def test_an_explicit_param_still_wins_over_the_shape():
    """A file must be able to pin one phase and shape the rest."""
    story = _shaped()
    story["params"]["flap_cycles"] = 2
    stx = _plan(story)
    cycles = next(p for p in stx["labels"]["timeline"]
                  if p["phase"] == "ospf_interface_flap")["cycles"]
    assert len(cycles) == 2


def test_a_recovery_ratio_of_zero_is_a_hard_outage():
    stx = _plan(_shaped(recovery_ratio=0.0))
    assert stx["labels"]["recovery_offset_s"] is None
    assert stx["labels"]["hard_outage"] is True


def test_shaped_lines_still_match_the_coverage_table():
    """A shape adds MASS, never a new message: every line a shaped story emits
    — repeats and contradictions included — must still promote exactly as
    `parser_coverage` claims, or the twin would be scoring the engine against
    a network that does not exist."""
    stx = _plan(_shaped())
    by_app = {row.exemplar[0]: row.coverage for row in chain.CHAIN_SIGNATURES
              if row.exemplar is not None}
    seen_unpromoted = 0
    for it in stx["items"]:
        if it["lane"] != "syslog":
            continue
        assert it["appname"] in by_app, (
            f"{it['appname']} is not in the shared chain vocabulary — a shape "
            f"invented a message the two harnesses do not share")
        sig = _classify(it)
        if by_app[it["appname"]] == chain.NOT_PROMOTED:
            assert sig is None
            seen_unpromoted += 1
        else:
            assert sig is not None, f"line never promotes: {it['message']!r}"
    # See the note in test_every_emitted_line_matches_the_coverage_table: the
    # chain has had no invisible symptom since tracker 184.
    assert seen_unpromoted == 0 and not chain.not_promoted_types()
