# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 385 — an admin-caused link change is a CHANGE, not a fault.

Tracker 378 stamped `link_cause` (admin/fault/unknown) on link traps. This pins
what stages [5] and [6] do with it (owner decision 2026-11-08):

* [5] a no-edge link_state_change node whose every opening-severity signal is
  link_cause=admin opens no object, is counted, and still joins any object that
  later grounds to it.
* [6] clause `attrs` / `attrs_not` predicates; `local-link-fault` and
  `lastmile-circuit-flap` are contradicted by an admin link change; the unflagged
  sibling `sig.ent.access.admin-link-change-induced` scores it as a change.
* Evidence with no link_cause=admin is byte-identical bar the two version stamps.
* The parser is NOT touched: severity stays high (storm eviction is
  severity-ordered).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import catalog as C
import coverage
import engine as E
import main
import parser_rules
from catalog import builtin_catalog, load_catalog
from engine import EngineConfig, engine_version, run_window
from rank_memo import rank_key, signal_projection
from scoring import (
    CONFIDENCE_FLOOR,
    VERIFICATION_RESULT_KIND,
    clause_matches,
    rank,
    score_template,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    clause_attr,
    set_config_change_family,
    set_origin_observer,
)
from test_fixtures import fixture_files, signal_from_fixture
from verdicts import VerdictTier

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
SIBLING = "sig.ent.access.admin-link-change-induced"
LOCAL = "sig.ent.access.local-link-fault"
LASTMILE = "sig.ent.middle-mile.lastmile-circuit-flap"
BGP_FLAP = "sig.ent.wan-edge.bgp-peer-flap"
CONTROLLER_CHANGE = "sig.ent.wan-edge.controller-change-induced"
ADMIN_TAG = "link_state_change[link_cause=admin]"


def _sig(kind: str, eid: str = "r1:Gi0/1", et: EntityType = EntityType.INTERFACE,
         off: float = 0.0, sev: Severity = Severity.HIGH, cause: str | None = None,
         observer: str = "r1", modality: ModalityClass = ModalityClass.CONTROL_PLANE,
         tokens: tuple[str, ...] = (), attrs: dict | None = None) -> Signal:
    a = dict(attrs or {})
    if cause is not None:
        a["link_cause"] = cause
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=Source.TRAP, kind=kind,
        observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=et, entity_id=eid, severity=sev,
        native_id=f"t385|{kind}|{eid}|{off}|{cause}", entity_tokens=tokens, attrs=a)


def _link(cause: str | None = "admin", **kw: object) -> Signal:
    return _sig("link_state_change", cause=cause, **kw)  # type: ignore[arg-type]


def _bgp(off: float = 20.0, eid: str = "r1") -> Signal:
    return _sig("bgp_adjacency_change", eid=eid, et=EntityType.DEVICE, off=off)


def _if_metric(off: float = 30.0) -> Signal:
    return _sig("if_metric_anomaly", off=off, observer="r1-snmp",
                modality=ModalityClass.DEVICE_TELEMETRY)


def _hyp(result, template_id: str):
    return next(h for h in result.hypotheses if h.template_id == template_id)


def _ids(result) -> set[str]:
    return {h.template_id for h in result.hypotheses}


# ══ stage [5]: the singleton exemption ══════════════════════════════════════


def test_a_lone_admin_shutdown_opens_nothing():
    assert run_window([_link("admin")], builtin_catalog(), ()) == []


def test_a_lone_fault_down_still_opens():
    assert len(run_window([_link("fault")], builtin_catalog(), ())) == 1


@pytest.mark.parametrize("cause", [None, "unknown", "", "ADMIN", "administratively down"])
def test_anything_but_exactly_admin_opens(cause):
    """Fail-closed: a pre-378 trap, an unknown cause, a controller-relayed change."""
    assert len(run_window([_link(cause)], builtin_catalog(), ())) == 1


def test_a_non_string_link_cause_opens():
    assert len(run_window([_link(None, attrs={"link_cause": 1})], builtin_catalog(), ())) == 1


def test_a_real_fault_sharing_the_port_opens():
    win = [_link("admin"), _link("fault", off=5.0)]
    assert len(run_window(win, builtin_catalog(), ())) == 1


def test_an_unattributed_high_down_sharing_the_port_opens():
    win = [_link("admin"), _link(None, off=5.0)]
    assert len(run_window(win, builtin_catalog(), ())) == 1


def test_shutdown_then_no_shutdown_opens_nothing():
    """The warn linkUp is link_cause=unknown and below the floor: still exempt."""
    win = [_link("admin"), _link("unknown", off=40.0, sev=Severity.WARN)]
    assert run_window(win, builtin_catalog(), ()) == []


def test_the_exemption_is_only_for_link_state_change():
    assert len(run_window([_sig("bgp_adjacency_change", cause="admin")],
                          builtin_catalog(), ())) == 1


def test_a_grounded_shutdown_stays_in_the_object():
    """Owner: a shutdown on the wrong port is often the root cause."""
    win = [_link("admin"), _bgp()]
    objs = run_window(win, builtin_catalog(), ())
    assert len(objs) == 1
    assert len(objs[0].nodes) == 2
    kept = [s for n in objs[0].nodes for s in n.signals if s.kind == "link_state_change"]
    assert [clause_attr(s, "link_cause") for s in kept] == ["admin"]


def test_a_later_cohort_fault_opens_an_object_holding_the_earlier_shutdown():
    cat = builtin_catalog()
    admin = _link("admin")
    assert run_window([admin], cat, ()) == []
    objs = run_window([admin, _bgp(off=60.0)], cat, (),
                      since_ts=(T0 + timedelta(seconds=30)).timestamp())
    assert len(objs) == 1
    assert {n.kind for n in objs[0].nodes} == {"link_state_change", "bgp_adjacency_change"}
    assert objs[0].ranking.top_hypothesis == SIBLING


def test_storm_mode_folds_no_aggregate_and_counts():
    before = E.admin_link_change_singletons_total()
    assert run_window([_link("admin")], builtin_catalog(), (), storm_mode=True) == []
    assert E.admin_link_change_singletons_total() == before + 1


def test_a_cohort_that_does_not_touch_the_node_does_not_count():
    win = [_link("admin"), _sig("metric_anomaly", eid="r9", et=EntityType.DEVICE, sev=Severity.WARN)]
    before = E.admin_link_change_singletons_total()
    run_window(win, builtin_catalog(), (), cohort_keys=frozenset({"device:r9:metric_anomaly"}))
    assert E.admin_link_change_singletons_total() == before


def test_a_fault_down_is_not_counted():
    before = E.admin_link_change_singletons_total()
    run_window([_link("fault")], builtin_catalog(), ())
    assert E.admin_link_change_singletons_total() == before


def _samples() -> dict[str, str]:
    resp = asyncio.run(main.metrics_exposition())
    body = resp.body.decode() if hasattr(resp, "body") else str(resp)
    return {ln.split(" ", 1)[0]: ln.split(" ", 1)[1] for ln in body.splitlines()
            if ln and not ln.startswith("#") and " " in ln}


def test_the_counter_reaches_the_exposition():
    run_window([_link("admin")], builtin_catalog(), ())
    sample = int(_samples()["corr_admin_link_change_singletons_total"])
    assert sample == E.admin_link_change_singletons_total() >= 1


def test_engine_semver_moved():
    # 3.3.0 was this change; later minors (3.4.0: SD-WAN controller fan-in) keep it.
    semver = engine_version(EngineConfig()).split("+", 1)[0]
    assert tuple(int(x) for x in semver.split(".")) >= (3, 3, 0)


# ══ stage [6]: the clause DSL ═══════════════════════════════════════════════


@pytest.mark.parametrize("bad", [
    {"attrs": {"reason": "admin"}},          # key outside CLAUSE_ATTR_KEYS
    {"attrs_not": {"reason": "admin"}},
    {"attrs": {"link_cause": ""}},           # empty can never be asked for
    {"attrs": {"link_cause": " admin"}},     # clause_attr strips: could never match
    {"attrs": {"link_cause": 1}},            # non-str
    {"attrs": {"link_cause": "x" * 65}},     # over the read bound
    {"attrs": {}},
    {"attr": {"link_cause": "admin"}},       # extra=forbid catches the typo
    {"optional": True, "anchor": True},
])
def test_the_clause_validator_refuses(bad):
    with pytest.raises(ValidationError):
        C.Clause(kind="link_state_change", **bad)


def test_attrs_needs_equality_and_an_absent_key_fails():
    clause = C.Clause(kind="link_state_change", attrs={"link_cause": "admin"})
    assert clause_matches(clause, _link("admin"))
    assert not clause_matches(clause, _link("fault"))
    assert not clause_matches(clause, _link(None))


def test_attrs_not_refuses_equality_and_an_absent_key_passes():
    clause = C.Clause(kind="link_state_change", attrs_not={"link_cause": "admin"})
    assert not clause_matches(clause, _link("admin"))
    assert clause_matches(clause, _link("fault"))
    assert clause_matches(clause, _link(None))


def test_a_kind_only_clause_ignores_the_attr():
    clause = C.Clause(kind="link_state_change")
    assert all(clause_matches(clause, _link(c)) for c in ("admin", "fault", None))


def test_clause_attr_is_fail_closed():
    assert clause_attr(_link(None), "link_cause") == ""
    assert clause_attr(_link(None, attrs={"link_cause": 1}), "link_cause") == ""
    assert clause_attr(_link(None, attrs={"link_cause": " admin "}), "link_cause") == "admin"
    assert len(clause_attr(_link("x" * 200), "link_cause")) == 64


def _witness(corroborates: list[str]) -> Signal:
    return _sig(VERIFICATION_RESULT_KIND, modality=ModalityClass.ACTIVE_VERIFICATION,
                attrs={"corroborates_kinds": corroborates, "verify_method": "ssh"})


def test_a_verification_witness_cannot_satisfy_an_attrs_clause():
    """`_satisfying` is what scoring calls: it must refuse via the verification lane too."""
    t = C.Template(id="sig.ent.test.t", title="t", domain="ent.test", requires=[{"kind": "link_state_change", "attrs": {"link_cause": "admin"}}], verdict={"owner": "netops", "layer": "x", "first_steps": ["x"]})
    assert score_template(t, (_witness(["link_state_change"]),)).coverage == 0.0


def test_a_verification_witness_cannot_arm_the_discriminator():
    ev = (_link("fault"), _if_metric(), _witness(["link_state_change"]))
    assert not score_template(builtin_catalog().get(LOCAL), ev).contradicted


def test_a_verification_witness_cannot_be_the_sibling_anchor():
    assert SIBLING not in _ids(rank(builtin_catalog(), (_witness(["link_state_change"]), _bgp())))


def test_attrs_clauses_stay_reachable_through_the_kind_index():
    """Attrs make a clause stricter, so the kind-only index stays a superset: it
    scores exactly what a full evaluation would."""
    from scoring import _catalog_plan
    index, _ = _catalog_plan(builtin_catalog())
    assert "link_state_change" in index[LOCAL]
    assert "link_state_change" in index[SIBLING]
    assert "if_metric_anomaly" in index[SIBLING]


# ══ stage [6]: scoring ══════════════════════════════════════════════════════


def test_local_link_fault_is_contradicted_by_an_admin_trap():
    cat = builtin_catalog()
    result = rank(cat, (_link("admin"), _if_metric()))
    local = _hyp(result, LOCAL)
    assert local.contradicted
    assert local.confidence_rank <= 0.2 < CONFIDENCE_FLOOR
    assert local.forced_competitors == (SIBLING,)
    assert local.contradictions == (ADMIN_TAG,)
    assert result.top_hypothesis == SIBLING
    assert _hyp(result, SIBLING).confidence_rank == 1.0


def test_lone_admin_trap_gives_the_sibling_half_coverage():
    """attrs_not on the fault clause: the shutdown is not its own effect."""
    sib = _hyp(rank(builtin_catalog(), (_link("admin"),)), SIBLING)
    assert sib.coverage == 0.5
    assert sib.missing == (C.ADMIN_LINK_CHANGE_FAULT_KINDS,)


def test_two_admin_traps_are_still_half_coverage():
    ev = (_link("admin"), _link("admin", eid="r1:Gi0/2", off=1.0))
    assert _hyp(rank(builtin_catalog(), ev), SIBLING).coverage == 0.5


def test_a_fault_trap_leaves_local_link_fault_exactly_as_it_was():
    """Scored against a catalog without the 385 discriminator: identical row."""
    without = [dict(t) for t in C.BUILTIN_TEMPLATES]
    for t in without:
        if t["id"] == LOCAL:
            t.pop("discriminators")
    ev = (_link("fault"), _if_metric())
    now = score_template(builtin_catalog().get(LOCAL), ev).to_dict()
    old = score_template(load_catalog(without).get(LOCAL), ev).to_dict()
    assert now == old
    assert rank(builtin_catalog(), ev).top_hypothesis == LOCAL


def test_without_an_admin_signal_the_sibling_does_not_compete():
    """THE ANCHOR. The fault clause passes on any fault kind, and this id sorts
    first among ties: unanchored, a BGP drop with no shutdown anywhere ranks 'an
    operator shut down this interface' at 0.5, and even as a zero row it would
    displace the visible competitors."""
    for ev in ((_bgp(),), (_link("fault"), _if_metric()), (_link(None), _bgp()),
               (_sig("probe_loss", et=EntityType.PATH, eid="a->b"),)):
        assert SIBLING not in _ids(rank(builtin_catalog(), ev))


def test_shutdown_then_bgp_cascade_flag_off():
    set_config_change_family(False)
    result = rank(builtin_catalog(), (_link("admin"), _bgp(), _if_metric()))
    assert result.top_hypothesis == SIBLING
    assert _hyp(result, SIBLING).confidence_rank == 1.0
    assert _hyp(result, BGP_FLAP).contradicted
    assert _hyp(result, LOCAL).contradicted


def test_lastmile_flap_does_not_take_a_shutdown_on_a_wan_seam():
    """lastmile (owner: carrier) ties the sibling at 1.0, and seam affinity
    (engine `_break_ties_by_seam_affinity`) would hand it the object."""
    result = rank(builtin_catalog(), (_link("admin"), _bgp()))
    last = _hyp(result, LASTMILE)
    assert last.contradicted and last.contradictions == (ADMIN_TAG,)
    assert last.forced_competitors == (SIBLING,)


def test_lastmile_flap_is_unmoved_by_a_fault_trap():
    result = rank(builtin_catalog(), (_link("fault"), _bgp()))
    assert not _hyp(result, LASTMILE).contradicted


def test_the_sibling_declares_every_network_seam():
    """So the seam-affinity tie-break cannot prefer a 1.0 look-alike over it."""
    sib = builtin_catalog().get(SIBLING)
    assert set(sib.seams) == {"LAN", "WAN_SDWAN", "DC_FABRIC", "CARRIER_INTERCONNECT"}


def test_the_sibling_routes_to_netops():
    sib = _hyp(rank(builtin_catalog(), (_link("admin"), _bgp())), SIBLING)
    assert sib.owner == "netops"
    assert sib.operator_phrase.startswith("An operator shut down this interface")
    assert "remediation" in sib.false_positives[0]


@pytest.fixture
def _e5c_on():
    set_origin_observer(True)
    set_config_change_family(True)
    yield
    set_config_change_family(False)
    set_origin_observer(False)


def test_the_sibling_is_untouched_by_the_config_change_family():
    raw = C.BUILTIN_TEMPLATES
    before = next(t for t in raw if t["id"] == SIBLING)
    after = next(t for t in C.apply_config_change_family(raw) if t["id"] == SIBLING)
    assert before == after


def test_e5c_on_keeps_sibling_and_controller_template(_e5c_on):
    ev = (_link("admin"), _bgp(), _if_metric())
    on_cat = builtin_catalog()
    on = rank(on_cat, ev)
    assert on.top_hypothesis == SIBLING
    assert on_cat.get(CONTROLLER_CHANGE).title.startswith("Change-induced incident (configuration")
    on_row = _hyp(on, SIBLING).to_dict()
    set_config_change_family(False)
    set_origin_observer(False)
    off_row = _hyp(rank(builtin_catalog(), ev), SIBLING).to_dict()
    assert on_row == off_row


# ══ byte identity for evidence with no link_cause ═══════════════════════════


def _strip(blob: str) -> dict:
    data = json.loads(blob)
    data.pop("engine", None)
    data.get("ranking", {}).pop("catalog_version", None)
    data.pop("catalog_version", None)
    return data


def _corpus_blobs(cat, names: set[str] | None = None) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for path in fixture_files():
        raw = path.read_text()
        if "link_cause" in raw or (names is not None and path.stem not in names):
            continue
        ev = [signal_from_fixture(s, i) for i, s in enumerate(json.loads(raw)["signals"])]
        out[path.stem] = [_strip(o.hypotheses_blob()) for o in run_window(ev, cat, ())]
    return out


def _catalog_before_385():
    raw = []
    for t in C.BUILTIN_TEMPLATES:
        if t["id"] == SIBLING:
            continue
        t = dict(t)
        if t["id"] in (LOCAL, LASTMILE):
            discs = [d for d in t["discriminators"] if d["else_prefer"] != SIBLING]
            t["discriminators"] = discs
        raw.append(t)
    return load_catalog(raw)


def test_no_link_cause_evidence_is_byte_identical_with_and_without_385():
    """Whole corpus, durable: follows the catalog as other changes move it."""
    assert _corpus_blobs(builtin_catalog()) == _corpus_blobs(_catalog_before_385())


#: Frozen on main a40e750b, BEFORE this change, over these fixtures with the
#: hypotheses blob minus `engine` / `catalog_version`. A later catalog change that
#: legitimately moves one of these re-freezes it with its own proof.
STEP0_CONTROL = ("ambiguous-undetermined", "bgp-peer-flap-confirmed",
                 "lastmile-circuit-flap-confirmed", "local-link-fault-confirmed")
STEP0_DIGEST = "0dafd680d13d29fa"
PINNED_RULE_COUNT = 103  # parser_rules.RULES since tracker 387 wave 2 (Comware PHY_UPDOWN row)


def test_control_digest_frozen_before_the_change():
    blobs = _corpus_blobs(builtin_catalog(), set(STEP0_CONTROL))
    assert set(blobs) == set(STEP0_CONTROL)
    canon = json.dumps(blobs, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canon.encode()).hexdigest()[:16] == STEP0_DIGEST


# ══ rank memo ═══════════════════════════════════════════════════════════════


def test_link_cause_moves_the_rank_key():
    catv = builtin_catalog().version_hash()
    assert rank_key("t1", catv, (_link("admin"),)) != rank_key("t1", catv, (_link("fault"),))


def test_absent_and_empty_project_equal_because_the_scorer_reads_them_equal():
    absent, empty = _link(None), replace(_link(None), attrs={"link_cause": ""})
    assert signal_projection(absent) == signal_projection(empty)
    cat = builtin_catalog()
    assert [h.to_dict() for h in rank(cat, (absent, _bgp())).hypotheses] == \
           [h.to_dict() for h in rank(cat, (empty, _bgp())).hypotheses]


# ══ the parser did not move (owner: never lower severity at the parser) ═════


def test_the_parser_is_untouched():
    """A later parser change updates these pins: they record that THIS one did not.
    Re-pinned for tracker 387 PR 10, which moved the generic net and the IOS protocol
    line. The admin severity this file protects did not move: a trap link-down stays
    high (test below), and only the protocol line, which carries no cause, went to warn.
    Re-pinned for tracker 387 wave 1 (vendor packs, 388 syslog link cause): new rows
    behind every older one; the trap link rows this file protects did not move.
    Re-pinned for the tracker 387 process snapshot: the SD-WAN `ps` row only.
    Re-pinned for the tracker 387 SD-WAN DNS / ConfD SNMP auth grammars: no rule row.
    Re-pinned for the tracker 387 final syslog wave: five pack rows (the SD-WAN gateway
    lost at warn, two rows, and three known_benign) behind every older one; no link row moved.
    Re-pinned for the SD-WAN controller token: the two control-connection syslog rows emit
    the lost controller as a token; no link row moved.
    Re-pinned for the ConfD SNMP session grammar that reads no user: no rule row.
    Re-pinned for the merge of those two; no link row moved.
    Re-pinned for tracker 388 (syslog link cause): two link rows, SR Linux and SONiC, behind
    every older one; the trap link rows this file protects did not move.
    Re-pinned for tracker 387 vendor wave 2: a Comware PHY_UPDOWN row (warn) behind every
    older one, and the neutral syslog link row names the port of a `link status is` line;
    the trap link rows this file protects did not move."""
    assert parser_rules.PARSER_REV == "2026-11-13-vendor-packs-wave2"
    assert parser_rules.BAKED_RULES_HASH == (
        "5061534a0a9c9fbb8804eff7b0d7768321cf1c951ce056b459e4c4351eba6cba")
    assert parser_rules.RULES_HASH == parser_rules.BAKED_RULES_HASH
    assert len(parser_rules.RULES) == PINNED_RULE_COUNT
    link_rules = [r for r in parser_rules.RULES if r.kind == "link_state_change" and r.emit]
    assert any(set(r.emit.omit_empty) == {"admin_status", "oper_status", "link_cause", "link_reason"}
               for r in link_rules)


def test_the_coverage_matrix_did_not_move():
    """The sibling consumes only kinds other templates already consume."""
    now, old = builtin_catalog(), _catalog_before_385()
    assert coverage.consumed_kinds(now) == coverage.consumed_kinds(old)
    assert coverage.blind_spot_kinds(now) == coverage.blind_spot_kinds(old)
    assert coverage.orphan_producer_kinds(now) == coverage.orphan_producer_kinds(old)


def test_a_planned_shutdown_and_its_own_traffic_drop_never_confirm() -> None:
    # Review finding: trap + independent SNMP anomaly on one port is what ANY
    # planned shutdown looks like, so two observers must not make it CONFIRMED
    # (which feeds RCA auto-promotion).
    sib = _hyp(rank(builtin_catalog(), (_link("admin"), _if_metric())), SIBLING)
    assert sib.confidence_rank == 1.0
    assert sib.verdict_gate.tier is VerdictTier.SUSPECTED
    assert any("causes its own traffic drop" in r for r in sib.verdict_gate.reasons)


def test_a_device_level_admin_change_contradicts_nothing_it_cannot_replace() -> None:
    # The sibling's anchor needs an INTERFACE. A discriminator that fired on a
    # device-level signal would force a competitor the anchor gate keeps out of
    # the ranking: a "ruled out in favour of X" row with no X.
    result = rank(builtin_catalog(),
                  (_link("admin", eid="r1", et=EntityType.DEVICE), _if_metric()))
    assert SIBLING not in _ids(result)
    assert not [h.template_id for h in result.hypotheses if ADMIN_TAG in h.contradictions]
    assert not [h.template_id for h in result.hypotheses if SIBLING in h.forced_competitors]
