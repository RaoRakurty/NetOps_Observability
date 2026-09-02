"""A9 — a trap and a syslog line for ONE symptom must be one symptom.

The tracker-184 exercise, applied to SNMP traps. Before A9 the trap lane typed
three families (link state, device restart, BGP transition) and swept everything
else into the generic `device_alarm`: an OSPF adjacency loss reported by
`ospfNbrStateChange` and the same loss reported by `%OSPF-5-ADJCHG` produced two
DIFFERENT kinds, so the trap could not corroborate the syslog line, could not
satisfy a signature clause, and could not close an incident.

THE CONTRACT THIS FILE PINS. For a promoted symptom, the trap and the syslog
line agree on the vocabulary the engine reasons in — `kind`, entity TYPE and ID,
and `attrs["state"]` — and disagree only on the OBSERVER: the `Source` is
different, the modality is CONTROL_PLANE on both sides (a trap is the device's
own report, not an independent plane; it corroborates, it does not confirm
alone). The pairs are DATA: `telemetry-catalog/fixtures/trap_events.jsonl`
carries the trap and, on the rows where one exists, the syslog line for the same
symptom, so a new promoted rule ships its pair or has no pair test to pass.

It also pins the two things the audit deliberately did NOT do:
  * no new kind — a kind no signature template names is inert evidence;
  * no trap-side ingest pre-filter — see the screen test at the bottom.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

import producers as P
from signals import ModalityClass, Source

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.abspath(os.path.join(
    HERE, "..", "..", "telemetry-catalog", "fixtures", "trap_events.jsonl"))

T0 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)

#: The four rules the A9 audit promoted out of the generic trap alarm, and the
#: syslog rule each one has to agree with.
PROMOTED_PAIRS: dict[str, str] = {
    "trap.ospf.adjacency_change": "syslog.ospf.adjacency_change",
    "trap.isis.adjacency_change": "syslog.isis.adjacency_change",
    "trap.stp.topology_change": "syslog.stp.topology_notification",
    "trap.fhrp.state_change": "syslog.fhrp.state_change",
}


def _rows() -> list[dict]:
    with open(FIXTURES, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


ROWS = _rows()
PAIRED = [r for r in ROWS if r.get("_syslog_counterpart")]


def _trap(ev: dict):
    return P.trap_control_signal(dict(ev), "t1", T0)


def _syslog(ev: dict):
    return P.syslog_control_signal(dict(ev), "t1", T0)


# ══ the pairing table ════════════════════════════════════════════════════════


@pytest.mark.parametrize("fx", PAIRED, ids=lambda f: f["_case"])
def test_the_trap_and_its_syslog_counterpart_are_the_same_symptom(fx):
    """THE A9 PROOF. Same kind, same entity, same state — from two different
    wire formats, on two different observers."""
    t, s = _trap(fx["trap"]), _syslog(fx["_syslog_counterpart"])
    assert t is not None and s is not None, fx["_case"]
    assert t.kind == s.kind, f"{fx['_case']}: {t.kind} vs {s.kind}"
    assert t.entity_type == s.entity_type, fx["_case"]
    assert t.entity_id == s.entity_id, fx["_case"]
    assert t.attrs.get("state") == s.attrs.get("state"), fx["_case"]
    assert t.severity == s.severity, fx["_case"]


@pytest.mark.parametrize("fx", PAIRED, ids=lambda f: f["_case"])
def test_only_the_observer_differs(fx):
    """The trap is the DEVICE's own report of its own state: control plane, like
    the syslog line. Promoting it must not smuggle in a second modality plane —
    that would let one device self-confirm an incident."""
    t, s = _trap(fx["trap"]), _syslog(fx["_syslog_counterpart"])
    assert t.modality_class is ModalityClass.CONTROL_PLANE
    assert s.modality_class is ModalityClass.CONTROL_PLANE
    assert t.source is Source.TRAP and s.source is Source.SYSLOG
    # Two reports of one fault must remain two pieces of evidence.
    assert t.signal_id != s.signal_id, fx["_case"]
    assert t.native_id != s.native_id, fx["_case"]


@pytest.mark.parametrize("fx", PAIRED, ids=lambda f: f["_case"])
def test_the_pair_is_the_pair_the_catalog_declares(fx):
    t, s = _trap(fx["trap"]), _syslog(fx["_syslog_counterpart"])
    trap_rule = t.attrs["rule_id"]
    assert trap_rule in PROMOTED_PAIRS, f"{fx['_case']}: unexpected rule {trap_rule}"
    assert s.attrs["rule_id"] == PROMOTED_PAIRS[trap_rule], fx["_case"]


def test_every_promoted_rule_has_at_least_one_pair():
    paired = {_trap(f["trap"]).attrs["rule_id"] for f in PAIRED}
    missing = sorted(set(PROMOTED_PAIRS) - paired)
    assert not missing, (
        f"promoted with no syslog pair fixture: {missing} — a trap rule that "
        "cannot be shown to agree with its syslog counterpart is not promoted, "
        "it is a second vocabulary")


def test_both_directions_of_every_state_are_paired():
    """A symptom with only its DOWN half paired proves nothing about recovery:
    a trap that reports `up` as `unknown` would leave incidents open forever."""
    states: dict[str, set[str]] = {}
    for fx in PAIRED:
        t = _trap(fx["trap"])
        states.setdefault(t.attrs["rule_id"], set()).add(str(t.attrs.get("state")))
    for rid in ("trap.ospf.adjacency_change",):
        assert {"up", "down"} <= states.get(rid, set()), (
            f"{rid}: both transition directions must be paired")


# ══ no new kinds ═════════════════════════════════════════════════════════════


def test_the_audit_introduced_no_new_kind():
    """A kind no signature clause names is INERT: it grounds, it stores, and it
    confirms nothing. Every promoted trap rule reuses a kind the syslog lane
    already emits — which is also why coverage.py needed no new entry."""
    syslog_kinds = {r.kind for r in P.RULES if r.lane == "syslog"}
    for rule in P.RULES:
        if rule.rule_id in PROMOTED_PAIRS:
            assert rule.kind in syslog_kinds, rule.rule_id
            assert rule.kind in P.EMITTED_KINDS, rule.rule_id


def test_the_promoted_rules_are_ordered_before_the_generic_net():
    """Order is behaviour: a typed rule declared AFTER the severity-floor net
    would never run."""
    order = [r.rule_id for r in P.RULES if r.lane == "trap"]
    generic = order.index("trap.generic.device_alarm")
    for rid in PROMOTED_PAIRS:
        assert order.index(rid) < generic, rid
    assert generic == len(order) - 1, "the generic trap net must stay last"


def test_the_promoted_rules_stamp_their_catalog_rung():
    """A9 rows carry a ROW-level `fidelity_status` (no captured fixture exists),
    and it must reach the signal's provenance — an operator reading a stored
    signal has to be able to see how well-evidenced the grammar behind it is."""
    for fx in ROWS:
        sig = _trap(fx["trap"])
        if sig.attrs["rule_id"] in PROMOTED_PAIRS:
            assert sig.attrs["fidelity"] == "doc_claimed", fx["_case"]


# ══ the trap lane has no ingest screen (and must not grow a hand-written one) ══


def test_the_trap_lane_has_no_prefilter_and_the_screen_stays_syslog_derived():
    """A4/W1b built the ingest pre-filter for the SYSLOG lane and DERIVED its
    literals from the rule table, so registering a branch's screen coverage is
    the same act as registering the branch.

    The TRAP lane has no such screen, and A9 deliberately did not add one:
      * the last trap rule fires on SEVERITY alone (`severity_floor: trap`), so
        a sound screen would have to pass every warning-or-worse trap anyway;
      * a trap arrives as an already-decoded envelope, not as 2 KB of free text,
        so there is no `.upper()`-and-substring-scan cost to avoid;
      * a screen that is not derived from the table can go stale silently, and
        a stale trap screen would DROP evidence.

    This test is the guard on that decision: if a `trap_promotable` ever
    appears, its literals must be derived from the `lane == "trap"` rows the way
    `_CP_GUARD_MARKERS` is derived from the syslog rows — and this test has to
    be rewritten to prove it, not deleted."""
    assert not hasattr(P, "trap_promotable"), (
        "a trap-side pre-filter appeared: derive its literals from the "
        "`lane == 'trap'` rules (as _CP_GUARD_MARKERS does for syslog) and "
        "extend this test to re-derive them independently")
    # The syslog screen is table-derived and covers ONLY the syslog rows that
    # can EMIT: a trap row's markers must never leak into it (they screen a
    # different haystack), and neither may a `shadow` row's (A9b) — a row that
    # emits nothing must not widen the gate that admits raw lines into the
    # classifiers, so it is observed only on lines already admitted for some
    # other rule.
    syslog_markers = {m for r in P.RULES
                      if r.lane == "syslog" and not r.shadow for m in r.markers}
    assert set(P._CP_GUARD_MARKERS) == syslog_markers
    shadow_markers = {m for r in P.RULES if r.shadow for m in r.markers}
    assert not (shadow_markers & set(P._CP_GUARD_MARKERS)), (
        "a shadow rule's markers reached the screen — it emits nothing, so the "
        "only effect would be admitting more raw syslog into both producers")
    assert all(m == m.upper() for m in P._CP_GUARD_MARKERS)
    trap_markers = {m for r in P.RULES if r.lane == "trap" for m in r.markers}
    assert not (trap_markers & set(P._CP_GUARD_MARKERS)), (
        "a trap rule's markers reached the SYSLOG screen — they test the trap "
        "lane's oid/name/etype haystacks, not a syslog classification token")


def test_a_trap_below_the_severity_floor_is_still_not_a_signal():
    """The anti-noise guardrail A9 must not weaken: an unclassified trap the MIB
    flags below `warning` stays a searchable log and never an RCA signal."""
    quiet = dict(ROWS[0]["trap"])
    quiet.update(trap_oid="1.3.6.1.4.1.9.9.999.0.7", trap_name="",
                 event_type="enterprise_specific", severity="notice",
                 varbinds=[])
    assert _trap(quiet) is None
