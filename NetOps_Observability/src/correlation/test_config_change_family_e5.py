# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""E5c config-change family — change-induced RCA from ANY source (stages [6]+[7]).

Plan of record: docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md (E5). A change
reaches the engine as `device_config_change` (the box: syslog / traps),
`controller_policy_change` (a controller: vManage audit, Catalyst Center, …) or
`config_change`. Before E5c the change-induced signature REQUIRED the
controller's kind, so an SNMP-only or syslog-only estate could never match it,
and a lone controller push with no fault scored full coverage.

With CORR_CONFIG_CHANGE_FAMILY on (and E1 on — it is refused without it):
  * any change kind + a fault from any source → change-induced;
  * a change with no fault is half coverage, never an incident on its own;
  * a change matched by an OPTIONAL clause is context: it never enters the
    verdict gate, so a controller audit record cannot confirm a BGP flap;
  * the same change seen twice (controller + device) never self-confirms.
Off, not one byte moves.
"""
from __future__ import annotations

import pytest

import catalog as C
from scoring import score_template
from signals import (
    CONFIG_CHANGE_KIND_SET,
    ORIGIN_DEVICE_ATTR,
    ModalityClass,
    ObserverType,
    Source,
    config_change_family_enabled,
    set_config_change_family,
    set_origin_observer,
)
from test_verdicts import make_signal
from verdicts import VerdictTier

CHANGE_INDUCED = C.CHANGE_INDUCED_TEMPLATE_ID
BGP_FLAP = "sig.ent.wan-edge.bgp-peer-flap"
TIER = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1, VerdictTier.CONFIRMED: 2}


@pytest.fixture(autouse=True)
def _restore():
    # Every test starts OFF whatever the environment says (the ON suites run
    # this file with CORR_CONFIG_CHANGE_FAMILY=1 too); ON is opted into.
    set_config_change_family(False)
    set_origin_observer(False)
    yield
    set_config_change_family(False)
    set_origin_observer(False)


@pytest.fixture
def family_on():
    set_origin_observer(True)
    set_config_change_family(True)


def _origin(origin: str | None) -> dict | None:
    return {ORIGIN_DEVICE_ATTR: origin} if origin else None


# The make_signal entity is device "leaf1"; every signal below is about it.
def trap_change(origin: str | None = None):
    return make_signal("leaf1", ModalityClass.CONTROL_PLANE, source=Source.TRAP,
                       kind="device_config_change", attrs=_origin(origin))


def controller_change(origin: str | None = None):
    return make_signal("vmanage:nmsi-1", ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER,
                       collection_path="via_controller", observer_type=ObserverType.CONTROLLER,
                       kind="controller_policy_change", attrs=_origin(origin))


def snmp_bgp_episode(origin: str | None = None):
    return make_signal("leaf1", ModalityClass.DEVICE_TELEMETRY, source=Source.METRIC,
                       collection_path="snmp_poll", kind="bgp_state_anomaly", attrs=_origin(origin))


def syslog_bgp(origin: str | None = None):
    return make_signal("leaf1", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG,
                       kind="bgp_adjacency_change", attrs=_origin(origin))


def controller_bfd(origin: str | None = None):
    return make_signal("vmanage:nmsi-1", ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER,
                       collection_path="via_controller", observer_type=ObserverType.CONTROLLER,
                       kind="controller_bfd_down", attrs=_origin(origin))


def score(tid: str, *evidence):
    return score_template(C.builtin_catalog().get(tid), tuple(evidence))


# ── OFF is byte-identical; ON without E1 is refused ──────────────────────────

def test_off_catalog_is_the_unchanged_built_in_set() -> None:
    assert not config_change_family_enabled()
    assert C.builtin_catalog().version_hash() == C.load_catalog(C.BUILTIN_TEMPLATES).version_hash()


def test_requested_without_e1_stays_off() -> None:
    set_config_change_family(True)
    assert not config_change_family_enabled(), "the family must require the E1 origin rule"
    assert C.builtin_catalog().version_hash() == C.load_catalog(C.BUILTIN_TEMPLATES).version_hash()


def test_on_catalog_has_its_own_version(family_on) -> None:
    assert C.builtin_catalog().version_hash() != C.load_catalog(C.BUILTIN_TEMPLATES).version_hash()


def test_the_rewrite_is_pure() -> None:
    before = repr(C.BUILTIN_TEMPLATES)
    C.apply_config_change_family(C.BUILTIN_TEMPLATES)
    assert repr(C.BUILTIN_TEMPLATES) == before


def test_off_scoring_is_unchanged_for_the_device_change_clause() -> None:
    """OFF, the device's own change in the BGP-flap optional clause still enters
    the gate exactly as before (the context-only rule is an ON rule)."""
    s = score(BGP_FLAP, syslog_bgp(), trap_change())
    assert "device_config_change" in s.satisfied


# ── the shape of the ON catalog ───────────────────────────────────────────────

def test_change_induced_requires_any_change_and_a_fault(family_on) -> None:
    t = C.builtin_catalog().get(CHANGE_INDUCED)
    required = [c for c in t.requires if not c.optional]
    assert len(required) == 2 and not [c for c in t.requires if c.optional]
    assert required[0].kinds() == CONFIG_CHANGE_KIND_SET
    assert required[1].kinds() == frozenset(C.CHANGE_INDUCED_FAULT_KINDS.split("|"))


def test_every_what_changed_clause_widens_and_stays_optional(family_on) -> None:
    widened = {t.id for t in C.builtin_catalog().enabled_templates() for c in t.requires
               if c.kinds() == CONFIG_CHANGE_KIND_SET and c.optional}
    assert {BGP_FLAP, "sig.ent.access.ospf-adjacency-flap", "sig.ent.fabric.isis-adjacency-flap",
            "sig.ent.security.hardening-drift-story"} <= widened


# ── any source reaches change-induced ─────────────────────────────────────────

def test_snmp_only_change_induced(family_on) -> None:
    """A CONFIG-MAN / CFGMGMT trap + an SNMP BGP episode: no controller at all."""
    assert score(CHANGE_INDUCED, trap_change(), snmp_bgp_episode()).coverage == 1.0


def test_snmp_only_could_not_match_before() -> None:
    assert score(CHANGE_INDUCED, trap_change(), snmp_bgp_episode()).coverage < 0.5


def test_controller_only_change_induced(family_on) -> None:
    """vManage audit + vManage BFD down: an integration-only tenant."""
    assert score(CHANGE_INDUCED, controller_change(), controller_bfd()).coverage == 1.0


# ── a change is not an incident ───────────────────────────────────────────────

def test_a_lone_controller_push_was_full_coverage_before() -> None:
    """The defect, pinned: routine change work scored like an incident."""
    assert score(CHANGE_INDUCED, controller_change()).coverage == 1.0


def test_a_change_with_no_fault_is_half_coverage(family_on) -> None:
    s = score(CHANGE_INDUCED, controller_change())
    assert s.coverage == 0.5
    assert s.missing


# ── the verdict gate ──────────────────────────────────────────────────────────

def test_a_required_change_is_still_a_witness(family_on) -> None:
    """Context-only applies to OPTIONAL clauses. In change-induced the change is
    required evidence and counts toward coverage — but a controller push is
    management_plane, which since owner D1 (2026-11-11) supports and never
    anchors: with ONE measurement plane beside it the story stays suspected."""
    s = score(CHANGE_INDUCED, controller_change(), syslog_bgp())
    assert s.coverage == 1.0
    assert ModalityClass.MANAGEMENT_PLANE in s.verdict_gate.coverage.trusted_modalities
    assert s.verdict_gate.tier is VerdictTier.SUSPECTED
    assert any("supports but never anchors" in r for r in s.verdict_gate.reasons)


def test_the_same_change_seen_twice_never_self_confirms(family_on) -> None:
    """The controller's audit record and the device's own CONFIG-MAN trap are one
    change; with the fault from the same box, nothing independent remains."""
    s = score(CHANGE_INDUCED, controller_change("leaf1"), trap_change("leaf1"), syslog_bgp("leaf1"))
    assert s.coverage == 1.0
    assert s.verdict_gate.tier is not VerdictTier.CONFIRMED


def test_an_optional_change_never_promotes_a_bgp_flap(family_on) -> None:
    """A controller audit record (MANAGEMENT plane, another observer) matched by
    the BGP flap's optional "what changed?" clause raises coverage but is never
    the second plane that confirms it."""
    on = score(BGP_FLAP, syslog_bgp(), controller_change())
    set_config_change_family(False)
    off = score(BGP_FLAP, syslog_bgp(), controller_change())
    assert TIER[on.verdict_gate.tier] <= TIER[off.verdict_gate.tier]
    assert on.verdict_gate.tier is not VerdictTier.CONFIRMED


def test_the_optional_change_still_supports(family_on) -> None:
    s = score(BGP_FLAP, syslog_bgp(), controller_change())
    assert s.supporting_hit
    assert C.CONFIG_CHANGE_KINDS in s.satisfied
