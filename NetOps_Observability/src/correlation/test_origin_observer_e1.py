# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""E1 origin observer — one device's own state, seen through two lanes, is one
observation, never two independent witnesses (verdict stage [7]).

Plan of record: docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md §7a/§7b. The
cases are the two real over-counts the source-equivalence analysis found:

  * a device's own trap + the controller relaying the SAME device's alarm
    (observer = the device vs observer = the controller), and
  * a device's syslog (observer = its hostname) + its SNMP episode (observer =
    its inventory id) — two spellings of one box.

With CORR_ORIGIN_OBSERVER off nothing moves (no attrs key, no Witness field, no
memo key byte); with it on each pair stops being independent. The rule is
downgrade-only: it can remove an independent pair, never add one.
"""
from __future__ import annotations

import itertools

import pytest

import main
import rank_memo
from entity_resolver import EntityResolver
from signals import (
    ORIGIN_DEVICE_ATTR,
    ModalityClass,
    ObserverType,
    Source,
    set_origin_observer,
)
from test_verdicts import make_signal
from verdicts import VerdictTier, assess, witness_of

DEVICE_ID = "vedge-20-1e95f00f"


@pytest.fixture
def origin_on():
    set_origin_observer(True)
    yield
    set_origin_observer(False)


@pytest.fixture(autouse=True)
def _always_restore():
    yield
    set_origin_observer(False)


def resolver() -> EntityResolver:
    return EntityResolver.from_rows(
        devices=[
            {"device": DEVICE_ID, "name": "vEdge-20", "mgmt_ip": "192.168.222.104"},
            {"device": "cedge-40-b99e47eb", "name": "cEDGE-40", "mgmt_ip": "192.168.222.107"},
            # Two devices sharing a name: the name must resolve to NOTHING.
            {"device": "core-a", "name": "core"},
            {"device": "core-b", "name": "core"},
        ],
        interface_ips=[], ifindex=[])


def trap_from_device(origin: str | None = None):
    return make_signal(DEVICE_ID, ModalityClass.CONTROL_PLANE, source=Source.TRAP, kind="link_state_change",
                       attrs={ORIGIN_DEVICE_ATTR: origin} if origin else None)


def controller_relay_of_device(origin: str | None = None):
    return make_signal("vmanage:nmsi-1", ModalityClass.MANAGEMENT_PLANE, source=Source.CONTROLLER,
                       collection_path="via_controller", observer_type=ObserverType.CONTROLLER,
                       kind="link_state_change", attrs={ORIGIN_DEVICE_ATTR: origin} if origin else None)


def syslog_by_hostname(origin: str | None = None):
    return make_signal("vEdge-20", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, kind="link_state_change",
                       attrs={ORIGIN_DEVICE_ATTR: origin} if origin else None)


def snmp_episode_by_id(origin: str | None = None):
    return make_signal(DEVICE_ID, ModalityClass.DEVICE_TELEMETRY, source=Source.METRIC,
                       collection_path="snmp_poll", kind="if_metric_anomaly",
                       attrs={ORIGIN_DEVICE_ATTR: origin} if origin else None)


# ── the over-counts, before and after ─────────────────────────────────────────

def test_trap_plus_controller_relay_of_one_device_no_longer_confirms_even_with_the_rule_off() -> None:
    """The defect E1 was built for: with the rule off this pair CONFIRMED on one
    box's word. Owner D1 (2026-11-11) closes it for every device, flag or not:
    the controller relay is management_plane, which supports but never anchors."""
    v = assess([trap_from_device(DEVICE_ID), controller_relay_of_device(DEVICE_ID)])
    assert v.tier is not VerdictTier.CONFIRMED
    assert any("supports but never anchors" in r for r in v.reasons), v.reasons


def test_trap_plus_controller_relay_of_one_device_never_confirms(origin_on) -> None:
    v = assess([trap_from_device(DEVICE_ID), controller_relay_of_device(DEVICE_ID)])
    assert v.tier is not VerdictTier.CONFIRMED


def test_syslog_hostname_plus_snmp_id_confirms_today() -> None:
    assert assess([syslog_by_hostname(DEVICE_ID), snmp_episode_by_id(DEVICE_ID)]).tier is VerdictTier.CONFIRMED


def test_syslog_hostname_plus_snmp_id_never_confirms(origin_on) -> None:
    assert assess([syslog_by_hostname(DEVICE_ID), snmp_episode_by_id(DEVICE_ID)]).tier is not VerdictTier.CONFIRMED


def test_two_different_devices_still_confirm(origin_on) -> None:
    """The rule removes only same-device pairs: two boxes are still two witnesses
    (two measurement planes since owner D1; a controller relay never anchors)."""
    assert assess([syslog_by_hostname(DEVICE_ID), snmp_episode_by_id("cedge-40-b99e47eb")]).tier \
        is VerdictTier.CONFIRMED


def test_unstamped_signals_are_unaffected(origin_on) -> None:
    """No origin means no claim either way — the old rule applies."""
    assert assess([syslog_by_hostname(), snmp_episode_by_id()]).tier is VerdictTier.CONFIRMED


# ── downgrade-only ─────────────────────────────────────────────────────────────

def _witness_pool():
    sigs = [trap_from_device(DEVICE_ID), controller_relay_of_device(DEVICE_ID), syslog_by_hostname(DEVICE_ID),
            snmp_episode_by_id(DEVICE_ID), controller_relay_of_device("cedge-40-b99e47eb"), trap_from_device(),
            syslog_by_hostname()]
    return sigs


def test_the_rule_never_creates_independence() -> None:
    pool = _witness_pool()
    off = [witness_of(s) for s in pool]
    set_origin_observer(True)
    on = [witness_of(s) for s in pool]
    for (a_off, b_off), (a_on, b_on) in zip(itertools.combinations(off, 2), itertools.combinations(on, 2)):
        if a_on.independent_of(b_on):
            assert a_off.independent_of(b_off), "the origin rule made a dependent pair independent"


def test_the_verdict_never_rises() -> None:
    pool = _witness_pool()
    rank = {VerdictTier.UNDETERMINED: 0, VerdictTier.SUSPECTED: 1, VerdictTier.CONFIRMED: 2}
    for r in (2, 3):
        for combo in itertools.combinations(pool, r):
            off = assess(list(combo)).tier
            set_origin_observer(True)
            on = assess(list(combo)).tier
            set_origin_observer(False)
            assert rank[on] <= rank[off], f"origin rule raised {off} → {on}"


# ── OFF is byte-identical ──────────────────────────────────────────────────────

def test_off_witness_carries_no_origin() -> None:
    assert witness_of(trap_from_device(DEVICE_ID)).origin == ""


def test_off_memo_key_ignores_origin() -> None:
    a = rank_memo.signal_projection(trap_from_device(DEVICE_ID))
    b = rank_memo.signal_projection(trap_from_device("someone-else"))
    assert a == b, "with the flag off the origin must not reach the memo key"


def test_off_window_entry_stamps_nothing(monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    sig = syslog_by_hostname()
    assert main.origin_observer_enabled() is False
    assert ORIGIN_DEVICE_ATTR not in sig.attrs


def test_on_memo_key_separates_origins(origin_on) -> None:
    a = rank_memo.signal_projection(trap_from_device(DEVICE_ID))
    b = rank_memo.signal_projection(trap_from_device("cedge-40-b99e47eb"))
    assert a != b, "a cached verdict could be served across evidence that differs only in origin"


# ── canonicalisation at the window entry ───────────────────────────────────────

def test_hostname_and_inventory_id_canonicalise_to_one_origin(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    by_name = main._stamp_origin_device(syslog_by_hostname())
    by_id = main._stamp_origin_device(snmp_episode_by_id())
    assert by_name.attrs[ORIGIN_DEVICE_ATTR] == by_id.attrs[ORIGIN_DEVICE_ATTR] == DEVICE_ID
    assert assess([by_name, by_id]).tier is not VerdictTier.CONFIRMED


def test_an_address_canonicalises_too(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    flow = make_signal("192.168.222.104", ModalityClass.PASSIVE_FLOW, source=Source.FLOW,
                       collection_path="flow_export", kind="flow_volume_anomaly")
    assert main._stamp_origin_device(flow).attrs[ORIGIN_DEVICE_ATTR] == DEVICE_ID


def test_an_ambiguous_name_is_never_guessed(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    sig = make_signal("core", ModalityClass.CONTROL_PLANE, source=Source.SYSLOG, kind="link_state_change")
    assert main._stamp_origin_device(sig).attrs[ORIGIN_DEVICE_ATTR] == "core", \
        "an ambiguous token must stay itself, never become one of the devices it could mean"


def test_the_controller_origin_is_the_reported_device_not_the_controller(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    stamped = main._stamp_origin_device(controller_relay_of_device("vEdge-20"))
    assert stamped.attrs[ORIGIN_DEVICE_ATTR] == DEVICE_ID
    bare = main._stamp_origin_device(controller_relay_of_device())
    assert ORIGIN_DEVICE_ATTR not in bare.attrs, "a controller event without a device has no origin"


def test_a_probe_gets_no_origin(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    probe = make_signal("agent-1", ModalityClass.ACTIVE_PROBE)
    assert ORIGIN_DEVICE_ATTR not in main._stamp_origin_device(probe).attrs


def test_stamping_builds_a_new_attrs_dict(origin_on, monkeypatch) -> None:
    monkeypatch.setattr(main, "cached_entity_resolver_for", lambda tenant: resolver())
    sig = syslog_by_hostname()
    original = sig.attrs
    stamped = main._stamp_origin_device(sig)
    assert ORIGIN_DEVICE_ATTR not in original and stamped.attrs is not original


def test_resolver_canonical_device() -> None:
    r = resolver()
    assert r.canonical_device(DEVICE_ID) == DEVICE_ID
    assert r.canonical_device("VEDGE-20") == DEVICE_ID
    assert r.canonical_device("192.168.222.107") == "cedge-40-b99e47eb"
    assert r.canonical_device("core") is None
    assert r.canonical_device("") is None and r.canonical_device(None) is None
