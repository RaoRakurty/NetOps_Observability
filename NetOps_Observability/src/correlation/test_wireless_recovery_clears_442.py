# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 442 — wireless recoveries are clears (stage [1] only).

The wireless synthesis (`nms/wireless_events.go`) reported an AP rejoin as
`wireless_ap_up` and a radio coming back as `wireless_radio_up`: kinds of their
own, not `<kind>_clear`. `build_nodes` skips only `*_clear`, so each recovery
became a LIVE node at info that could join a component, and every reader that
tells a recovery by the `_clear` suffix (the RCA document's anomalous list,
`rca_accounting`, the UI's rcaCase) counted it as fault evidence — the
tracker-380 defect in a third spelling.

Now the synthesis emits `wireless_ap_down_clear` / `wireless_radio_down_clear`,
bound to the fault's entity, and stage [1] folds the retired `_up` spelling (an
api older than this change, or a replayed record) onto the same clear. No
template reads a wireless recovery, so no catalog, gate or constant moved.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import confirmability
import coverage
import producers as P
from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import build_nodes
from signals import EntityType, Severity

T0 = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)

# (fault kind, recovery clear, retired spelling, entity type, canonical entity id)
PAIRS = [
    ("wireless_ap_down", "wireless_ap_down_clear", "wireless_ap_up",
     EntityType.ACCESS_POINT, "ap-abc123"),
    ("wireless_radio_down", "wireless_radio_down_clear", "wireless_radio_up",
     EntityType.RADIO, "ap-abc123:radio1"),
]


def _ev(kind: str, device: str, severity: str, at: str = "2026-11-23T12:00:00Z") -> dict:
    return {
        "tenant_id": "t1", "normalized_event_type": kind,
        "source_system": "catalyst_9800", "integration_id": "int-1",
        "device_id": device, "severity": severity, "event_time": at,
        "event_id": f"{device}|{kind}|{at}", "category": "wireless_state",
    }


@pytest.mark.parametrize("down,clear,legacy,etype,dev", PAIRS)
def test_a_wireless_recovery_is_a_clear_on_its_faults_entity(down, clear, legacy, etype, dev):
    d = controller_event_to_signal(_ev(down, dev, "high"), T0)
    c = controller_event_to_signal(_ev(clear, dev, "info", "2026-11-23T12:01:00Z"), T0)
    assert d is not None and c is not None
    assert c.kind == clear
    assert (c.entity_type, c.entity_id) == (d.entity_type, d.entity_id) == (etype, dev)
    assert c.severity is Severity.INFO


@pytest.mark.parametrize("down,clear,legacy,etype,dev", PAIRS)
def test_the_retired_up_spelling_folds_onto_the_clear(down, clear, legacy, etype, dev):
    """A mixed-version deploy (api before this change, engine after) or a
    replayed record still carries the `_up` kind; it must not come back as a
    live node."""
    sig = controller_event_to_signal(_ev(legacy, dev, "info"), T0)
    assert sig is not None
    assert sig.kind == clear
    assert (sig.entity_type, sig.entity_id) == (etype, dev)


@pytest.mark.parametrize("down,clear,legacy,etype,dev", PAIRS)
def test_a_wireless_recovery_is_never_a_node(down, clear, legacy, etype, dev):
    d = controller_event_to_signal(_ev(down, dev, "high"), T0)
    for kind in (clear, legacy):
        c = controller_event_to_signal(_ev(kind, dev, "info", "2026-11-23T12:01:00Z"), T0)
        assert not list(build_nodes((c,))), kind
        nodes = list(build_nodes((d, c)))
        assert [n.kind for n in nodes] == [down], kind


def test_the_up_kinds_are_retired_and_the_clears_registered():
    for _down, clear, legacy, _etype, _dev in PAIRS:
        assert legacy not in P.EMITTED_KINDS, legacy
        assert legacy not in coverage.INTENTIONAL_BLIND, legacy
        assert legacy not in confirmability.KIND_MODALITY, legacy
        assert clear in P.EMITTED_KINDS, clear
        assert clear in coverage.INTENTIONAL_BLIND, clear
        assert confirmability.KIND_MODALITY[clear] is confirmability.KIND_MODALITY[_down]


def test_no_template_reads_a_wireless_recovery():
    """The premise that makes this golden-neutral: the fold changes no
    template's input — no clause, discriminator or anything else in the
    built-in catalog names a wireless recovery in either spelling."""
    names = {p[1] for p in PAIRS} | {p[2] for p in PAIRS}
    for t in builtin_catalog().templates:
        blob = t.model_dump_json()
        assert not [n for n in names if f'"{n}"' in blob], t.id
