# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 288 — the loop-thread bound, held by a real cycle at estate scale.

Tracker 288 recorded a 276-316 ms per-object `builder.content_hash` stretch at
2,800 devices and asked for the bound to be pinned "with a COUNT the way the
snapshot loop now is", not with a timing. That reading came from a harness that
was never checked in; driving the real `engine_cycle()` (ClickHouse stubbed, as
in test_carried_edges_bound_192) over a single-tenant storm at 700 / 2,800 /
5,000 devices, plain and under a declared storm, the worst un-yielded block
measured 15-47 ms with zero overruns, and the discarded cold first sample was
never the worst `content_hash` call (2026-10-10).

So the assertion is the §10 safety observable itself: a real cycle at the
2,800-device scale the row names produces ZERO blocks over CORR_SYNC_BUDGET_MS.
That is a count, so it does not go red on a loaded runner the way a millisecond
threshold does; the budget sits an order of magnitude above what the cycle
needs, so an overrun here is a regression in what runs on the loop thread, not
noise.
"""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta

import pytest

import main
import signals as S
from test_prune_buffer_156 import T0

DEVICES = 2_800


class _StubCH:
    async def insert_detailed(self, table, rows, dedup_token=""):
        return main.InsertOutcome(committed=True, kind="committed",
                                  rows=len(list(rows)))


def _sig(i: int, kind: str, etype: S.EntityType, entity: str, off: float) -> S.Signal:
    return S.Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=off),
        source=S.Source.SYSLOG, kind=kind,
        observer=S.observer_of(f"leaf{i}", S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=S.ModalityClass.CONTROL_PLANE,
        entity_type=etype, entity_id=entity, severity=S.Severity.WARN,
        native_id=f"nat-{kind}-{i}", entity_tokens=(f"leaf{i}",))


def _load_storm(devices: int) -> int:
    """Every device reports a link-state change and a resource anomaly — a
    two-node object per device, carrying real hypotheses."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    loaded = 0
    for i in range(devices):
        for s in (_sig(i, "link_state_change", S.EntityType.INTERFACE, f"leaf{i}:Gi0/1", i * 0.01),
                  _sig(i, "device_resource_anomaly", S.EntityType.DEVICE, f"leaf{i}", i * 0.01 + 1)):
            sid = str(s.signal_id)
            main.WINDOW_BUFFER.append(s)
            main._BUFFERED_ID_ORDER.append(sid)
            main._BUFFERED_IDS.add(sid)
            main._advance_watermark(s, time.monotonic())
            loaded += 1
    return loaded


@pytest.fixture
def _engine(monkeypatch):
    """A clean engine with the deployed sync accounting, restored afterwards."""
    monkeypatch.setattr(main, "ch", _StubCH())
    monkeypatch.setattr(main, "OPEN_OBJECTS", {})
    monkeypatch.setattr(main, "_SYNC_RATE", {})
    monkeypatch.setattr(main, "SYNC_STRETCH_MAX_MS", 0.0)
    monkeypatch.setattr(main, "SYNC_STRETCH_MAX_SITE", "")
    monkeypatch.setattr(main, "SYNC_OVERRUNS_TOTAL", 0)
    monkeypatch.setattr(main, "SYNC_OVERRUN_LAST_SITE", "")
    monkeypatch.setattr(main, "CORR_SYNC_OFFLOAD", True)
    monkeypatch.setattr(main, "CORR_SYNC_BUDGET_MS", 500.0)
    for name in ("_STORM_ACTIVE", "STORM_BUFFER_FRACTION", "STORM_EXIT_FRACTION"):
        monkeypatch.setattr(main, name, getattr(main, name))
    yield
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()


@pytest.mark.parametrize("storm", [False, True], ids=["plain", "declared-storm"])
def test_a_real_cycle_at_estate_scale_never_overruns_the_sync_budget(_engine, storm):
    if storm:
        # Forced declaration, exactly as test_the_storm_priority_sort_is_attributed.
        main._STORM_ACTIVE = False
        main.STORM_BUFFER_FRACTION = 0.0
        main.STORM_EXIT_FRACTION = -0.1
    assert _load_storm(DEVICES) == 2 * DEVICES
    asyncio.run(main.engine_cycle())

    assert main.OPEN_OBJECTS, "the cycle built no objects — the bound was not exercised"
    assert main.SYNC_OVERRUNS_TOTAL == 0, (
        f"{main.SYNC_OVERRUNS_TOTAL} loop-thread block(s) over the "
        f"{main.CORR_SYNC_BUDGET_MS:.0f} ms budget at {DEVICES} devices; last at "
        f"{main.SYNC_OVERRUN_LAST_SITE}, worst {main.SYNC_STRETCH_MAX_MS:.0f} ms at "
        f"{main.SYNC_STRETCH_MAX_SITE} (tracker 288)")
    # The instrument must actually have run: a cycle this size records spans.
    assert main.SYNC_STRETCH_MAX_SITE, "no sync span recorded — the observable is dark"
