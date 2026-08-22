"""Tracker 163 — OPEN_OBJECTS count cap with DEFINED behaviour at the bound.

Every other major structure is bounded by count or LRU; OPEN_OBJECTS was
bounded only by quiesce TIME — under a broad storm its population is a
function of the network's behaviour, not of any configured limit (deferral
premise "0-8 observed" died at 168: live population ~1,500 at 1K stress).

Pinned here: exceeding the cap FORCE-CLOSES the least-recently-seen objects
to a terminal PERSISTED version (the quiesce path — append-only, replayable),
counted and logged — never a silent drop; eviction order is deterministic
(last_seen, then correlation_id); under-cap populations are untouched; and
the cap can be disabled explicitly (<=0) for lab characterization.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import main
from signals import EntityType
from test_archive_slice import sig

T0 = datetime(2026, 8, 22, 23, 0, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    def __init__(self):
        self.closed: list[tuple[str, int]] = []

    async def insert_detailed(self, table, rows, dedup_token=""):
        rows = list(rows)
        if table == "netops.corr_objects":
            for r in rows:
                if r.get("state") == "closed":
                    self.closed.append((r["correlation_id"], r["version"]))
        return main.InsertOutcome(committed=True, kind="committed", rows=len(rows))


def _snap(i: int):
    """A minimal real snapshot: one HIGH singleton per device."""
    from engine import EngineConfig, run_window
    from test_archive_slice import CAT
    window = (sig("device_cpu_high", EntityType.DEVICE, f"cap-dev-{i:04d}",
                  offset_s=i),)
    return run_window(window, CAT, (), EngineConfig())[0]


def _register(n: int):
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    for i in range(n):
        snap = _snap(i)
        main.OPEN_OBJECTS[snap.correlation_id] = {
            "version": 1, "hash": f"h{i}", "material": f"m{i}",
            "last_seen": T0 + timedelta(seconds=i),   # i=0 is LRU
            "last_persist": T0, "snapshot": snap, "opened_at": T0,
        }
        main._ARCHIVE_SLICE_HASH[snap.correlation_id] = f"slice{i}"
    return list(main.OPEN_OBJECTS)


async def _cycle():
    """One engine cycle over an EMPTY window — only lifecycle sweeps run."""
    await main.engine_cycle()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    monkeypatch.setattr(main, "OPEN_OBJECTS_FORCE_CLOSED", 0)
    monkeypatch.setattr(main, "_FORCE_CLOSE_LOG_LAST", 0.0)
    monkeypatch.setattr(main, "CORR_QUIESCE_S", 10**9)   # quiesce never fires
    yield
    main.OPEN_OBJECTS.clear(); main._ARCHIVE_SLICE_HASH.clear()


def test_cap_force_closes_the_least_recently_seen(monkeypatch):
    cids = _register(8)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 5)
    run(_cycle())
    assert len(main.OPEN_OBJECTS) == 5
    evicted = {c for c, _v in ch.closed}
    assert evicted == set(cids[:3]), "eviction must be least-recently-seen first"
    assert main.OPEN_OBJECTS_FORCE_CLOSED == 3
    for c in cids[:3]:
        assert c not in main._ARCHIVE_SLICE_HASH, "slice-hash entry leaked"


def test_eviction_persists_a_terminal_version_bump(monkeypatch):
    _register(3)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 2)
    run(_cycle())
    assert ch.closed and all(v == 2 for _c, v in ch.closed), (
        "a force-close must persist state='closed' at version+1 — the same "
        "append-only terminal the quiesce path writes")


def test_under_cap_is_untouched(monkeypatch):
    cids = _register(4)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 5)
    run(_cycle())
    assert list(main.OPEN_OBJECTS) == cids and not ch.closed
    assert main.OPEN_OBJECTS_FORCE_CLOSED == 0


def test_disabled_cap_never_evicts(monkeypatch):
    _register(50)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 0)
    run(_cycle())
    assert len(main.OPEN_OBJECTS) == 50 and not ch.closed


def test_eviction_order_is_deterministic_on_ties(monkeypatch):
    cids = _register(6)
    for c in main.OPEN_OBJECTS.values():
        c["last_seen"] = T0                          # all tied
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", 4)
    run(_cycle())
    assert [c for c, _v in ch.closed] == sorted(cids)[:2], (
        "tied last_seen must break on correlation_id — nondeterministic "
        "eviction makes replay evidence unreproducible")


def test_mutation_without_the_cap_population_is_unbounded(monkeypatch):
    """The defect this row exists for, as a witness: with the cap disabled the
    population tracks registration without limit."""
    _register(120)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "CORR_OPEN_OBJECTS_MAX", -1)
    run(_cycle())
    assert len(main.OPEN_OBJECTS) == 120
