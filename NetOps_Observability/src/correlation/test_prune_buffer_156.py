"""Tracker 156 — window eviction must not recompute signal ids.

`_prune_buffer` and the maxlen-eviction branch of `buffer_signal` both did
`str(WINDOW_BUFFER[0].signal_id)` — a uuid5, i.e. a SHA-1 — for EVERY signal
they evicted, inline on the event loop. `buffer_signal` had already computed
that exact id at insert to key the dedup set, so it was pure recomputation, and
unbounded: a 50,000-signal window aging out in one prune is 50,000 SHA-1s with
no await between them.

Captured live 2026-08-20 as the top frame of a 30,989 ms stall — past the 30 s
Kafka session timeout — while the container had ~800 MB of FREE memory. A stall
source independent of memory pressure.

Measured on a 50,000-signal full eviction: 770.0 ms -> 60.3 ms, 50,000 -> 0
uuid5 calls, output byte-identical.

The risk of a parallel id deque is DESYNC, so every test below is about the two
structures staying aligned, and the last ones prove a desync degrades to
correct-and-slow rather than to wrong.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import main
import pytest
import signals as S

T0 = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)


def mk(i: int, secs: int | None = None) -> S.Signal:
    return S.Signal(
        tenant_id="acme", ts=T0 + timedelta(seconds=i if secs is None else secs),
        source=S.Source.SYSLOG, kind="link_state_change",
        observer=S.observer_of(f"leaf{i}", S.ObserverType.DEVICE,
                               collection_path="direct", clock_quality="unknown"),
        modality_class=S.ModalityClass.CONTROL_PLANE,
        entity_type=S.EntityType.INTERFACE, entity_id=f"leaf{i}:Gi0/1",
        severity=S.Severity.WARN, native_id=f"nat-{i}",
        entity_tokens=(f"leaf{i}",))


def load(n: int, secs=None):
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    for i in range(n):
        sig = mk(i, secs(i) if secs else None)
        sid = str(sig.signal_id)
        main._BUFFERED_IDS.add(sid)
        main.WINDOW_BUFFER.append(sig)
        main._BUFFERED_ID_ORDER.append(sid)


def reference_prune(now):
    """The pre-fix implementation, verbatim — the equivalence oracle."""
    horizon = now.timestamp() - main.ENGINE_CFG.window_s
    while main.WINDOW_BUFFER and main.WINDOW_BUFFER[0].ts.timestamp() < horizon:
        main._BUFFERED_IDS.discard(str(main.WINDOW_BUFFER[0].signal_id))
        main.WINDOW_BUFFER.popleft()


def snapshot():
    return ([str(s.signal_id) for s in main.WINDOW_BUFFER], set(main._BUFFERED_IDS))


@pytest.fixture(autouse=True)
def _clean():
    yield
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()


# --- output equivalence ----------------------------------------------------

@pytest.mark.parametrize("ahead", [0, 1, 50, 300, 5000, 100_000])
def test_prune_is_byte_identical_to_the_old_implementation(ahead):
    """Same evicted set, same remaining window, same dedup set — at every depth
    from 'evict nothing' to 'evict everything'."""
    now = T0 + timedelta(seconds=main.ENGINE_CFG.window_s + ahead)
    load(400)
    reference_prune(now)
    want = snapshot()
    load(400)
    main._prune_buffer(now)
    assert snapshot() == want


def test_prune_preserves_arrival_order():
    load(200)
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 50))
    remaining = [str(s.signal_id) for s in main.WINDOW_BUFFER]
    assert remaining == sorted(remaining, key=lambda x: remaining.index(x))
    assert list(main._BUFFERED_ID_ORDER) == remaining, "id deque drifted from the window"


def test_dedup_set_and_window_stay_the_same_size():
    load(300)
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 100))
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER) == len(main._BUFFERED_ID_ORDER)


# --- the expensive thing is actually gone ----------------------------------

def test_prune_computes_no_uuid5(monkeypatch):
    """THE POINT. Not 'fewer' — none."""
    load(500)
    calls = {"n": 0}
    real = uuid.uuid5

    def counting(ns, name):
        calls["n"] += 1
        return real(ns, name)

    monkeypatch.setattr(S.uuid, "uuid5", counting)
    monkeypatch.setattr(uuid, "uuid5", counting)
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 100_000))
    assert len(main.WINDOW_BUFFER) == 0, "the whole window should have aged out"
    assert calls["n"] == 0, f"prune still computed {calls['n']} uuid5s"


def test_a_full_window_prune_is_fast_enough_not_to_threaten_membership():
    """Bounded wall-clock: the acceptance criterion is that one prune cannot
    approach the Kafka session timeout. Generous ceiling so this is a
    catastrophic-regression canary, not a flaky micro-benchmark."""
    import time
    load(20_000)
    t0 = time.perf_counter()
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 100_000))
    elapsed = time.perf_counter() - t0
    assert len(main.WINDOW_BUFFER) == 0
    assert elapsed < 2.0, (
        f"a 20k-signal prune blocked the loop for {elapsed:.2f}s — the old "
        "implementation is back or something equally expensive is inline")


# --- the desync hazard the parallel deque introduces -----------------------

def test_desync_self_heals_and_is_counted():
    """A drifted id deque must degrade to correct-and-slow, never to wrong."""
    load(100)
    main._BUFFERED_ID_ORDER.clear()          # simulate drift
    before = main.WINDOW_ID_ORDER_RESYNCS
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 50))
    assert main.WINDOW_ID_ORDER_RESYNCS == before + 1, "a resync must be counted"
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER)
    assert list(main._BUFFERED_ID_ORDER) == [str(s.signal_id) for s in main.WINDOW_BUFFER]


def test_desync_still_produces_the_right_answer():
    now = T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 120)
    load(300)
    reference_prune(now)
    want = snapshot()
    load(300)
    main._BUFFERED_ID_ORDER.clear()          # drift before pruning
    main._prune_buffer(now)
    assert snapshot() == want


def test_a_test_that_clears_only_the_window_does_not_corrupt_state():
    """Existing suites clear WINDOW_BUFFER and _BUFFERED_IDS directly."""
    load(50)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._prune_buffer(T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 10))
    assert len(main._BUFFERED_ID_ORDER) == 0


# --- the maxlen path -------------------------------------------------------

def test_maxlen_eviction_keeps_all_three_structures_aligned(monkeypatch):
    """A full deque drops its head silently; the dedup set must drop it too, or
    the set leaks AND a later redelivery of an evicted signal is wrongly
    deduped."""
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=10))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=10))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    for i in range(40):
        main.buffer_signal(mk(i))
    assert len(main.WINDOW_BUFFER) == 10
    assert len(main._BUFFERED_ID_ORDER) == 10
    assert len(main._BUFFERED_IDS) == 10, "the dedup set leaked past the window bound"
    assert list(main._BUFFERED_ID_ORDER) == [str(s.signal_id) for s in main.WINDOW_BUFFER]


def test_a_signal_evicted_by_maxlen_can_be_redelivered(monkeypatch):
    """Its stale id must not linger in the dedup set and swallow the redelivery."""
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=5))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    first = mk(0)
    main.buffer_signal(first)
    for i in range(1, 12):
        main.buffer_signal(mk(i))
    assert str(first.signal_id) not in main._BUFFERED_IDS
    main.buffer_signal(first)
    assert str(first.signal_id) in main._BUFFERED_IDS, (
        "a redelivered signal that had aged out was wrongly deduped")


def test_redelivery_inside_the_window_is_still_deduped(monkeypatch):
    from collections import deque
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_ID_ORDER", deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    sig = mk(1)
    main.buffer_signal(sig)
    main.buffer_signal(sig)
    main.buffer_signal(sig)
    assert len(main.WINDOW_BUFFER) == 1, "at-least-once redelivery was not deduped"
    assert len(main._BUFFERED_ID_ORDER) == 1
