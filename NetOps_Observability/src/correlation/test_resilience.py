"""Load / resilience bounds (gap-report #10, §9 'all queues bounded'). The engine's
working memory must stay bounded and correct under a signal flood and at-least-once
Kafka redelivery — no unbounded growth, no silently-dropped fresh signals."""

from datetime import datetime, timedelta, timezone

import pytest

import main
from signals import (
    EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source,
)

T0 = datetime(2026, 6, 22, 9, 0, 0, tzinfo=timezone.utc)


def mk(i: int, *, ts: datetime | None = None) -> Signal:
    return Signal(
        tenant_id="t1", ts=ts or (T0 + timedelta(seconds=i % 100)), source=Source.METRIC,
        kind="if_util_high", observer=Observer(observer_id="o", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.INTERFACE,
        entity_id=f"d:Gi0/{i}", severity=Severity.HIGH, native_id=f"n{i}", attrs={},
    )


@pytest.fixture(autouse=True)
def _clean_buffer():
    """Isolate the shared module globals between tests."""
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    yield
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()


def test_window_buffer_is_maxlen_bounded():
    assert main.WINDOW_BUFFER.maxlen is not None, "the window buffer MUST be bounded (§9)"


def test_dedup_set_never_exceeds_the_buffer_under_flood():
    # Push well past maxlen — a flood the engine must survive without leaking memory.
    n = main.WINDOW_BUFFER.maxlen + 5_000
    for i in range(n):
        main.buffer_signal(mk(i))
    assert len(main.WINDOW_BUFFER) == main.WINDOW_BUFFER.maxlen
    # The dedup set must track the buffer, NOT the total ingested count.
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER), "dedup set leaked past the buffer"


def test_at_least_once_redelivery_is_deduped_within_the_window():
    for _ in range(3):  # same signal delivered 3×
        main.buffer_signal(mk(1))
    assert len(main.WINDOW_BUFFER) == 1
    assert len(main._BUFFERED_IDS) == 1


def test_an_evicted_signal_is_not_falsely_deduped_after_overflow():
    # signal 0 is evicted once the buffer overflows; if its stale id lingered in the
    # dedup set, a genuine redelivery would be wrongly dropped. Lockstep prevents that.
    for i in range(main.WINDOW_BUFFER.maxlen + 1):
        main.buffer_signal(mk(i))
    evicted = str(mk(0).signal_id)
    assert evicted not in main._BUFFERED_IDS, "evicted signal's id must leave the dedup set"
    before = len(main.WINDOW_BUFFER)
    main.buffer_signal(mk(0))  # redelivery of the evicted signal
    # It re-enters (not falsely deduped); buffer stays at maxlen (one more eviction).
    assert str(mk(0).signal_id) in main._BUFFERED_IDS
    assert len(main.WINDOW_BUFFER) == before == main.WINDOW_BUFFER.maxlen


def test_prune_ages_out_old_signals_and_their_ids():
    old = mk(1, ts=T0)
    fresh_ts = T0 + timedelta(seconds=main.ENGINE_CFG.window_s + 10_000)
    fresh = mk(2, ts=fresh_ts)
    main.buffer_signal(old)
    main.buffer_signal(fresh)
    main._prune_buffer(fresh_ts)
    ids = {str(s.signal_id) for s in main.WINDOW_BUFFER}
    assert str(old.signal_id) not in ids, "aged-out signal pruned from buffer"
    assert str(old.signal_id) not in main._BUFFERED_IDS, "aged-out id pruned from dedup set"
    assert str(fresh.signal_id) in main._BUFFERED_IDS
    # Invariant after pruning: dedup set and buffer agree exactly.
    assert len(main._BUFFERED_IDS) == len(main.WINDOW_BUFFER)
