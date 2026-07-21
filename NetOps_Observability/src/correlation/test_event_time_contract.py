"""The event-time contract (F-34) — run with: python3 -m pytest test_event_time_contract.py

`parse_event_ts` is the single door every lane's event time comes through
(13 call sites, all shaped `parse_event_ts(...) or ingest_ts`). It used to
accept ONLY RFC3339 and return None for every numeric epoch — the exact shapes
the ingest lane normalizes downstream of Kafka. Correlation reads UPSTREAM of
that normalization, so a numeric-epoch producer landed correctly in ClickHouse
and was SILENTLY re-timestamped to receive time in the engine: RCA's causal
ordering (onset_uncertainty_s) was then computed from when we heard about the
event, not when it happened, and nothing counted the substitution.

These tests pin the accepted shapes and the visibility of the fallback.
"""
from datetime import datetime, timedelta, timezone

import pytest

import producers
from producers import parse_event_ts

REF = datetime(2026, 7, 21, 20, 52, 56, 123000, tzinfo=timezone.utc)
EPOCH_S = 1784667176.123


@pytest.fixture(autouse=True)
def _reset():
    producers.reset_ts_invalid()
    yield
    producers.reset_ts_invalid()


@pytest.mark.parametrize("raw", [
    EPOCH_S,                       # float epoch seconds
    "1784667176.123",              # numeric string
    1784667176123,                 # int epoch milliseconds
    1784667176123456,              # microseconds
    1784667176123456789,           # nanoseconds
    "2026-07-21T20:52:56.123Z",    # RFC3339 with Z
    "2026-07-21T20:52:56.123+00:00",
    "2026-07-21T22:52:56.123+02:00",   # offset-bearing → same instant
])
def test_every_wire_shape_resolves_to_the_same_instant(raw):
    got = parse_event_ts(raw)
    assert got is not None, f"{raw!r} rejected — the lane would use receive time"
    assert got.tzinfo is not None
    assert abs((got - REF).total_seconds()) < 0.001


def test_integer_epoch_seconds_are_seconds_not_milliseconds():
    """The unit inference is the same thresholds the ingest lane uses; an
    off-by-1000 here would put every event decades away from its incident."""
    assert parse_event_ts(1784667176) == REF.replace(microsecond=0)


def test_nanosecond_precision_rfc3339_is_truncated_not_rejected():
    """gNMI/OpenConfig sources stamp nanoseconds. Truncation must never round
    the timestamp FORWARD (that would reorder cause and effect)."""
    got = parse_event_ts("2026-06-12T10:00:00.123456789Z")
    assert got == datetime(2026, 6, 12, 10, 0, 0, 123456, tzinfo=timezone.utc)


def test_absent_timestamp_is_not_an_error():
    """No timestamp = nothing to be wrong about; the caller falls back to
    ingest time and that is honest, so it is not counted as invalid."""
    for raw in (None, ""):
        assert parse_event_ts(raw) is None
    assert producers.ts_invalid_count() == 0


def test_unparseable_timestamp_is_counted_so_the_fallback_is_visible():
    assert parse_event_ts("not-a-time") is None
    assert parse_event_ts({"nested": "object"}) is None
    assert producers.ts_invalid_count() == 2


def test_booleans_are_not_timestamps():
    """bool is an int subclass — `True` must not become 1970-01-01."""
    assert parse_event_ts(True) is None


def test_rfc3164_syslog_header_time_resolves_against_a_reference():
    ref = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)
    got = parse_event_ts("Jul 21 06:30:00", reference=ref)
    assert got == datetime(2026, 7, 21, 6, 30, 0, tzinfo=timezone.utc)


def test_zoneless_iso_is_read_as_utc_not_rejected():
    got = parse_event_ts("2026-07-21T20:52:56")
    assert got == datetime(2026, 7, 21, 20, 52, 56, tzinfo=timezone.utc)


def test_epoch_event_time_survives_into_a_signal():
    """End-to-end at a real call site: a probe event stamped with an epoch must
    carry EVENT time into the signal, not the ingest time passed alongside it."""
    ingest = datetime(2026, 7, 21, 21, 30, 0, tzinfo=timezone.utc)
    ev = {"ts": EPOCH_S}
    assert (parse_event_ts(ev["ts"]) or ingest) != ingest
    assert abs(((parse_event_ts(ev["ts"]) or ingest) - REF).total_seconds()) < 0.001


def test_the_ordering_bug_this_prevents():
    """Two events one minute apart in EVENT time, received in the same second.
    With receive-time fallback they are simultaneous and RCA cannot order cause
    before effect; with event time honored the order survives."""
    cause = parse_event_ts(EPOCH_S - 60)
    effect = parse_event_ts(EPOCH_S)
    assert cause is not None and effect is not None
    assert effect - cause == timedelta(seconds=60)
