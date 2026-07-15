"""CloudTrail checkpoint tests — run with: python3 -m pytest test_trail_state.py

Pins the regression: the checkpoint must advance over EXCLUDED chatter too
(SSM heartbeats pinned trail_ts and burned the 20-page ceiling every cycle),
and an empty window must advance without ever entering the delivery-lag
blind spot (late-delivered change events must never be skipped).
"""
from trail_state import DELIVERY_LAG_S, advance_checkpoint, advance_checkpoint_any

NOW = 1_800_000_000.0


def test_seen_events_advance_even_when_none_matched():
    # A cycle full of excluded SSM chatter still moves the mark to the newest
    # timestamp seen — the exact case that used to pin the checkpoint forever.
    start = NOW - 3600
    newest_seen = NOW - 120
    assert advance_checkpoint(start, newest_seen, True, NOW) == newest_seen


def test_empty_window_advances_to_lagged_now():
    # No events at all: advance to now - delivery lag, so the re-scan window
    # stays bounded at one page instead of growing without limit.
    start = NOW - 7200
    assert advance_checkpoint(start, start, False, NOW) == NOW - DELIVERY_LAG_S


def test_empty_window_never_regresses_a_fresh_checkpoint():
    # A checkpoint already inside the lag window must not move BACKWARD —
    # that would re-produce events already sent.
    start = NOW - 60
    assert advance_checkpoint(start, start, False, NOW) == start


def test_seen_events_never_regress():
    # Clock skew / stale page: an older-than-start "newest" must not rewind.
    start = NOW - 100
    assert advance_checkpoint(start, start - 500, True, NOW) == start


def test_generic_core_works_for_iso_string_lanes():
    # Azure activity / GCP audit checkpoints are ISO-8601 strings; the same
    # rule must hold under lexicographic ordering.
    since = "2026-07-15T00:00:00Z"
    newest = "2026-07-15T01:30:00Z"
    lagged = "2026-07-15T02:45:00Z"
    # seen (matched or excluded) → newest wins
    assert advance_checkpoint_any(since, newest, True, lagged) == newest
    # empty window → lagged now wins
    assert advance_checkpoint_any(since, since, False, lagged) == lagged
    # fresh checkpoint never regresses to an older lagged-now
    assert advance_checkpoint_any("2026-07-15T03:00:00Z", "2026-07-15T03:00:00Z",
                                  False, lagged) == "2026-07-15T03:00:00Z"


def test_generic_core_works_for_millisecond_lanes():
    # CloudWatch flow lane keeps epoch-millis; units ride through untouched.
    start_ms = (NOW - 3600) * 1000
    lagged_ms = (NOW - 900) * 1000
    assert advance_checkpoint_any(start_ms, start_ms, False, lagged_ms) == lagged_ms
    assert advance_checkpoint_any(start_ms, (NOW - 60) * 1000, True, lagged_ms) == (NOW - 60) * 1000
