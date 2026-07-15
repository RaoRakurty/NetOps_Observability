"""CloudTrail checkpoint tests — run with: python3 -m pytest test_trail_state.py

Pins the regression: the checkpoint must advance over EXCLUDED chatter too
(SSM heartbeats pinned trail_ts and burned the 20-page ceiling every cycle),
and an empty window must advance without ever entering the delivery-lag
blind spot (late-delivered change events must never be skipped).
"""
from trail_state import DELIVERY_LAG_S, advance_checkpoint

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
