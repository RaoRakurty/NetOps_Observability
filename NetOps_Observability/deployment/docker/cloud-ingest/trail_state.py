"""CloudTrail checkpoint core — pure, no boto3/kafka (same pattern as seam_state.py).

The bug this fixes (#105 side-find, seen live 2026-07-14): the poller advanced
`trail_ts` only when a cycle PRODUCED events, and only over MATCHED timestamps.
During quiet periods every visible event is excluded chatter (SSM heartbeats
etc.), so the checkpoint never moved, the lookup window grew without bound and
every cycle burned the full 20-page ceiling re-reading the same noise
("cloudtrail page ceiling hit" logged EVERY cycle).

The rule: a checkpoint may advance over anything we have SEEN, matched or not.
"""
from __future__ import annotations

# CloudTrail delivers management events to lookup_events minutes late (~10 min
# observed, AWS documents up to 15). When a window comes back EMPTY we still
# advance — but never into that delivery blind spot, or a late-arriving change
# event (exactly the evidence an RCA needs) is silently dropped forever.
DELIVERY_LAG_S = 900.0


def advance_checkpoint(start: float, newest_seen: float, saw_events: bool, now: float) -> float:
    """Next trail_ts after a poll cycle. Never regresses.

    - saw_events: anchor on the newest EventTime SEEN this cycle (matched or
      excluded — visible means safe to move past).
    - empty window: anchor on now - DELIVERY_LAG_S, so quiet periods re-scan at
      most the delivery-lag window (1 page) instead of an ever-growing one.
    """
    return advance_checkpoint_any(start, newest_seen, saw_events, now - DELIVERY_LAG_S)


def advance_checkpoint_any(start, newest_seen, saw_events: bool, lagged_now):
    """Ordering-generic checkpoint advance — same rule for epoch-seconds,
    epoch-millis and ISO-8601 string lanes (each lane passes its own
    delivery-lagged 'now' in ITS units/format). The audit that followed the
    trail_ts fix found the identical matched-only defect in the Azure activity
    and GCP audit lanes, and an empty-window pin in the CloudWatch flow lane —
    one rule now serves them all: advance over anything SEEN; an empty window
    advances to the lagged now; never regress.
    """
    if saw_events:
        return max(start, newest_seen)
    return max(start, lagged_now)
