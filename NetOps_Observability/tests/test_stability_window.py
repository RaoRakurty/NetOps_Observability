"""The stability gate must observe the WHOLE lifecycle, not just the drain.

THE FALSE GREEN THIS REPLACES (2026-08-20). Stability was diagnosed only inside
`if drained_at is None:` — a PASSING drain collected no evidence at all — from
`docker logs --since <burst+drain>` on a SINGLE replica. Run 08192339borh
reported commit_failed=0 while three CommitFailedError events occurred at
00:01:34, 00:04:42 and 00:08:15, after the window closed, on a replica the
diagnosis never read.

Three independent ways it lied, each pinned below:
  1. the window ended with drain          -> late failures invisible
  2. only one replica was inspected       -> the other reported clean unread
  3. it only ran when drain FAILED        -> a passing drain proved nothing
"""
from __future__ import annotations

import importlib.util
import os

import pytest

SPEC = importlib.util.spec_from_file_location(
    "scale_miniladder",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "scripts", "scale-miniladder.py"))
ml = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ml)

H = ml.Harness

CLEAN = "INFO correlation started\nINFO rebalance #1: assignment=...\n"
# A REAL aiokafka traceback: "CommitFailedError" appears on two lines, which is
# why the counter anchors on the reporting line instead of counting substrings.
LATE_COMMIT_FAIL = (
    "INFO drain finished\n"
    "    raise Errors.CommitFailedError(\n"
    "2026-08-20 00:04:42,929 aiokafka.errors.CommitFailedError: CommitFailedError: "
    "('Commit cannot be completed since the group has already rebalanced')\n"
)
STALL = "WARNING correlation event loop STALLED 8657ms (threshold 1000ms, stalls=104, worst=112802ms)\n"


def test_a_late_commit_failure_fails_the_gate():
    """THE REGRESSION TEST: this exact event was reported as commit_failed=0."""
    counters = H.stability_counters({"c1": CLEAN + LATE_COMMIT_FAIL})
    assert counters["commit_failed"] == 1
    problems = H.stability_verdict(counters, 30000)
    assert problems, "a late CommitFailedError must fail the stability gate"
    assert any("CommitFailedError" in p for p in problems)


def test_a_clean_lifecycle_passes():
    counters = H.stability_counters({"c1": CLEAN, "c2": CLEAN})
    assert H.stability_verdict(counters, 30000) == []


def test_every_replica_is_counted_not_just_the_first():
    """cid() returns one container; the old diagnosis never read replica 2."""
    counters = H.stability_counters({"c1": CLEAN, "c2": CLEAN + LATE_COMMIT_FAIL})
    assert counters["commit_failed"] == 1, "the second replica's failure was missed"
    assert counters["replicas_observed"] == 2
    assert H.stability_verdict(counters, 30000)


def test_unreadable_replica_logs_are_incomplete_not_clean():
    """Missing evidence must never read as PASS."""
    counters = H.stability_counters({"c1": CLEAN, "c2": None})
    assert counters["replicas_unreadable"] == 1
    problems = H.stability_verdict(counters, 30000)
    assert any("unreadable" in p for p in problems)


def test_no_readable_logs_at_all_is_unknown_not_pass():
    counters = H.stability_counters({"c1": None})
    problems = H.stability_verdict(counters, 30000)
    assert any("UNKNOWN" in p or "unreadable" in p for p in problems)
    assert problems, "zero observed replicas cannot be a PASS"


def test_a_stall_beyond_the_session_timeout_fails():
    """A 112s stall is past the 30s session timeout — the member can be ejected."""
    counters = H.stability_counters({"c1": STALL})
    assert counters["worst_loop_lag_ms"] == 112802
    problems = H.stability_verdict(counters, 30000)
    assert any("EXCEEDS" in p for p in problems)


def test_a_stall_below_the_session_timeout_does_not_fail_on_its_own():
    counters = H.stability_counters(
        {"c1": "WARNING event loop STALLED 1200ms (stalls=3, worst=1900ms)\n"})
    assert counters["worst_loop_lag_ms"] == 1900
    assert H.stability_verdict(counters, 30000) == []


def test_worst_stall_is_the_max_across_replicas():
    counters = H.stability_counters({
        "c1": "worst=5000ms\n",
        "c2": "worst=112802ms\n",
    })
    assert counters["worst_loop_lag_ms"] == 112802


@pytest.mark.parametrize("marker,key", [
    ("aiokafka.errors.UnknownMemberIdError: x", "unknown_member"),
    ("consumer failed; restarting", "consumer_restarts"),
])
def test_each_instability_marker_is_counted_and_fails(marker, key):
    counters = H.stability_counters({"c1": f"ERROR {marker}\n"})
    assert counters[key] == 1
    assert H.stability_verdict(counters, 30000)


def test_rebalances_are_recorded_but_not_alone_disqualifying():
    """A rebalance is expected on deploy; it is evidence, not a verdict."""
    counters = H.stability_counters({"c1": "INFO rebalance #3: assignment=...\n"})
    assert counters["rebalances"] == 1
    assert H.stability_verdict(counters, 30000) == []


def test_the_observation_covers_the_post_drain_window_by_construction():
    """The grace period must be long enough to contain the observed failures.

    The three real events landed up to ~4 minutes after drain ended.
    """
    assert ml.STABILITY_GRACE_S >= 120, (
        "the grace window must outlast the gap in which the 2026-08-20 failures "
        "appeared, or the gate reintroduces its own blind spot")
    assert ml.STABILITY_SETTLE_MAX_S >= 300


def test_one_traceback_counts_as_one_event():
    """A real aiokafka traceback names CommitFailedError twice; that is ONE
    event. Over-counting fails safe but makes the number useless for judging
    whether a fix worked."""
    counters = H.stability_counters({"c1": LATE_COMMIT_FAIL})
    assert counters["commit_failed"] == 1


def test_three_tracebacks_count_as_three():
    counters = H.stability_counters({"c1": LATE_COMMIT_FAIL * 3})
    assert counters["commit_failed"] == 3


# --- the collection itself, not just the counters --------------------------
#
# X1/X2 survived mutation until these existed: the pure counters cannot see
# how wide the window is or how many replicas were read, and those were the
# two original defects.

class _FakeStack:
    def __init__(self, ids):
        self._ids = ids
    def cids(self, _service):
        return list(self._ids)


def _harness_with(monkeypatch, ids, calls):
    h = object.__new__(H)
    h.stack = _FakeStack(ids)
    h.stability_t0 = 1000.0

    def fake_run(cmd, timeout, *a, **k):
        calls.append(cmd)
        return 0, "INFO clean\n", ""

    monkeypatch.setattr(ml, "run", fake_run)
    return h


def test_the_window_spans_from_burst_start_not_from_drain_end(monkeypatch):
    """THE ORIGINAL BLIND SPOT: a window that starts at drain-end cannot contain
    a failure that happened during the burst, and one that is only seconds wide
    cannot contain one that happened minutes ago."""
    calls = []
    h = _harness_with(monkeypatch, ["c1"], calls)
    # 1800s of wall clock have passed since the burst began.
    blobs, since = h.collect_stability_blobs(now=1000.0 + 1800.0)
    assert since >= 1800, (
        f"observation window is only {since}s — it must reach back to the start "
        "of the burst, or late failures fall outside it")
    assert any("--since" in c and f"{since}s" in c for c in calls)


def test_every_replica_is_read(monkeypatch):
    calls = []
    h = _harness_with(monkeypatch, ["c1", "c2", "c3"], calls)
    blobs, _ = h.collect_stability_blobs(now=1100.0)
    assert set(blobs) == {"c1", "c2", "c3"}, (
        "cid() returns one container; reading only it reports the others clean "
        "by never looking")
    assert len([c for c in calls if "logs" in c]) == 3


def test_an_unreadable_replica_maps_to_none(monkeypatch):
    def fake_run(cmd, timeout, *a, **k):
        return (1, "", "no such container") if "c2" in cmd else (0, "INFO ok\n", "")
    monkeypatch.setattr(ml, "run", fake_run)
    h = object.__new__(H)
    h.stack = _FakeStack(["c1", "c2"])
    h.stability_t0 = 0.0
    blobs, _ = h.collect_stability_blobs(now=100.0)
    assert blobs["c2"] is None
    counters = H.stability_counters(blobs)
    assert counters["replicas_unreadable"] == 1
    assert H.stability_verdict(counters, 30000)


def test_no_replicas_found_at_all_cannot_pass():
    """An empty blob set means we observed nothing — not that nothing happened."""
    counters = H.stability_counters({})
    assert counters["replicas_observed"] == 0
    problems = H.stability_verdict(counters, 30000)
    assert problems, "observing zero replicas must never be a PASS"
