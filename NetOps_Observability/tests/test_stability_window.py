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
    _blobs, since = h.collect_stability_blobs(now=1000.0 + 1800.0)
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


# ── TRACKER 190: the stall threshold is READ from the engine, never assumed ──
#
# THE DEFECT. `stability_verdict`'s one arithmetic clause compared the worst
# observed event-loop stall against a constant hard-coded in the harness —
# 30000 ms — while the engine has run CORR_SESSION_TIMEOUT_MS=60000 since the
# P1 max-poll-thrash work. The gate was measuring a stale COPY of the engine's
# group-membership contract. The drift happened to be conservative; the next one
# need not be, and a threshold nobody publishes cannot be audited either way.
#
# The engine now exports `corr_session_timeout_ms`; the harness reads it off
# every replica it already scrapes, and refuses (UNKNOWN, which is not PASS)
# when the replicas disagree or the gauge is absent.

def _rep(cid, timeout_ms=None):
    """A SCRAPED replica, shaped exactly like `Stack.corr_replicas()` returns.

    `timeout_ms=None` = an engine that answered /metrics but does not export the
    gauge (an image older than tracker 190) — which is NOT the same thing as a
    replica that could not be scraped at all (`_unreadable`).
    """
    m = {"corr_engine_pending": 0.0}
    if timeout_ms is not None:
        m["corr_session_timeout_ms"] = float(timeout_ms)
    return {"container": cid, "name": f"netops-{cid}", "ip": "172.18.0.9",
            "started_at": "2026-08-30T00:00:00Z", "rss": 1, "metrics": m}


def _unreadable(cid):
    return {"container": cid, "name": f"netops-{cid}",
            "error": "metrics probe failed"}


def test_the_live_session_timeout_is_read_from_the_replicas():
    """THE REGRESSION TEST: engine at 60000, harness must use 60000."""
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000), _rep("c2", 60000)])
    assert v == 60000, (
        "the harness hard-coded 30000 while the engine ran 60000 — the gate "
        "must take the threshold from the engine, not from a constant")
    assert "60000ms" in why and "2 replica(s)" in why


def test_a_45s_stall_does_not_fail_a_60s_engine():
    """THE MUTANT KILLER. Re-hard-coding 30000 makes this stall disqualifying;
    against the engine's real 60000ms contract the broker keeps the member."""
    counters = H.stability_counters(
        {"c1": "WARNING correlation event loop STALLED 900ms "
               "(threshold 1000ms, stalls=1, worst=45000ms)\n"})
    assert counters["worst_loop_lag_ms"] == 45000
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000)])
    assert H.stability_verdict(counters, v, why) == [], (
        "45000ms is inside the engine's 60000ms session timeout; failing it "
        "means the threshold came from somewhere other than the engine")
    assert H.stability_verdict(counters, 30000, "hard-coded"), (
        "sanity: the same stall MUST fail against a 30000ms contract")


def test_a_stall_past_the_live_timeout_still_fails():
    counters = H.stability_counters(
        {"c1": "WARNING event loop STALLED 1ms (threshold 1000ms, worst=61000ms)\n"})
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000)])
    problems = H.stability_verdict(counters, v, why)
    assert problems and "60000ms" in problems[0]


def test_replicas_that_disagree_are_refused():
    """A half-rolled deploy: guessing which member the stall belonged to is
    exactly the assumption this exists to remove."""
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000), _rep("c2", 30000)])
    assert v is None
    assert "DISAGREE" in why and "c1=60000ms" in why and "c2=30000ms" in why
    # An otherwise SPOTLESS run: the only thing wrong is that the threshold is
    # unknown, and that alone must deny the PASS.
    problems = H.stability_verdict(H.stability_counters({"c1": CLEAN}), v, why)
    assert [p for p in problems if "session timeout is UNKNOWN" in p], (
        "UNKNOWN is not PASS")


def test_an_absent_gauge_is_refused_not_defaulted():
    """An engine image older than the gauge. Falling back to a constant is the
    original defect; the run must say the threshold is unknown."""
    v, why = H.session_timeout_from_replicas([_rep("c1"), _rep("c2")])
    assert v is None
    assert "corr_session_timeout_ms absent from all 2" in why
    problems = H.stability_verdict(H.stability_counters({"c1": CLEAN}), v, why)
    assert [p for p in problems if "session timeout is UNKNOWN" in p]


def test_a_partially_absent_gauge_is_refused():
    """One replica on the new image, one on the old: the group's real eviction
    point is not established by the half that answered."""
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000), _rep("c2")])
    assert v is None
    assert "absent from 1 of 2" in why and "60000ms" in why


def test_unreadable_replicas_cannot_supply_the_threshold():
    v, why = H.session_timeout_from_replicas([_unreadable("c1")])
    assert v is None
    assert "none of 1 replica(s) could be scraped" in why


def test_no_replicas_at_all_is_unknown():
    v, why = H.session_timeout_from_replicas([])
    assert v is None
    assert "no correlation replica was read" in why


def test_the_env_override_wins_and_says_so():
    """The override survives — but as an OVERRIDE with a stated derivation, not
    as a silent default that can contradict the running engine unnoticed."""
    v, why = H.session_timeout_from_replicas([_rep("c1", 60000)], override=20000)
    assert v == 20000
    assert why.startswith("override MLX_KAFKA_SESSION_TIMEOUT_MS=20000ms")
    assert "60000ms" in why, "the override must still report what was observed"


def test_the_override_works_when_the_gauge_is_absent():
    """The stated escape hatch for an old engine image: explicit, and audited."""
    v, why = H.session_timeout_from_replicas([_rep("c1")], override=30000)
    assert v == 30000
    assert "absent" in why
    counters = H.stability_counters(
        {"c1": "WARNING event loop STALLED 1ms (threshold 1000ms, worst=29999ms)\n"})
    assert H.stability_verdict(counters, v, why) == []


def test_the_override_default_is_none_not_a_number():
    """"Nobody told us" must be distinguishable from "somebody said 30000", or
    the refusal path can never fire."""
    assert ml.KAFKA_SESSION_TIMEOUT_OVERRIDE_MS is None, (
        "MLX_KAFKA_SESSION_TIMEOUT_MS is unset in this process; a non-None "
        "default here is the hard-coded threshold coming back")
