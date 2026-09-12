# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""UNKNOWN is never PASS — the settle and hollow-completion gates (ultra #23/#24).

Two 2026-08-31 fixes, each with the false green it kills:

  #23  the stability phase's lag-settle loop read `group_lag` `_total: -1`
       (the describe FAILED — an unreadable group, not a lag value) and, since
       two consecutive -1 readings are byte-identical, counted them as "lag
       stopped moving": a group the harness never actually read settled as
       STABLE, and the phase could then PASS on clean logs alone.
  #24  correlation_completion's hollow-completion clause computed
       `cohorts_delta` from `cohorts_total` with unreadable mapped to -1; the
       delta then landed in the `<= 0` "drained nothing to judge" continue and
       the clause was silently SKIPPED on exactly the replica it cannot vouch
       for — tracker-170's own rule ("an unreadable counter is UNKNOWN, which
       is never PASS") violated inside its own gate.

Run:  python3 -m pytest tests/test_miniladder_unknown_gates.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_harness():
    """Import the hyphen-named harness by path; the import must not touch PATH
    (same discipline as every other miniladder suite)."""
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_unknown", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_unknown"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()
H = ml.Harness


# ═══════════════════════════════════════════════════════════════════════════
# ultra #23 — the pure settle arithmetic
# ═══════════════════════════════════════════════════════════════════════════
def _drive(totals, epsilon=50):
    last, stable = None, 0.0
    steps = []
    for total in totals:
        last, stable, readable = H.settle_step(last, total, stable, epsilon)
        steps.append((last, stable, readable))
    return last, stable, steps


def test_THE_bug_two_unreadable_reads_never_settle():
    """-1 == -1 must never read as 'lag stopped moving'."""
    last, stable, steps = _drive([-1, -1, -1, -1])
    assert stable == 0.0, "an unreadable group accumulated stability"
    assert last is None
    assert all(readable is False for _l, _s, readable in steps)


def test_an_unreadable_poll_invalidates_the_previous_real_reading():
    """100, -1, 100 is NOT accumulated stability: the group vanished from view
    in between, so settlement must be re-established by consecutive reads."""
    last, stable, _steps = _drive([100, -1, 100])
    assert stable == 0.0
    assert last == 100


def test_real_stable_readings_still_accumulate():
    last, stable, _steps = _drive([100, 120, 100])       # epsilon 50
    assert stable == 30.0 and last == 100


def test_movement_beyond_epsilon_resets():
    last, stable, _steps = _drive([100, 100, 400])
    assert stable == 0.0 and last == 400


def test_settle_lag_problems_names_the_unreadable_source():
    for lag in (None, -1, -1.0):
        problems = H.settle_lag_problems(lag, 3)
        assert len(problems) == 1
        problem = problems[0]
        assert "UNREADABLE" in problem and "netops-correlation" in problem
        assert "UNKNOWN is never PASS" in problem
        assert "3 unreadable poll(s)" in problem


def test_settle_lag_problems_accepts_a_real_lag_including_zero():
    assert H.settle_lag_problems(0, 0) == []
    assert H.settle_lag_problems(151234, 0) == []
    # a transient unreadable poll that RECOVERED into a real reading is
    # survivable; only ending unreadable is UNKNOWN
    assert H.settle_lag_problems(10, 5) == []


# ═══════════════════════════════════════════════════════════════════════════
# ultra #23 — stability() end to end, over a scripted lag series
# ═══════════════════════════════════════════════════════════════════════════
CLEAN_LOG = "INFO correlation started\nINFO rebalance #1: assignment=...\n"


class _StabilityRunner:
    """Only what `Harness.stability` touches, against a scripted group_lag."""

    collect_stability_blobs = ml.Harness.collect_stability_blobs
    stability_counters = staticmethod(ml.Harness.stability_counters)
    session_timeout_from_replicas = staticmethod(
        ml.Harness.session_timeout_from_replicas)
    stability_verdict = staticmethod(ml.Harness.stability_verdict)
    settle_step = staticmethod(ml.Harness.settle_step)
    settle_lag_problems = staticmethod(ml.Harness.settle_lag_problems)

    def __init__(self, totals):
        self.phases: list[dict] = []
        self.stability_t0 = 0.0
        self.args = type("A", (), {"lag_epsilon": 50})()
        self._totals = list(totals)
        outer = self

        class _Stack:
            def group_lag(self, _group):
                return {"_total": (outer._totals.pop(0)
                                   if len(outer._totals) > 1
                                   else outer._totals[0])}

            def cids(self, _service):
                return ["r1"]

            def corr_replicas(self):
                return [{"container": "r1",
                         "metrics": {ml.SESSION_TIMEOUT_GAUGE: 45000.0}}]

        self.stack = _Stack()

    def phase(self, name, status, evidence, notes=""):
        self.phases.append({"phase": name, "status": status,
                            "evidence": evidence, "notes": notes})
        return status == "PASS"

    @property
    def last(self):
        return self.phases[-1]

    def go(self, monkeypatch):
        monkeypatch.setattr(ml.time, "sleep", lambda _s: None)
        ticks = iter(range(0, 10_000_000, 11))
        monkeypatch.setattr(ml.time, "monotonic", lambda: float(next(ticks)))
        monkeypatch.setattr(ml, "run", lambda cmd, timeout: (0, CLEAN_LOG, ""))
        monkeypatch.setattr(ml, "KAFKA_SESSION_TIMEOUT_OVERRIDE_MS", None)
        return ml.Harness.stability(self)


def test_INTEGRATION_an_unreadable_lag_fails_stability(monkeypatch):
    """THE regression: every poll answers -1 and the logs are CLEAN — the old
    loop settled on the -1s and the phase PASSED with zero evidence of lag."""
    r = _StabilityRunner([-1])
    assert r.go(monkeypatch) is False
    assert r.last["status"] == "FAIL"
    assert "UNREADABLE at settlement" in r.last["notes"]
    assert "UNKNOWN is never PASS" in r.last["notes"]
    assert r.last["evidence"]["settled"] is False
    assert r.last["evidence"]["lag_at_settlement"] == -1
    assert r.last["evidence"]["lag_unreadable_polls"] > 0


def test_INTEGRATION_a_readable_settled_run_still_passes(monkeypatch):
    """The gate must not become unpassable — that is its own false signal."""
    r = _StabilityRunner([100, 100, 100, 100, 100])
    assert r.go(monkeypatch) is True, r.last["notes"]
    assert r.last["evidence"]["settled"] is True
    assert r.last["evidence"]["lag_unreadable_polls"] == 0


def test_INTEGRATION_a_transient_unreadable_poll_that_recovers_passes(monkeypatch):
    """-1 mid-window is survivable when REAL consecutive readings re-establish
    settlement afterwards; only ENDING unreadable is UNKNOWN."""
    r = _StabilityRunner([-1, 100, 100, 100, 100])
    assert r.go(monkeypatch) is True, r.last["notes"]
    assert r.last["evidence"]["lag_unreadable_polls"] == 1
    assert r.last["evidence"]["settled"] is True


# ═══════════════════════════════════════════════════════════════════════════
# ultra #24 — hollow completion cannot be bypassed by an unreadable counter
# ═══════════════════════════════════════════════════════════════════════════
R1, R2 = "02f0c701526a", "182088270d24"
START1, START2 = "2026-08-29T01:16:03.100000000Z", "2026-08-29T01:16:07.900000000Z"


def _replica(started, *, pending=0.0, cohorts=0.0, persisted=0.0, drop=()):
    row = {"started_at": started, "pending": pending, "cohorts_total": cohorts,
           "oldest_pending_age_s": 0.0, "epochs_total": 12.0,
           "window_signals": 50000.0, "windows_rejected": 0.0,
           "profiler_errors": 0.0, "versions_persisted": persisted,
           "versions_damped": 0.0, "signals_dropped_window_rejected": 0.0}
    # `drop` models a counter the aggregator could not read: -1.0 == UNKNOWN,
    # exactly what corr_completion_state records for an absent metric.
    for key in drop:
        row[key] = -1.0
    return row


def _state(r1: dict, r2: dict) -> dict:
    per = {R1: r1, R2: r2}
    return {"replicas": 2, "readable": 2, "unreadable": [], "errors": [],
            "pending_sum": sum(v["pending"] for v in per.values()),
            "oldest_pending_age_max": max(v["oldest_pending_age_s"]
                                          for v in per.values()),
            # the real aggregator floors unreadable at 0 for the SUM
            "cohorts_sum": sum(max(v["cohorts_total"], 0.0)
                               for v in per.values()),
            "per_replica": per}


BASELINE = _state(_replica(START1), _replica(START2))


class _CompletionRunner:
    """Only what `Harness.correlation_completion` touches (the shape
    tests/test_completion_hollow_20260829.py pins)."""

    _corr_mem_track = ml.Harness._corr_mem_track

    def __init__(self, states, baseline=BASELINE):
        self.phases: list[dict] = []
        self.baseline = {"corr_completion": baseline}
        self.burst_seconds = 720.0
        self.args = type("A", (), {"drain_factor": 3.0})()
        self.corr_mem_track: dict = {}
        self._states = list(states)
        outer = self

        class _Stack:
            def corr_completion_state(self):
                return (outer._states.pop(0) if len(outer._states) > 1
                        else outer._states[0])

        self.stack = _Stack()

    def phase(self, name, status, evidence, notes=""):
        self.phases.append({"phase": name, "status": status,
                            "evidence": evidence, "notes": notes})
        return status == "PASS"

    def evidence_file(self, name, content):
        return name

    @property
    def last(self):
        return self.phases[-1]

    def go(self, monkeypatch):
        monkeypatch.setattr(ml.time, "sleep", lambda _s: None)
        ticks = iter(range(0, 10_000_000, 11))
        monkeypatch.setattr(ml.time, "monotonic", lambda: float(next(ticks)))
        return ml.Harness.correlation_completion(self)


def test_THE_bug_unreadable_final_cohorts_total_cannot_pass(monkeypatch):
    """A healthy partner used to carry the run while the unreadable replica was
    silently EXEMPTED from the hollow-completion clause (its -1 delta hit the
    'drained nothing to judge' continue)."""
    final = _state(_replica(START1, cohorts=16, persisted=940),
                   _replica(START2, cohorts=15, persisted=880,
                            drop=("cohorts_total",)))
    r = _CompletionRunner([final])
    assert r.go(monkeypatch) is False, (
        "an unreadable cohorts_total bypassed the hollow-completion clause")
    assert "cohorts_total is unreadable" in r.last["notes"]
    assert "UNKNOWN is never PASS" in r.last["notes"]
    assert R2 in r.last["notes"], "the problem must NAME the replica"


def test_an_unreadable_BASELINE_cohorts_total_cannot_pass(monkeypatch):
    """The baseline half of the delta is evidence too: unreadable-at-preflight
    used to be silently treated as 0."""
    baseline = _state(_replica(START1),
                      _replica(START2, drop=("cohorts_total",)))
    final = _state(_replica(START1, cohorts=16, persisted=940),
                   _replica(START2, cohorts=15, persisted=880))
    r = _CompletionRunner([final], baseline=baseline)
    assert r.go(monkeypatch) is False
    assert "cohorts_total is unreadable" in r.last["notes"]
    assert R2 in r.last["notes"]


def test_a_fully_readable_productive_run_still_passes(monkeypatch):
    """The gate must not become unpassable — that is its own false signal."""
    final = _state(_replica(START1, cohorts=16, persisted=940),
                   _replica(START2, cohorts=15, persisted=880))
    r = _CompletionRunner([final])
    assert r.go(monkeypatch) is True, r.last["notes"]


def test_the_hollow_clause_still_fires_on_readable_counters(monkeypatch):
    """The #24 guard must not swallow the clause it protects: readable cohorts
    with nothing persisted is still HOLLOW COMPLETION."""
    final = _state(_replica(START1, cohorts=16, persisted=940),
                   _replica(START2, cohorts=15, persisted=0))
    r = _CompletionRunner([final])
    assert r.go(monkeypatch) is False
    assert "HOLLOW COMPLETION" in r.last["notes"] and R2 in r.last["notes"]
