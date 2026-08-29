"""2026-08-29 — a drained engine that produced NOTHING is not a completed run.

THE FALSE GREEN THIS KILLS (run p2-s012-08290116, /var/tmp/scale-runs). With the
opt-in stage profiler on, the correlation engine's own WORK ACCOUNTING raised
`ValueError: invalid literal for int() with base 10: ''` on every cycle — from
inside the cohort loop's `except ValueError: ... continue`. Every tenant's
snapshots were discarded, `_mark_processed` still advanced the frontier, and:

    pending           drained to 0        ✅ tracker 170's clause
    cohorts           advanced            ✅ tracker 170's clause
    oldest age        idle                ✅ tracker 170's clause
    objects produced  ZERO                — nothing asked

`correlation_completion` PASSED in 14 s on a run with no incidents at all.
Tracker 170 taught this gate that transport drain is not evaluation; this file
teaches it that DRAINING is not PRODUCING.

Two clauses are added, and each is proven load-bearing below:

  1. WINDOW REJECTIONS / PROFILER FAULTS — `corr_engine_windows_rejected_total`
     or `corr_engine_profiler_errors_total` rising on ANY replica during the run
     means evidence was discarded or the run's own numbers are incomplete.
  2. HOLLOW COMPLETION — a replica that drained cohorts must have advanced
     `corr_versions{outcome="persisted"}`. Cohorts consumed with nothing
     persisted is the exact signature of snapshots computed and thrown away.

Both read PER REPLICA (a sum would let a healthy replica mask a broken partner)
and treat a missing counter as UNKNOWN, which is never PASS.

Run:  python3 -m pytest tests/test_completion_hollow_20260829.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_hollow", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_hollow"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()

R1, R2 = "02f0c701526a", "182088270d24"
START1, START2 = "2026-08-29T01:16:03.100000000Z", "2026-08-29T01:16:07.900000000Z"


def _replica(started, *, pending=0.0, cohorts=0.0, age=0.0, persisted=0.0,
             damped=0.0, rejected=0.0, profiler_errors=0.0, dropped=0.0,
             drop=()):
    row = {
        "started_at": started, "pending": pending, "cohorts_total": cohorts,
        "oldest_pending_age_s": age, "epochs_total": 12.0,
        "window_signals": 50000.0,
        "windows_rejected": rejected, "profiler_errors": profiler_errors,
        "versions_persisted": persisted, "versions_damped": damped,
        "signals_dropped_window_rejected": dropped,
    }
    # `drop` models an engine image that does not export a counter at all: the
    # aggregator leaves it at -1.0 == UNKNOWN.
    for k in drop:
        row[k] = -1.0
    return row


def _state(r1: dict, r2: dict, replicas: int = 2) -> dict:
    per = {R1: r1, R2: r2}
    return {
        "replicas": replicas, "readable": len(per), "unreadable": [], "errors": [],
        "pending_sum": sum(v["pending"] for v in per.values()),
        "oldest_pending_age_max": max(v["oldest_pending_age_s"] for v in per.values()),
        "cohorts_sum": sum(v["cohorts_total"] for v in per.values()),
        "per_replica": per,
    }


# preflight: an idle engine that has produced nothing yet
BASELINE = _state(_replica(START1), _replica(START2))

# what a healthy run looks like at the end: drained, and it PRODUCED
HEALTHY = _state(_replica(START1, cohorts=16, persisted=940),
                 _replica(START2, cohorts=15, persisted=880))

# THE BUG: pending 0, ages idle, cohorts advanced on BOTH replicas — and not one
# object persisted, because every cohort's snapshots were discarded by the
# accounting fault. Every tracker-170 clause is satisfied.
HOLLOW = _state(_replica(START1, cohorts=16, persisted=0),
                _replica(START2, cohorts=15, persisted=0))


class _Runner:
    """A harness instance with only what the completion phase touches."""

    def __init__(self, states, baseline=BASELINE, burst_seconds=720.0):
        self.phases: list[dict] = []
        self.baseline = {"corr_completion": baseline}
        self.burst_seconds = burst_seconds
        self.run_dir = None
        self._states = list(states)
        self.args = type("A", (), {"drain_factor": 3.0})()
        self.stack = type("S", (), {
            "corr_completion_state": lambda _s: (
                self._states.pop(0) if len(self._states) > 1 else self._states[0])
        })()

    def phase(self, name, status, evidence, notes=""):
        self.phases.append({"phase": name, "status": status,
                            "evidence": evidence, "notes": notes})
        return status == "PASS"

    def evidence_file(self, name, content):
        return name

    def run(self):
        return ml.Harness.correlation_completion(self)

    @property
    def last(self):
        return self.phases[-1]


@pytest.fixture(autouse=True)
def _no_sleep_no_wall_clock(monkeypatch):
    monkeypatch.setattr(ml.time, "sleep", lambda _s: None)
    ticks = iter(range(0, 100_000, 11))
    monkeypatch.setattr(ml.time, "monotonic", lambda: float(next(ticks)))


# ── the negative control ─────────────────────────────────────────────────────


def test_THE_hollow_run_is_now_a_FAIL():
    """Run p2-s012-08290116, as its own metrics reported it."""
    r = _Runner([HOLLOW])
    assert r.run() is False
    assert "HOLLOW COMPLETION" in r.last["notes"]
    assert r.last["status"] == "FAIL"


def test_the_hollow_run_satisfies_EVERY_tracker_170_clause():
    """Proves the new clause is doing the work, not a pre-existing one: the
    fixture is idle, readable, unrestarted, and its cohorts advanced."""
    assert HOLLOW["pending_sum"] == 0
    assert HOLLOW["oldest_pending_age_max"] <= ml.CORR_IDLE_AGE_S
    assert HOLLOW["cohorts_sum"] > BASELINE["cohorts_sum"]
    assert HOLLOW["readable"] == HOLLOW["replicas"] == 2
    r = _Runner([HOLLOW])
    assert r.run() is False, (
        "a run that drained 31 cohorts and persisted zero objects was accepted "
        "as complete — this is the 14-second PASS on an empty run")


def test_a_genuinely_productive_run_still_passes():
    """The gate must not be unpassable — that would be its own false signal."""
    r = _Runner([HEALTHY])
    assert r.run() is True, r.last["notes"]
    assert r.last["status"] == "PASS"


# ── clause 2: HOLLOW COMPLETION, isolated ────────────────────────────────────


def test_ISOLATION_hollow_on_ONE_replica_only_must_fail():
    """Replica 1 produced 940 versions; replica 2 drained 15 cohorts and
    produced nothing. A SUM over replicas would call this healthy."""
    one_sided = _state(_replica(START1, cohorts=16, persisted=940),
                       _replica(START2, cohorts=15, persisted=0))
    assert one_sided["pending_sum"] == 0 and one_sided["cohorts_sum"] > 0
    r = _Runner([one_sided])
    assert r.run() is False, (
        "a productive replica masked a partner that persisted nothing")
    assert "HOLLOW COMPLETION" in r.last["notes"] and R2 in r.last["notes"]


def test_a_replica_that_drained_NOTHING_is_not_judged_hollow():
    """Precision, not just recall: a replica holding no partitions drains no
    cohorts, so it has nothing to have produced. Its partner carries the run."""
    idle_partner = _state(_replica(START1, cohorts=16, persisted=940),
                          _replica(START2, cohorts=0, persisted=0))
    r = _Runner([idle_partner])
    assert r.run() is True, (
        f"an idle replica was called hollow: {r.last['notes']}")


def test_an_UNREADABLE_persisted_counter_is_UNKNOWN_never_PASS():
    """An engine image too old to export the counter cannot prove it produced
    anything, and UNKNOWN is never PASS."""
    old_image = _state(
        _replica(START1, cohorts=16, persisted=940, drop=("versions_persisted",)),
        _replica(START2, cohorts=15, persisted=880))
    r = _Runner([old_image])
    assert r.run() is False
    assert "unreadable" in r.last["notes"] and "UNKNOWN is never PASS" in r.last["notes"]


# ── clause 1: window rejections / profiler faults, isolated ──────────────────


def test_ISOLATION_a_rejected_window_alone_must_fail_the_gate():
    """Fully productive, fully drained — but one tenant window was rejected, so
    its evidence was marked processed and never evaluated. Only clause 1 can
    reject this."""
    rejected = _state(
        _replica(START1, cohorts=16, persisted=940, rejected=4, dropped=812),
        _replica(START2, cohorts=15, persisted=880))
    assert rejected["pending_sum"] == 0 and rejected["cohorts_sum"] > 0
    r = _Runner([rejected])
    assert r.run() is False, "4 rejected windows were accepted as a complete run"
    notes = r.last["notes"]
    assert "corr_engine_windows_rejected_total rose 0 -> 4" in notes
    assert "812" in notes, "the note must say how many signals the drop cost"


def test_ISOLATION_a_profiler_fault_alone_must_fail_the_gate():
    """A profiler fault does not lose evidence any more — but it does mean the
    numbers this very gate is reading are incomplete."""
    faulted = _state(_replica(START1, cohorts=16, persisted=940, profiler_errors=9),
                     _replica(START2, cohorts=15, persisted=880))
    r = _Runner([faulted])
    assert r.run() is False
    assert "corr_engine_profiler_errors_total rose 0 -> 9" in r.last["notes"]


def test_a_rejection_that_predates_the_run_is_not_charged_to_it():
    """Counters are monotonic per replica, so the clause must compare against
    the preflight BASELINE — not against zero, which would fail every run on a
    replica that ever rejected a window."""
    base = _state(_replica(START1, rejected=4), _replica(START2, rejected=4))
    final = _state(_replica(START1, cohorts=16, persisted=940, rejected=4),
                   _replica(START2, cohorts=15, persisted=880, rejected=4))
    r = _Runner([final], baseline=base)
    assert r.run() is True, (
        f"a pre-existing rejection was charged to this run: {r.last['notes']}")


def test_an_UNREADABLE_rejection_counter_is_UNKNOWN_never_PASS():
    old_image = _state(
        _replica(START1, cohorts=16, persisted=940, drop=("windows_rejected",)),
        _replica(START2, cohorts=15, persisted=880))
    r = _Runner([old_image])
    assert r.run() is False
    assert "does not export corr_engine_windows_rejected_total" in r.last["notes"]


# ── the numbers must be ON the phase line, in both directions ────────────────


def test_the_phase_line_prints_the_numbers_on_PASS():
    r = _Runner([HEALTHY])
    assert r.run() is True
    notes = r.last["notes"]
    assert "windows_rejected +0" in notes
    assert "profiler_errors +0" in notes
    assert "versions_persisted +1820" in notes, (
        "the operator must see WHAT the run produced, not just that it drained")


def test_the_phase_line_prints_the_numbers_on_FAIL():
    r = _Runner([HOLLOW])
    assert r.run() is False
    assert "versions_persisted +0" in r.last["notes"]


def test_the_evidence_carries_the_per_replica_deltas():
    r = _Runner([HOLLOW])
    r.run()
    deltas = r.last["evidence"]["counter_deltas"]
    assert deltas[R1]["cohorts"] == 16
    assert deltas[R1]["versions_persisted"] == 0
    assert deltas[R2]["windows_rejected"] == 0
    assert "also_proves" in r.last["evidence"]


# ── mutants: drop a clause, and the run it exists to catch goes green ───────


def _gate(state, baseline=BASELINE, *, hollow=True, rejected=True, **kw):
    """The gate re-implemented over the same facts, with one clause removable."""
    adv = state["cohorts_sum"] - baseline["cohorts_sum"]
    checks = {
        "readable": state["readable"] == state["replicas"] and state["replicas"] > 0,
        "pending": state["pending_sum"] == 0,
        "age": 0 <= state["oldest_pending_age_max"] <= ml.CORR_IDLE_AGE_S,
        "advanced": adv > 0,
    }
    if hollow:
        checks["hollow"] = all(
            n["versions_persisted"] > baseline["per_replica"][c]["versions_persisted"]
            for c, n in state["per_replica"].items()
            if n["cohorts_total"] > baseline["per_replica"][c]["cohorts_total"])
    if rejected:
        checks["rejected"] = all(
            n["windows_rejected"] <= baseline["per_replica"][c]["windows_rejected"]
            and n["profiler_errors"] <= baseline["per_replica"][c]["profiler_errors"]
            for c, n in state["per_replica"].items())
    checks.update(kw)
    return all(checks.values())


def test_MUTANT_dropping_the_hollow_clause_passes_the_empty_run():
    """Without clause 2, the 14-second empty run is green again."""
    assert _gate(HOLLOW) is False
    assert _gate(HOLLOW, hollow=False) is True, (
        "if removing the hollow clause does not pass the bug, this mutant is "
        "not exercising it")
    assert _Runner([HOLLOW]).run() is False        # and the real gate keeps it


def test_MUTANT_dropping_the_rejection_clause_passes_discarded_evidence():
    rejected = _state(
        _replica(START1, cohorts=16, persisted=940, rejected=4, dropped=812),
        _replica(START2, cohorts=15, persisted=880))
    assert _gate(rejected) is False
    assert _gate(rejected, rejected=False) is True
    assert _Runner([rejected]).run() is False


def test_MUTANT_summing_persisted_across_replicas_hides_a_hollow_replica():
    """Why the clause is per-replica: the cross-replica SUM advances as long as
    ONE replica is producing."""
    one_sided = _state(_replica(START1, cohorts=16, persisted=940),
                       _replica(START2, cohorts=15, persisted=0))
    summed = sum(v["versions_persisted"] for v in one_sided["per_replica"].values())
    assert summed > 0, "the summed form sees progress and would PASS"
    assert _Runner([one_sided]).run() is False


# ── the aggregator feeds the clause the RIGHT series ─────────────────────────


def test_PARSER_keeps_labelled_series_apart():
    """`corr_versions{outcome="persisted"}` and `{outcome="damped"}` share a
    bare name. Collapsing labels made the completion check read `damped`."""
    body = ('# HELP corr_versions x\n'
            '# TYPE corr_versions counter\n'
            'corr_versions{outcome="persisted"} 940\n'
            'corr_versions{outcome="damped"} 3\n'
            'corr_engine_pending 0\n'
            'corr_engine_windows_rejected_total 2\n'
            'garbage_line\n'
            'corr_bad_value NaNish\n')
    m = ml.parse_prom_metrics(body)
    assert m['corr_versions{outcome="persisted"}'] == 940.0
    assert m['corr_versions{outcome="damped"}'] == 3.0
    assert m["corr_engine_pending"] == 0.0
    assert m["corr_engine_windows_rejected_total"] == 2.0
    assert "corr_bad_value" not in m, "an unparseable value must not be guessed at"


class _StubStack:
    def __init__(self, replicas):
        self._replicas = replicas

    corr_completion_state = ml.Stack.corr_completion_state

    def corr_replicas(self):
        return self._replicas


def _rep(cid, *, pending=0.0, cohorts=16.0, age=0.0, persisted=940.0,
         damped=3.0, rejected=0.0, profiler_errors=0.0, dropped=0.0,
         started="2026-08-29T01:16:03Z"):
    return {"container": cid, "ip": "172.18.0.2", "started_at": started,
            "metrics": {
                "corr_engine_pending": pending,
                "corr_engine_cohorts_total": cohorts,
                "corr_engine_oldest_pending_age_seconds": age,
                "corr_engine_epochs_total": 12.0,
                "corr_window_signals": 50000.0,
                "corr_engine_windows_rejected_total": rejected,
                "corr_engine_profiler_errors_total": profiler_errors,
                'corr_versions{outcome="persisted"}': persisted,
                'corr_versions{outcome="damped"}': damped,
                'corr_signals_dropped_total{reason="window_rejected"}': dropped,
            }}


def test_AGGREGATION_reads_persisted_not_damped():
    st = _StubStack([_rep(R1, persisted=940.0, damped=3.0)]).corr_completion_state()
    assert st["per_replica"][R1]["versions_persisted"] == 940.0
    assert st["per_replica"][R1]["versions_damped"] == 3.0


def test_AGGREGATION_a_missing_counter_stays_UNKNOWN():
    rep = _rep(R1)
    del rep["metrics"]['corr_versions{outcome="persisted"}']
    st = _StubStack([rep]).corr_completion_state()
    assert st["per_replica"][R1]["versions_persisted"] == -1.0, (
        "a missing counter must not read as 0 — 0 is a claim, -1 is UNKNOWN")


def test_AGGREGATION_end_to_end_the_real_aggregator_feeds_the_real_gate():
    """No stubbed aggregate: per-replica readings -> real aggregation -> real
    gate, on the hollow shape."""
    r = _Runner([None])
    r.stack = _StubStack([_rep(R1, cohorts=16.0, persisted=0.0),
                          _rep(R2, cohorts=15.0, persisted=0.0)])
    r.baseline = {"corr_completion": _StubStack(
        [_rep(R1, cohorts=0.0, persisted=0.0),
         _rep(R2, cohorts=0.0, persisted=0.0)]).corr_completion_state()}
    assert r.run() is False, (
        "the real aggregator + real gate accepted 31 cohorts that persisted "
        "nothing")
    assert "HOLLOW COMPLETION" in r.last["notes"]
