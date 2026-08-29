"""Tracker 170 — the qualification harness must not call the engine healthy
because the transport and ingest layers finished.

THE FALSE GREEN THIS KILLS. Run 082120173zup (2026-08-21, post-168, 1000
devices / 12 min / 182 eps) returned **PASS on all eight phases** while the
correlation engine had evaluated 3% of the workload:

    drain      PASS  Kafka consumer lag drained in 56s of a 2160s budget.
                     True — and irrelevant. The consumer buffers into the
                     engine's window and commits; transport drain is not
                     evaluation.
    accounting PASS  131,041 injected == 131,041 corr_signals rows + 0 DLQ.
                     True — and irrelevant. Those rows are written by
                     handle_syslog on the INGEST path, before the engine sees
                     them.

    reality          1 and 2 cohorts completed across the two replicas,
                     127,247 signals never evaluated, pending frozen at
                     66,179 / 61,068, oldest pending 700s against a 516.527s
                     horizon.

Neither gate was wrong about what it measured. Both were being *read* as
something they never claimed. `correlation_completion` makes the missing claim,
and this file proves it can go red.

Every mutant below is BEHAVIOURAL: each one is a plausible weaker version of
the gate, driven with the real run's numbers, and each must still FAIL the
run. A gate that cannot go red is not a gate.

Run:  python3 -m pytest tests/test_correlation_completion_gate_170.py -v
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
    spec = importlib.util.spec_from_file_location("scale_miniladder_170", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_170"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, (
        "importing the harness must not mutate PATH — pin it in main() instead")
    return mod


ml = _load_harness()

# ── the observed run, as fixtures ────────────────────────────────────────────
#
# Verbatim from run 082120173zup's own metrics, sampled independently of the
# harness while it was reporting PASS.
R1, R2 = "02f0c701526a", "182088270d24"
START1, START2 = "2026-08-21T20:11:53.781594769Z", "2026-08-21T20:12:48.879187508Z"


# 2026-08-29: the completion state carries four more per-replica facts (see
# the HOLLOW COMPLETION clauses in the gate). They are HEALTHY here — no window
# rejected, no profiler fault, objects persisted in step with the cohorts — so
# every fixture in this file keeps testing exactly the clause it was written
# for. tests/test_completion_hollow_20260829.py drives the unhealthy shapes.
def _healthy(cohorts):
    """Per-replica counters for an engine that produced what it drained."""
    return {"windows_rejected": 0.0, "profiler_errors": 0.0,
            "versions_persisted": float(cohorts) * 10.0,
            "versions_damped": 0.0, "signals_dropped_window_rejected": 0.0}


def _state(pending1, pending2, cohorts1, cohorts2, age1, age2,
           start1=START1, start2=START2, unreadable=(), replicas=2):
    readable = {
        R1: {"started_at": start1, "pending": pending1, "cohorts_total": cohorts1,
             "oldest_pending_age_s": age1, "epochs_total": 17.0,
             "window_signals": 67115.0, **_healthy(cohorts1)},
        R2: {"started_at": start2, "pending": pending2, "cohorts_total": cohorts2,
             "oldest_pending_age_s": age2, "epochs_total": 15.0,
             "window_signals": 63926.0, **_healthy(cohorts2)},
    }
    for u in unreadable:
        readable.pop(u, None)
    return {
        "replicas": replicas,
        "readable": len(readable),
        "unreadable": list(unreadable),
        "errors": [f"metrics probe failed: {u}" for u in unreadable],
        "pending_sum": sum(v["pending"] for v in readable.values()),
        "oldest_pending_age_max": max(
            (v["oldest_pending_age_s"] for v in readable.values()), default=-1.0),
        "cohorts_sum": sum(v["cohorts_total"] for v in readable.values()),
        "per_replica": readable,
    }


BASELINE = _state(0, 0, 0, 0, 0.0, 0.0)                 # preflight: idle engine
FALSE_GREEN = _state(66179, 61068, 1, 2, 700.0, 680.0)  # what actually happened
COMPLETED = _state(0, 0, 16, 15, 0.0, 0.0)              # the engine finally finishing


class _Runner:
    """A harness instance with only what the completion phase touches."""

    def __init__(self, states, baseline=BASELINE, burst_seconds=720.0):
        self.phases: list[dict] = []
        self.baseline = {"corr_completion": baseline}
        self.burst_seconds = burst_seconds
        self.run_dir = None
        self._states = list(states)
        # memflat's pending-zero leak anchor is derived by this phase
        # (2026-08-29): the real method runs over the real state dicts, and
        # these fixtures carry no per-replica RSS, so it records UNKNOWN
        # anchors — which is exactly what memflat must then report.
        self.corr_mem_track: dict = {}
        self.args = type("A", (), {"drain_factor": 3.0})()
        self.stack = type("S", (), {
            "corr_completion_state": lambda _s: (
                self._states.pop(0) if len(self._states) > 1 else self._states[0])
        })()
        self.stack.__dict__["_owner"] = self

    # the harness collaborators the phase uses
    _corr_mem_track = ml.Harness._corr_mem_track

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
    """The phase polls on a budget; drive it deterministically."""
    monkeypatch.setattr(ml.time, "sleep", lambda _s: None)
    ticks = iter(range(0, 100_000, 11))          # 11s per observation
    monkeypatch.setattr(ml.time, "monotonic", lambda: float(next(ticks)))


# ── the negative control (phase 7) ───────────────────────────────────────────


def test_THE_false_green_is_now_a_FAIL():
    """Ingest complete, Kafka drained, accounting balanced, engine pending
    66,179+61,068. This exact state returned PASS before tracker 170."""
    r = _Runner([FALSE_GREEN])
    assert r.run() is False
    assert r.last["status"] == "FAIL"
    assert "INCOMPLETE" in r.last["notes"]
    assert "127247" in r.last["notes"].replace(",", "") or "66179" in r.last["notes"]
    ev = r.last["evidence"]
    assert ev["final"]["pending_sum"] == 127247, "the two replicas' backlog"
    assert ev["cohorts_advanced"] == 3


def test_can_the_harness_still_pass_with_97_percent_unevaluated():
    """The question tracker 170 exists to answer. Required answer: NO."""
    assert _Runner([FALSE_GREEN]).run() is False


def test_a_genuinely_completed_run_still_passes():
    """The gate must not be unpassable — that would be its own false signal."""
    r = _Runner([COMPLETED])
    assert r.run() is True
    assert r.last["status"] == "PASS"
    assert r.last["evidence"]["cohorts_advanced"] == 31


def test_a_run_that_completes_after_some_waiting_passes():
    """Pending draining to zero across observations is the normal healthy shape."""
    r = _Runner([_state(50000, 40000, 3, 3, 400.0, 380.0),
                 _state(9000, 4000, 9, 8, 120.0, 90.0),
                 COMPLETED])
    assert r.run() is True
    assert r.last["evidence"]["completed_at_s"] is not None


# ── clause-isolating fixtures ────────────────────────────────────────────────
#
# The observed run fails EVERY clause at once, so it cannot prove any single
# clause is load-bearing — mutating one out still leaves the others to catch it.
# (Mutation-tested against the shipped gate: dropping the pending clause alone
# left the suite green until these were added.) Each fixture below trips
# exactly ONE clause.

# pending > 0, but the backlog is FRESH so the age gauge reads idle, and the
# engine did advance. Only the pending clause can reject this.
PENDING_ONLY = _state(5000, 3000, 9, 8, 2.0, 1.5)

# nothing pending, ages idle, engine READABLE — but it never did any work for
# this run. Only the cohort-progress clause can reject this.
NO_PROGRESS_ONLY = _state(0, 0, 0, 0, 0.0, 0.0)


def test_ISOLATION_pending_alone_must_fail_the_gate():
    """Fresh backlog: age reads idle and cohorts advanced, so ONLY the
    pending clause stands between this and a false PASS."""
    assert PENDING_ONLY["oldest_pending_age_max"] <= ml.CORR_IDLE_AGE_S
    assert PENDING_ONLY["cohorts_sum"] > BASELINE["cohorts_sum"]
    r = _Runner([PENDING_ONLY])
    assert r.run() is False, "8,000 signals pending was accepted as complete"
    assert "pending=8000" in r.last["notes"].replace(" ", "").replace(",", "") or \
        r.last["evidence"]["final"]["pending_sum"] == 8000


# One replica genuinely idle, its partner holding a FRESH backlog. Ages read
# idle and cohorts advanced, so ONLY the cross-replica SUM can reject this.
# (Mutation-tested: replacing the SUM with a per-replica "any idle" reading
# left the suite green until this fixture existed.)
ONE_REPLICA_IDLE = _state(0, 8000, 16, 9, 0.0, 3.0)


def test_ISOLATION_one_idle_replica_must_not_carry_the_verdict():
    """Replica 1 is genuinely finished. Replica 2 still holds 8,000 signals,
    recently arrived so its age gauge reads idle too. Only summing pending
    ACROSS replicas catches this."""
    per = ONE_REPLICA_IDLE["per_replica"]
    assert per[R1]["pending"] == 0, "replica 1 must look complete on its own"
    assert ONE_REPLICA_IDLE["oldest_pending_age_max"] <= ml.CORR_IDLE_AGE_S
    assert ONE_REPLICA_IDLE["cohorts_sum"] > BASELINE["cohorts_sum"]
    r = _Runner([ONE_REPLICA_IDLE])
    assert r.run() is False, (
        "one idle replica carried the verdict while its partner held 8,000 "
        "unevaluated signals")
    assert r.last["evidence"]["final"]["pending_sum"] == 8000


def test_ISOLATION_no_cohort_progress_alone_must_fail_the_gate():
    """Idle engine: pending 0 and ages 0, so ONLY the progress clause stands
    between an engine that never ran and a PASS."""
    assert NO_PROGRESS_ONLY["pending_sum"] == 0
    assert NO_PROGRESS_ONLY["oldest_pending_age_max"] <= ml.CORR_IDLE_AGE_S
    r = _Runner([NO_PROGRESS_ONLY])
    assert r.run() is False, "an engine that did nothing was accepted as complete"
    assert "did no work attributable to this run" in r.last["notes"]


# ── mutants (phase 8) — each must still FAIL the observed run ────────────────


def _gate(state, baseline=BASELINE, **kw):
    """Re-implementations of the gate with one clause removed."""
    adv = state["cohorts_sum"] - baseline["cohorts_sum"]
    idle = ml.CORR_IDLE_AGE_S
    checks = {
        "readable": state["readable"] == state["replicas"] and state["replicas"] > 0,
        "pending": state["pending_sum"] == 0,
        "age": 0 <= state["oldest_pending_age_max"] <= idle,
        "advanced": adv > 0,
    }
    checks.update(kw)
    return all(checks.values())


def test_MUTANT_1_dropping_the_pending_requirement_would_pass_the_bug():
    """Proves the pending clause is load-bearing, not decoration."""
    assert _gate(FALSE_GREEN) is False
    assert _gate(FALSE_GREEN, pending=True, age=True) is True, (
        "if removing the pending+age clauses does NOT pass the bug, this "
        "mutant is not exercising them")
    # and the real gate keeps them
    assert _Runner([FALSE_GREEN]).run() is False


def test_MUTANT_2_ignoring_oldest_pending_age_misses_a_stuck_engine():
    """An engine mid-drain can read pending 0 for an instant; age is the guard."""
    instant = _state(0, 0, 1, 2, 700.0, 680.0)   # pending momentarily 0, age stuck
    assert _gate(instant) is False, "the age clause must reject this"
    assert _gate(instant, age=True) is True, "without it the stuck engine passes"
    r = _Runner([instant])
    assert r.run() is False
    assert "INCOMPLETE" in r.last["notes"]


def test_MUTANT_3_not_requiring_cohort_progress_passes_an_idle_engine():
    """An engine that never received the workload also reports pending 0."""
    never_ran = _state(0, 0, 0, 0, 0.0, 0.0)
    assert _gate(never_ran) is False, "no cohort progress must fail"
    assert _gate(never_ran, advanced=True) is True, "without it, idle reads as done"
    r = _Runner([never_ran])
    assert r.run() is False
    assert "did no work attributable to this run" in r.last["notes"]


def test_MUTANT_4_checking_only_replica_1_misses_replica_2s_backlog():
    """Replica 1 idle, replica 2 holding 61,068 signals."""
    one_sided = _state(0, 61068, 16, 2, 0.0, 680.0)
    r = _Runner([one_sided])
    assert r.run() is False, "a per-replica check would have called this complete"
    assert r.last["evidence"]["final"]["pending_sum"] == 61068
    # the aggregation is a SUM precisely so one idle replica cannot carry the verdict
    assert one_sided["per_replica"][R1]["pending"] == 0


def test_MUTANT_5_kafka_drain_is_not_correlation_drain():
    """The transport gate passed on the real run; the engine gate must not."""
    assert _Runner([FALSE_GREEN]).run() is False


def test_MUTANT_6_ingest_accounting_is_not_evaluation():
    """corr_signals rows are written before the engine sees the signal, so a
    perfectly balanced ledger says nothing about evaluation."""
    r = _Runner([FALSE_GREEN])
    assert r.run() is False
    assert r.last["evidence"]["proves"] == "correlation_engine_evaluated_the_workload"


def test_MUTANT_7_a_restart_zeroes_the_counters_and_must_not_read_as_complete():
    """A restarted engine reports pending 0 with reset counters — identical to
    'finished' unless process identity is pinned."""
    restarted = _state(0, 0, 2, 1, 0.0, 0.0, start1="2026-08-21T21:40:00.000000000Z")
    r = _Runner([restarted])
    assert r.run() is False
    assert "RESTARTED mid-run" in r.last["notes"]


def test_MUTANT_7b_a_replaced_replica_set_is_not_completion():
    replaced = _state(0, 0, 5, 5, 0.0, 0.0)
    replaced["per_replica"] = {"deadbeefcafe": v for v in
                               [next(iter(replaced["per_replica"].values()))]}
    replaced["readable"] = 1
    replaced["replicas"] = 1
    r = _Runner([replaced])
    assert r.run() is False
    assert "replica set changed" in r.last["notes"]


def test_an_unreadable_replica_is_UNKNOWN_never_idle():
    blind = _state(0, 0, 16, 15, 0.0, 0.0, unreadable=(R2,))
    r = _Runner([blind])
    assert r.run() is False
    assert "unreadable" in r.last["notes"]


def test_no_replicas_at_all_is_a_failure_not_a_pass():
    empty = {"replicas": 0, "readable": 0, "unreadable": [], "errors": [],
             "pending_sum": 0, "oldest_pending_age_max": -1.0,
             "cohorts_sum": 0, "per_replica": {}}
    r = _Runner([empty])
    assert r.run() is False
    assert "no correlation replicas" in r.last["notes"]


# ── the aggregation layer itself (mutant 4, properly) ────────────────────────
#
# The fixtures above stub `corr_completion_state`, so they exercise the GATE but
# not the AGGREGATOR. Mutating SUM->MIN therefore left them green. These drive
# the real `Stack.corr_completion_state` over stubbed per-replica readings.


class _StubStack:
    def __init__(self, replicas):
        self._replicas = replicas

    corr_completion_state = ml.Stack.corr_completion_state

    def corr_replicas(self):
        return self._replicas


def _rep(cid, pending, cohorts, age, started="2026-08-21T20:00:00Z"):
    return {"container": cid, "ip": "172.18.0.1", "started_at": started,
            "metrics": {"corr_engine_pending": pending,
                        "corr_engine_cohorts_total": cohorts,
                        "corr_engine_oldest_pending_age_seconds": age,
                        "corr_engine_epochs_total": 10.0,
                        "corr_window_signals": 1000.0,
                        "corr_engine_windows_rejected_total": 0.0,
                        "corr_engine_profiler_errors_total": 0.0,
                        'corr_versions{outcome="persisted"}': cohorts * 10.0,
                        'corr_versions{outcome="damped"}': 0.0,
                        'corr_signals_dropped_total{reason="window_rejected"}': 0.0}}


def test_AGGREGATION_pending_SUMS_across_replicas():
    """One idle replica must not mask its partner's backlog. SUM, never MIN,
    never 'any replica idle'."""
    st = _StubStack([_rep(R1, 0, 16, 0.0), _rep(R2, 8000, 9, 3.0)]).corr_completion_state()
    assert st["pending_sum"] == 8000, (
        f"pending must SUM across replicas, got {st['pending_sum']} — an idle "
        f"replica is masking 8,000 unevaluated signals")


def test_AGGREGATION_oldest_age_takes_the_MAX():
    """The worst replica bounds the claim."""
    st = _StubStack([_rep(R1, 0, 16, 1.0), _rep(R2, 0, 9, 690.0)]).corr_completion_state()
    assert st["oldest_pending_age_max"] == 690.0


def test_AGGREGATION_cohorts_SUM_as_a_progress_counter():
    st = _StubStack([_rep(R1, 0, 16, 0.0), _rep(R2, 0, 15, 0.0)]).corr_completion_state()
    assert st["cohorts_sum"] == 31


def test_AGGREGATION_an_unreadable_replica_is_counted_not_skipped():
    """readable < replicas is what the gate keys off; a probe failure must
    never quietly shrink the denominator."""
    st = _StubStack([
        _rep(R1, 0, 16, 0.0),
        {"container": R2, "error": "metrics probe failed: connection refused"},
    ]).corr_completion_state()
    assert st["replicas"] == 2 and st["readable"] == 1
    assert st["unreadable"] == [R2]
    assert st["errors"] and "connection refused" in st["errors"][0]


def test_AGGREGATION_end_to_end_the_real_aggregator_feeds_the_real_gate():
    """No stubbed aggregate anywhere: per-replica readings -> real aggregation
    -> real gate. This is the one that dies if either layer regresses."""
    r = _Runner([None])
    stub = _StubStack([_rep(R1, 0, 16, 0.0), _rep(R2, 8000, 9, 3.0)])
    r.stack = stub
    assert r.run() is False, (
        "the real aggregator + real gate accepted a partner replica holding "
        "8,000 unevaluated signals")


# ── the phase is actually wired into the run (mutant 8) ──────────────────────


def test_the_gate_is_wired_into_the_qualification_sequence():
    """A gate that exists but is never called is the same false green."""
    src = (ROOT / "scripts" / "scale-miniladder.py").read_text(encoding="utf-8")
    assert "self.correlation_completion()" in src, (
        "correlation_completion is defined but never invoked — the qualification "
        "sequence would still return PASS on transport drain alone")
    seq = src.split("def execute(", 1)[1]
    assert seq.index("self.correlation_completion()") > seq.index("self.drain()"), \
        "completion must be gated after transport drain, not instead of it"


def test_overall_pass_depends_on_every_phase_including_this_one():
    src = (ROOT / "scripts" / "scale-miniladder.py").read_text(encoding="utf-8")
    assert 'all(p["status"] == "PASS" for p in self.phases)' in src, (
        "overall PASS must remain a conjunction over all phases, or the new "
        "gate can be red while the run reports green")


def test_drain_no_longer_claims_more_than_transport():
    """The phase that produced the false green must say what it proves."""
    src = (ROOT / "scripts" / "scale-miniladder.py").read_text(encoding="utf-8")
    assert '"kafka_transport_drain_only"' in src
    assert "KAFKA TRANSPORT lag drained" in src
