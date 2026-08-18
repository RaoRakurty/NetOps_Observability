"""Tests for the tracker-155 orchestration runner.

Same stance as test_ownership.py: the valuable tests are the ones proving this
thing REFUSES. A runner that restarts correlation containers during a 72h soak
would destroy evidence that takes three days to regenerate, so every interlock
here is tested for its closed state first and its open state second.

Load-bearing:
  * dry-run is the DEFAULT — a caller who forgets the flag mutates nothing
  * the soak interlock blocks while the soak runs, and blocks on an UNREADABLE
    baseline (unknown is not clear)
  * preflight refuses a non-loopback host and a wrong compose project
  * preflight refuses a single-replica stack (movement would be vacuous)
  * partition_raise needs its own flag, because restore() cannot undo it
  * a failing command aborts the remaining plan instead of ploughing on
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ownership import MOVES
from ownership_runner import (
    Action,
    capture,
    execute,
    in_flight_ready,
    plan_move,
    preflight,
    restore_plan,
    soak_interlock,
)

SOAK_START = "2026-08-16T23:14:13.530740+00:00"
OPEN = (True, "soak complete")


def _baseline(tmp_path, start=SOAK_START):
    p = tmp_path / "soak-baseline.json"
    p.write_text(json.dumps({"soak_start_utc": start, "rss": {}}))
    return str(p)


class FakeStack:
    def __init__(self, base_url="http://127.0.0.1:8000", project="netops",
                 replicas=2):
        self.base_url = base_url
        self.project = project
        self._replicas = replicas

    def cids(self, service):
        return [f"cid{i}" for i in range(self._replicas)]


def recorder():
    calls = []

    def run(cmd):
        calls.append(cmd)
        return 0, "", ""
    return calls, run


# --- soak interlock --------------------------------------------------------

def test_soak_interlock_blocks_while_running(tmp_path):
    now = _dt.datetime.fromisoformat(SOAK_START) + _dt.timedelta(hours=23)
    ok, reason = soak_interlock(now, _baseline(tmp_path))
    assert ok is False
    assert "REFUSING" in reason and "remaining" in reason


def test_soak_interlock_opens_after_72h(tmp_path):
    now = _dt.datetime.fromisoformat(SOAK_START) + _dt.timedelta(hours=72.1)
    ok, reason = soak_interlock(now, _baseline(tmp_path))
    assert ok is True and "soak complete" in reason


def test_soak_interlock_blocks_on_unreadable_baseline(tmp_path):
    """Unknown is not clear. A corrupt baseline must not read as 'go ahead'."""
    p = tmp_path / "soak-baseline.json"
    p.write_text("{ this is not json")
    ok, reason = soak_interlock(_dt.datetime.now(_dt.timezone.utc), str(p))
    assert ok is False
    assert "REFUSING" in reason


def test_soak_interlock_blocks_on_missing_key(tmp_path):
    p = tmp_path / "soak-baseline.json"
    p.write_text(json.dumps({"rss": {}}))
    ok, _ = soak_interlock(_dt.datetime.now(_dt.timezone.utc), str(p))
    assert ok is False


def test_absent_baseline_means_no_soak_and_is_allowed(tmp_path):
    ok, reason = soak_interlock(_dt.datetime.now(_dt.timezone.utc),
                                str(tmp_path / "nope.json"))
    assert ok is True and "no soak" in reason


# --- preflight -------------------------------------------------------------

def test_preflight_refuses_non_loopback_host():
    ok, findings = preflight(FakeStack(base_url="https://prod.example.com"))
    assert ok is False
    assert any("not loopback" in f for f in findings)


def test_preflight_refuses_wrong_project():
    ok, findings = preflight(FakeStack(project="customer-prod"))
    assert ok is False
    assert any("compose project" in f and "REFUSED" in f for f in findings)


def test_preflight_refuses_single_replica_as_vacuous():
    """With one member partitions never move between members, so every
    scenario would pass while exercising nothing."""
    ok, findings = preflight(FakeStack(replicas=1))
    assert ok is False
    assert any("vacuous" in f for f in findings)


def test_preflight_refuses_when_no_correlation_containers():
    ok, findings = preflight(FakeStack(replicas=0))
    assert ok is False
    assert any("no correlation containers" in f for f in findings)


def test_preflight_passes_on_the_lab_shape():
    ok, findings = preflight(FakeStack())
    assert ok is True
    assert not any("REFUSED" in f for f in findings)


# --- plans are pure --------------------------------------------------------

@pytest.mark.parametrize("move", MOVES)
def test_every_move_has_a_plan_and_runs_nothing_to_build_it(move):
    actions = plan_move(move, 2, "netops", "/tmp/.env")
    assert actions and all(isinstance(a, Action) for a in actions)
    assert all(a.cmd[0] == "docker" for a in actions)


def test_unknown_move_raises():
    with pytest.raises(ValueError):
        plan_move("nope", 2, "netops", "/tmp/.env")


def test_only_partition_raise_is_marked_irreversible():
    for move in MOVES:
        irr = any(a.irreversible for a in plan_move(move, 2, "n", "/e"))
        assert irr == (move == "partition_raise"), move


def test_scale_down_never_goes_below_two():
    """Below two replicas nothing can move between members."""
    actions = plan_move("scale_down", 2, "netops", "/tmp/.env")
    assert "correlation=2" in " ".join(actions[0].cmd)


def test_rapid_rebalance_churns_without_settling():
    actions = plan_move("rapid_rebalance", 2, "netops", "/tmp/.env")
    assert len(actions) >= 4


def test_restore_plan_cannot_restore_partitions():
    """Documented limitation, asserted so it cannot be quietly 'fixed' by
    someone adding a partition step that would not work anyway."""
    actions = restore_plan(2, "netops", "/tmp/.env")
    assert all(a.kind == "scale" for a in actions)
    assert not any("kafka-init" in " ".join(a.cmd) for a in actions)


# --- execution gates -------------------------------------------------------

def test_dry_run_is_the_default_and_executes_nothing():
    calls, run = recorder()
    out = execute(plan_move("restart_one", 2, "netops", "/e"), runner=run)
    assert calls == []
    assert out["executed"] is False
    assert all("DRY-RUN" in a["status"] for a in out["actions"])


def test_live_run_refused_while_soak_interlock_closed():
    calls, run = recorder()
    out = execute(plan_move("restart_one", 2, "netops", "/e"), dry_run=False,
                  interlock=(False, "72h soak in progress"),
                  preflight_ok=True, runner=run)
    assert calls == [], "a command ran despite the soak interlock"
    assert out["executed"] is False and "soak" in out["reason"]


def test_live_run_refused_when_preflight_failed():
    calls, run = recorder()
    out = execute(plan_move("scale_up", 2, "netops", "/e"), dry_run=False,
                  interlock=OPEN, preflight_ok=False, runner=run)
    assert calls == []
    assert "preflight" in out["reason"]


def test_partition_raise_refused_without_its_own_flag():
    calls, run = recorder()
    out = execute(plan_move("partition_raise", 2, "netops", "/e"),
                  dry_run=False, interlock=OPEN, preflight_ok=True, runner=run)
    assert calls == [], "an irreversible action ran without explicit consent"
    assert "irreversible" in out["reason"]


def test_partition_raise_runs_only_with_every_gate_open():
    calls, run = recorder()
    out = execute(plan_move("partition_raise", 2, "netops", "/e"),
                  dry_run=False, interlock=OPEN, preflight_ok=True,
                  allow_partition_raise=True, runner=run, sleeper=lambda s: None)
    assert len(calls) == 1 and out["executed"] is True


def test_reversible_moves_run_with_the_two_standard_gates():
    calls, run = recorder()
    out = execute(plan_move("rolling_restart", 3, "netops", "/e"),
                  dry_run=False, interlock=OPEN, preflight_ok=True,
                  runner=run, sleeper=lambda s: None)
    assert len(calls) == 3 and out["executed"] is True


def test_failing_command_aborts_the_rest_of_the_plan():
    calls = []

    def run(cmd):
        calls.append(cmd)
        return (1, "", "boom") if len(calls) == 2 else (0, "", "")
    out = execute(plan_move("rolling_restart", 3, "netops", "/e"),
                  dry_run=False, interlock=OPEN, preflight_ok=True,
                  runner=run, sleeper=lambda s: None)
    assert len(calls) == 2, "the plan continued after a failure"
    assert out["executed"] is False and "FAILED" in out["reason"]


def test_settle_is_honoured_between_steps():
    slept = []
    _, run = recorder()
    execute(plan_move("rolling_restart", 2, "netops", "/e"), dry_run=False,
            interlock=OPEN, preflight_ok=True, runner=run,
            sleeper=slept.append)
    assert slept and all(s > 0 for s in slept)


# --- capture / in-flight precondition --------------------------------------

class HealthStack(FakeStack):
    def __init__(self, open_objects=0, state="active", owned=24, lag=(9, 48),
                 **kw):
        super().__init__(**kw)
        self._hz = {
            "cf0609048b5d0000": {
                "consumer": {"state": state, "owned_partition_count": owned,
                             "cold_partitions": [], "assignment": {"t": [0, 1]}},
                "engine_v2": {"open_objects": open_objects},
            }
        }
        self._lag = lag

    def corr_healthz_all(self):
        return self._hz

    def group_lag_total(self, group):
        return self._lag


def test_capture_reads_the_real_phase1_field_names():
    snap = capture(HealthStack(open_objects=7), "before")
    assert snap.open_objects == 7
    assert snap.consumer_state["cf0609048b5d"] == "active"
    assert snap.assignment["cf0609048b5d"]["owned"] == 24
    assert (snap.lag_total, snap.lag_partitions) == (9, 48)
    assert snap.replicas == 2


def test_capture_marks_a_failed_lag_read_instead_of_reporting_zero():
    """A lag read that failed must not look like 'no lag'."""
    class Broken(HealthStack):
        def group_lag_total(self, group):
            raise RuntimeError("kafka unreachable")
    snap = capture(Broken(), "before")
    assert snap.lag_total == -1 and snap.lag_partitions == -1


def test_idle_lab_is_not_ready_for_a_move():
    """Measured live 2026-08-18: open_objects == 0 on the quiet lab."""
    ok, why = in_flight_ready(capture(HealthStack(open_objects=0), "before"))
    assert ok is False
    assert "exercise nothing" in why


def test_in_flight_state_makes_it_ready():
    ok, why = in_flight_ready(capture(HealthStack(open_objects=3), "before"))
    assert ok is True and "3 correlation object(s)" in why


def test_snapshot_serializes_every_recorded_dimension():
    d = capture(HealthStack(open_objects=2), "after",
                rca={"matched": 3, "total": 4},
                isolation_violations=("leak",)).to_dict()
    for key in ("assignment", "consumer_state", "open_objects",
                "cold_partitions", "lag_total", "replicas", "rca",
                "isolation_violations"):
        assert key in d, key
    assert d["rca"] == {"matched": 3, "total": 4}
    assert d["isolation_violations"] == ["leak"]
