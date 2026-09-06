# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The burst injects the PROFILE's fleet, or it fails (2026-08-29).

THE DEFECT THIS PINS. Two 2.5K T-nominal runs that were meant to be the same
ratified workload were not:

    p2-s04-08290653   injected 900001 events in 900s (~1000/s; fleet=900000)
    p2-s04b-08290858  injected 870001 events in 904s  (~963/s; fleet=870000)
                      ...and still printed [PASS] burst.

`_burst_lanes` was bounded by the WALL CLOCK (`while elapsed < duration`) and
sized each chunk from the rate sampled at that instant. In run b the producer
was slow (median chunk produce 7.95 s, 22 chunks over 10 s, peak 31.65 s), the
loop fell behind its own pacing, three of the ninety 10 s chunks never came
around, and 30,000 events were NEVER GENERATED — no produce failure, nothing
lost in flight, simply a smaller workload. The verdict looked only at
`produce_failures`, so a 3.3 % short fleet PASSED, and every TTUR/completion
number downstream was compared against a run of a different experiment.

What these tests hold:
  * the plan is a pure function of the profile — same profile, same chunk plan,
    event for event, whatever the box does (mutant: size the fleet from the
    achieved rate ⇒ red);
  * a slow injector EXTENDS the window and still injects the whole fleet;
  * past the bound the phase FAILS, naming shortfall / achieved rate / elapsed;
  * fleet_planned, fleet_injected and rate_achieved are in the evidence and in
    the printed verdict.

Run:  python3 -m pytest tests/test_miniladder_burst_fleet_integrity.py -v
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_fleet", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_fleet"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()


class FakeClock:
    """Virtual monotonic clock. `sleep` advances it; so does a produce call,
    by the per-chunk cost the test is simulating. Nothing here waits."""

    def __init__(self) -> None:
        self.t = 0.0
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        assert seconds > 0, "the loop must never sleep a non-positive interval"
        self.slept += seconds
        self.t += seconds


class FakeStack:
    """Records every produced batch and charges the clock for it."""

    def __init__(self, clock: FakeClock, chunk_cost_s: float,
                 fail_after: int = -1) -> None:
        self.clock = clock
        self.chunk_cost_s = chunk_cost_s
        self.fail_after = fail_after
        self.batches: list[list[str]] = []

    def produce(self, topic, lines, key=None):
        self.batches.append(list(lines))
        self.clock.t += self.chunk_cost_s
        if 0 <= self.fail_after < len(self.batches):
            return False, "simulated produce failure"
        return True, ""

    @property
    def produced(self) -> int:
        return sum(len(b) for b in self.batches)


def _harness(tmp_path, clock, stack, profile="t-nominal-2.5k", minutes=1,
             devices=10, window_factor=ml.BURST_WINDOW_MAX_FACTOR,
             cheap_events=False):
    cls = ml.Harness
    h = cls.__new__(cls)
    h.args = argparse.Namespace(
        burst_minutes=minutes, eps=1000, profile=profile, event_mix="single",
        producer_key="none", burst_window_factor=window_factor)
    h.profile = ml.WORKLOAD_PROFILES[profile]
    h._mix = cls._mix_table(cls.EVENT_MIX_REALISTIC)
    h._tables = cls._composed_tables()
    h.created_ids = [f"mlx-fleet-{i:05d}" for i in range(devices)]
    h.producer_key = None
    h.injected_total = 0
    h.produce_failures = []
    h.phases = []
    h.burst_seconds = 0.0
    h.run_dir = str(tmp_path)
    h.stack = stack
    if cheap_events:
        # The full 2.5K profile is 900,000 events; the payload shape is pinned
        # by test_workload_profiles, so keep these runs about the SCHEDULE.
        h._syslog_event = lambda dev, seq, mix_name=None, mix_seq=None: (
            f"{dev}|{seq}|{mix_seq}")
    return h


def _run_burst(monkeypatch, h, clock) -> tuple[bool, dict, str]:
    monkeypatch.setattr(ml, "time", clock)
    ok = h._burst_lanes({})
    entry = h.phases[-1]
    return ok, entry["evidence"], entry["notes"]


# ── the plan is a function of the PROFILE, never of the achieved rate ────────

@pytest.mark.parametrize("profile,minutes,want_total", [
    ("t-nominal-2.5k", 15, 900_000),
    ("t-nominal", 15, 360_000),
    ("s1-2.5k", 15, 9_000_000),
    ("s4-chatter", 60, 1_441_260),
])
def test_chunk_plan_is_identical_across_runs_of_one_profile(profile, minutes,
                                                            want_total):
    """Two runs, same profile ⇒ the same chunk plan, event for event. A fleet
    derived from the achieved rate (the defect) cannot satisfy this."""
    a = _harness(Path("."), FakeClock(), None, profile=profile, minutes=minutes)
    b = _harness(Path("."), FakeClock(), None, profile=profile, minutes=minutes)
    plan_a, plan_b = a._lane_schedule(), b._lane_schedule()
    assert plan_a == plan_b
    assert len(plan_a) == minutes * 60 // ml.BURST_CHUNK_SECS
    assert sum(sum(r.values()) for r in plan_a) == want_total
    assert a._planned_total() == want_total


def test_2k5_plan_is_the_ratified_fleet_chunk_by_chunk():
    """900,000 = 90 chunks x 10,000 — the ratified 2,500-device workload."""
    h = _harness(Path("."), FakeClock(), None, minutes=15)
    plan = h._lane_schedule()
    assert len(plan) == 90
    assert all(row == {"fleet": 10_000} for row in plan)


def test_planned_total_does_not_depend_on_devices_or_wall_clock():
    small = _harness(Path("."), FakeClock(), None, minutes=15, devices=10)
    big = _harness(Path("."), FakeClock(), None, minutes=15, devices=2500)
    assert small._planned_total() == big._planned_total() == 900_000


# ── a slow injector extends the window; the fleet stays whole ────────────────

def test_slow_injector_extends_the_window_and_injects_the_full_fleet(
        tmp_path, monkeypatch):
    clock = FakeClock()
    # 12 s to produce a 10 s chunk: the loop can never keep pace.
    stack = FakeStack(clock, chunk_cost_s=12.0)
    h = _harness(tmp_path, clock, stack, minutes=1)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)

    assert ok, notes
    assert ev["fleet_planned"] == 60_000
    assert ev["fleet_injected"] == 60_000, "the workload must never be truncated"
    assert ev["fleet_shortfall"] == 0
    assert stack.produced == 60_000
    assert ev["chunks"] == ev["chunks_planned"] == 6
    assert ev["burst_seconds"] == pytest.approx(72.0)
    assert ev["window_s"] == 60 and ev["window_extended"] is True
    assert ev["window_bound_exceeded"] is False
    assert ev["rate_achieved"] == pytest.approx(60_000 / 72.0, rel=1e-3)
    assert "fleet_injected=60000" in notes and "fleet_planned=60000" in notes
    assert "rate_achieved=" in notes and "window extended" in notes


def test_the_2k5_run_that_lost_30000_events_now_injects_them(
        tmp_path, monkeypatch):
    """Run p2-s04b's shape, replayed: chunks that take just over 10 s. The old
    time-boxed loop dropped the last chunks (870,000 of 900,000) and PASSED;
    the work-boxed loop injects all 900,000 in a stretched window."""
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=10.5)
    h = _harness(tmp_path, clock, stack, minutes=15, cheap_events=True)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)

    assert ok, notes
    assert ev["fleet_planned"] == 900_000
    assert ev["fleet_injected"] == 900_000
    assert stack.produced == 900_000
    assert ev["chunks"] == 90
    # The old loop broke at elapsed >= 900 s — 85 chunks, 850,000 events.
    assert ev["burst_seconds"] == pytest.approx(945.0)
    assert ev["window_extended"] is True
    assert ev["window_bound_s"] == pytest.approx(1350.0)


def test_a_healthy_run_is_not_marked_extended(tmp_path, monkeypatch):
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=6.4)   # the healthy run's median
    h = _harness(tmp_path, clock, stack, minutes=1)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)

    assert ok, notes
    assert ev["fleet_injected"] == ev["fleet_planned"] == 60_000
    assert ev["window_extended"] is False
    assert ev["burst_seconds"] == pytest.approx(60.0, abs=1.0)
    assert "window extended" not in notes


def test_paced_chunks_are_released_on_the_nominal_clock(tmp_path, monkeypatch):
    """Chunk i is released at t0 + i*10 s — the pacing the profile's arrival
    shape assumes; slippage is never 'caught up' by dropping chunks."""
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=2.0)
    h = _harness(tmp_path, clock, stack, minutes=1)
    ok, _ev, notes = _run_burst(monkeypatch, h, clock)
    assert ok, notes
    with open(tmp_path / "burst-chunks.json", encoding="utf-8") as f:
        chunks = json.load(f)
    assert [c["i"] for c in chunks] == list(range(6))
    assert [c["t"] for c in chunks] == [0.0, 10.0, 20.0, 30.0, 40.0, 50.0]


# ── past the bound: FAIL, loudly and with the numbers ────────────────────────

def test_bound_exceeded_fails_with_the_shortfall(tmp_path, monkeypatch):
    clock = FakeClock()
    # 40 s per 10 s chunk: only 3 chunks fit inside the 90 s bound.
    stack = FakeStack(clock, chunk_cost_s=40.0)
    h = _harness(tmp_path, clock, stack, minutes=1)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)

    assert not ok, "a truncated workload must never PASS"
    assert ev["fleet_planned"] == 60_000
    assert ev["fleet_injected"] == 30_000
    assert ev["fleet_shortfall"] == 30_000
    assert ev["window_bound_exceeded"] is True
    assert ev["window_bound_s"] == pytest.approx(90.0)
    assert ev["chunks"] == 3 and ev["chunks_planned"] == 6
    assert "WORKLOAD TRUNCATED" in notes
    assert "30000" in notes                      # the shortfall
    assert f"{ev['rate_achieved']:.0f}/s" in notes
    assert f"{ev['burst_seconds']:.0f}s" in notes


def test_window_factor_bounds_how_far_the_window_may_stretch(
        tmp_path, monkeypatch):
    """The same slow injector passes with a wider bound and fails with a
    tighter one — the bound is the only knob, the fleet is not."""
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=20.0)
    h = _harness(tmp_path, clock, stack, minutes=1, window_factor=3.0)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)
    assert ok, notes
    assert ev["fleet_injected"] == 60_000

    clock2 = FakeClock()
    stack2 = FakeStack(clock2, chunk_cost_s=20.0)
    h2 = _harness(tmp_path, clock2, stack2, minutes=1, window_factor=1.0)
    ok2, ev2, _notes2 = _run_burst(monkeypatch, h2, clock2)
    assert not ok2
    assert ev2["fleet_injected"] < ev2["fleet_planned"]
    assert ev2["fleet_shortfall"] == ev2["fleet_planned"] - ev2["fleet_injected"]


def test_produce_failures_do_not_count_towards_the_fleet(tmp_path, monkeypatch):
    """A batch that never reached the bus is not injected — the fleet counter,
    the lane tallies and the balance equation must all agree on that."""
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=1.0, fail_after=2)
    h = _harness(tmp_path, clock, stack, minutes=1)
    ok, ev, notes = _run_burst(monkeypatch, h, clock)

    assert not ok
    assert "produce failures" in notes
    assert ev["fleet_injected"] == 20_000
    assert ev["lanes"]["fleet"]["sent"] == 20_000
    assert ev["injected_total"] == 20_000


# ── the same contract on the single-lane (legacy) path ──────────────────────

def test_legacy_loop_injects_the_whole_fleet_when_slow(tmp_path, monkeypatch):
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=12.0)
    h = _harness(tmp_path, clock, stack, profile="legacy", minutes=1,
                 cheap_events=True)
    monkeypatch.setattr(ml, "time", clock)
    ok = h._burst_single_lane({})
    ev, notes = h.phases[-1]["evidence"], h.phases[-1]["notes"]

    assert ok, notes
    assert ev["fleet_planned"] == ev["fleet_injected"] == 60_000
    assert ev["fleet_shortfall"] == 0
    assert ev["window_extended"] is True
    assert "fleet_injected=60000" in notes and "rate_achieved=" in notes


def test_legacy_loop_fails_short_past_the_bound(tmp_path, monkeypatch):
    clock = FakeClock()
    stack = FakeStack(clock, chunk_cost_s=40.0)
    h = _harness(tmp_path, clock, stack, profile="legacy", minutes=1,
                 cheap_events=True)
    monkeypatch.setattr(ml, "time", clock)
    ok = h._burst_single_lane({})
    ev, notes = h.phases[-1]["evidence"], h.phases[-1]["notes"]

    assert not ok
    assert ev["fleet_injected"] == 30_000
    assert ev["fleet_shortfall"] == 30_000
    assert ev["window_bound_exceeded"] is True
    assert "WORKLOAD TRUNCATED" in notes


# ── the bus offset the injection actually lands on ──────────────────────────
#
# THE DEFECT (2026-08-29). `end_offset` asked kafka-get-offsets for
# `<topic>:0` — partition 0 alone. Keyed injection puts a whole tenant on ONE
# partition by design (measured: partition 3), so the preflight heuristic and
# the accounting baseline read a 900,000-event injection as "nothing here".

def _offset_stack(rc, out):
    st = ml.Stack.__new__(ml.Stack)
    calls: list[dict] = []

    def fake_kafka_tool(tool, args, input_text=None, timeout=0,
                        config_flag="--command-config"):
        calls.append({"tool": tool, "args": list(args)})
        return rc, out, "" if rc == 0 else "boom"

    st.kafka_tool = fake_kafka_tool        # type: ignore[assignment]
    st.calls = calls                       # type: ignore[attr-defined]
    return st


def test_end_offset_sums_every_partition():
    st = _offset_stack(0, "netops.syslog:0:12\nnetops.syslog:1:0\n"
                          "netops.syslog:2:5\nnetops.syslog:3:900001\n")
    assert st.end_offset("netops.syslog") == 900_018
    # ...and it asks for the whole topic, never one partition.
    assert st.calls[0]["args"] == ["--topic", "netops.syslog"]
    assert not any(a.endswith(":0") for a in st.calls[0]["args"])


def test_end_offset_ignores_other_topics_in_the_output():
    st = _offset_stack(0, "netops.flows:0:77\nnetops.syslog:0:3\n")
    assert st.end_offset("netops.syslog") == 3


def test_end_offset_reports_missing_evidence_as_minus_one():
    assert _offset_stack(1, "").end_offset("netops.syslog") == -1
    assert _offset_stack(0, "").end_offset("netops.syslog") == -1
    # A partition with no leader prints an empty offset: unknown, not zero.
    assert _offset_stack(0, "netops.syslog:0:5\nnetops.syslog:1:\n").end_offset(
        "netops.syslog") == -1
