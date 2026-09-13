# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The preflight disk-headroom + host-quiet gate (tracker 210).

WHY THIS GATE EXISTS. `storm-s10` (run `09012025x578`) started with **10.8 GiB**
root-fs free while concurrent CI suites drew ~3.1 GiB and pushed `node_load1` to
16-38 (the passing morning leg peaked at 14-17). Mid-burst the host crossed
OpenSearch's flood-stage watermark — 5 % of the 77 GiB root, ~3.85 GiB — by
about 0.4 GiB. Every index went read-only-allow-delete for eleven minutes, every
bulk write got 429 `cluster_block_exception`, and the vector router's
`opensearch_syslog` sink **discarded 291,296 syslog evidence docs** as
retry-exhausted. Either factor alone would not have crossed.

The insidious part: the Kafka→engine lane was intact, so accounting balanced,
drain and completion passed, and the harness reported gates green. The leg ran
**graded** and only a later diagnosis found the search/evidence copy of the
syslog lane was permanently gone. Preflight was not measuring either input.

WHAT THIS GATE IS NOT. It refuses BEFORE the leg runs. It grades nothing and
changes NO gate semantics — every clause of
`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md` is evaluated exactly as before on
any leg that starts, so a V1 rerun on a quiet host is byte-for-byte the run it
was. That is why this is not a V2 profile.

What is asserted here:

  refusal            below `--min-free-gib` or above `--max-load1`, preflight
                     REFUSES, with both readings in the evidence.
  unreadable probe   an unreadable `/proc/loadavg` or `shutil.disk_usage` is a
                     VIOLATION, not a pass — the whole failure mode was that
                     nobody was measuring (CLAUDE.md 16.1).
  --allow-unquiet    proceeds, but stamps UNQUIET into the preflight evidence
                     AND into `report.json` `parameters`, so a graded verdict
                     can never silently come from an unquiet host.
  boundaries         the free-space floor and the load bound are inclusive on
                     the passing side (exactly 10.0 GiB / exactly 6.0 passes).

Run:  python3 -m pytest tests/test_miniladder_host_quiet.py -q
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder_host_quiet",
                                                  path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_host_quiet"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, "import must not rewrite PATH"
    return mod


ml = _load_harness()

GIB = 1024 ** 3

# A throwaway /proc/loadavg stand-in. Module-scoped so it is removed when the
# interpreter exits — a test must not leave a fixture file in the source tree.
_TMP = tempfile.TemporaryDirectory(prefix="miniladder-host-quiet-")
LOADAVG_FIXTURE = Path(_TMP.name) / "loadavg"


class FakeUsage:
    def __init__(self, free_gib: float, total_gib: float = 77.0) -> None:
        self.free = int(free_gib * GIB)
        self.total = int(total_gib * GIB)
        self.used = self.total - self.free


def patch_host(monkeypatch, free_gib: float, load1: str,
               disk_exc: OSError | None = None) -> None:
    def usage(_path):
        if disk_exc is not None:
            raise disk_exc
        return FakeUsage(free_gib)
    monkeypatch.setattr(shutil, "disk_usage", usage)
    monkeypatch.setattr(ml.shutil, "disk_usage", usage)
    LOADAVG_FIXTURE.write_text(load1)
    monkeypatch.setattr(ml, "LOADAVG_PATH", str(LOADAVG_FIXTURE))


# ---------------------------------------------------------------------------
# the readings
# ---------------------------------------------------------------------------
def test_quiet_host_has_no_violations(monkeypatch):
    patch_host(monkeypatch, 11.0, "2.90 3.10 3.40 4/2078 738348")
    readings = ml.host_quiet_readings(10.0, 6.0,
                                      loadavg_path=ml.LOADAVG_PATH)
    assert readings["free_gib"] == 11.0
    assert readings["load1"] == 2.9
    assert ml.host_quiet_problems(readings) == []


def test_storm_s10s_disk_reading_is_refused(monkeypatch):
    """10.8 GiB free is what s10 started with — below the 10 GiB floor it is
    not, but s10's load1 of 16-38 is; both are checked, and the message names
    the incident so the operator knows what they are being protected from."""
    patch_host(monkeypatch, 9.9, "22.10 20.00 18.00 6/2100 1")
    readings = ml.host_quiet_readings(10.0, 6.0, loadavg_path=ml.LOADAVG_PATH)
    problems = ml.host_quiet_problems(readings)
    assert len(problems) == 2
    assert "9.9 GiB free" in problems[0] and "291,296" in problems[0]
    assert "load1 22.10" in problems[1] and "storm-s10" in problems[1]


@pytest.mark.parametrize("free_gib,expect_problem", [
    (9.99, True),
    (10.0, False),      # the floor is INCLUSIVE on the passing side
    (10.01, False),
])
def test_free_space_floor_boundary(monkeypatch, free_gib, expect_problem):
    patch_host(monkeypatch, free_gib, "1.00 1.00 1.00 1/1 1")
    problems = ml.host_quiet_problems(
        ml.host_quiet_readings(10.0, 6.0, loadavg_path=ml.LOADAVG_PATH))
    assert bool(problems) is expect_problem


@pytest.mark.parametrize("load1,expect_problem", [
    ("6.01 1 1 1/1 1", True),
    ("6.00 1 1 1/1 1", False),   # the bound is INCLUSIVE on the passing side
    ("5.99 1 1 1/1 1", False),
])
def test_load_bound_boundary(monkeypatch, load1, expect_problem):
    patch_host(monkeypatch, 40.0, load1)
    problems = ml.host_quiet_problems(
        ml.host_quiet_readings(10.0, 6.0, loadavg_path=ml.LOADAVG_PATH))
    assert bool(problems) is expect_problem


def test_an_unreadable_loadavg_is_a_violation_not_a_pass(monkeypatch):
    patch_host(monkeypatch, 40.0, "1.0 1 1 1/1 1")
    monkeypatch.setattr(ml, "LOADAVG_PATH", "/nonexistent/loadavg")
    readings = ml.host_quiet_readings(10.0, 6.0,
                                      loadavg_path="/nonexistent/loadavg")
    problems = ml.host_quiet_problems(readings)
    assert readings["load1"] == -1.0 and readings["load1_error"]
    assert len(problems) == 1 and "UNKNOWN" in problems[0]


def test_a_garbage_loadavg_is_a_violation(monkeypatch):
    patch_host(monkeypatch, 40.0, "not-a-number 1 1 1/1 1")
    problems = ml.host_quiet_problems(
        ml.host_quiet_readings(10.0, 6.0, loadavg_path=ml.LOADAVG_PATH))
    assert len(problems) == 1 and "not a number" in problems[0]


def test_an_unstatable_filesystem_is_a_violation(monkeypatch):
    patch_host(monkeypatch, 40.0, "1.0 1 1 1/1 1",
               disk_exc=PermissionError(13, "Permission denied"))
    readings = ml.host_quiet_readings(10.0, 6.0, loadavg_path=ml.LOADAVG_PATH)
    problems = ml.host_quiet_problems(readings)
    assert readings["free_gib"] == -1.0
    assert len(problems) == 1 and "headroom is UNKNOWN" in problems[0]


def test_readings_carry_the_bounds_they_were_judged_against(monkeypatch):
    patch_host(monkeypatch, 40.0, "1.0 1 1 1/1 1")
    readings = ml.host_quiet_readings(12.0, 4.0, loadavg_path=ml.LOADAVG_PATH)
    assert readings["min_free_gib"] == 12.0
    assert readings["max_load1"] == 4.0
    assert readings["filesystem"] == ml.HOST_QUIET_FS


# ---------------------------------------------------------------------------
# the defaults and the CLI
# ---------------------------------------------------------------------------
def test_defaults_match_the_v1_environment_clause():
    """V1 section 8(e): >= 10 GiB free and a quiet host. s11 launched at 2.9."""
    assert ml.MIN_FREE_GIB_DEFAULT == 10.0
    assert ml.MAX_LOAD1_DEFAULT == 6.0
    args = ml.parse_args([])
    assert args.min_free_gib == 10.0
    assert args.max_load1 == 6.0
    assert args.allow_unquiet is False


def test_the_flags_are_settable():
    args = ml.parse_args(["--min-free-gib", "20", "--max-load1", "2.5",
                          "--allow-unquiet"])
    assert args.min_free_gib == 20.0
    assert args.max_load1 == 2.5
    assert args.allow_unquiet is True


# ---------------------------------------------------------------------------
# how preflight uses it
# ---------------------------------------------------------------------------
class StubRunner:
    """Just enough of the Harness for the gate block of preflight().

    preflight() is long; this exercises ONLY its first block by driving the
    same code path with a stub whose next probe raises, so the test asserts the
    refusal (or the pass-through) without a stack.
    """

    def __init__(self, args) -> None:
        self.args = args
        self.phases: list[dict] = []
        self.host_quiet = "unmeasured"
        self.preflight_ok = False

    phase = ml.Harness.phase
    preflight = ml.Harness.preflight

    class _Stack:
        def service_states(self):
            raise RuntimeError("STOP — the gate let the run continue")

    stack = _Stack()


def _preflight_gate(monkeypatch, free_gib, load1, allow_unquiet):
    patch_host(monkeypatch, free_gib, load1)
    args = ml.parse_args(["--allow-unquiet"] if allow_unquiet else [])
    runner = StubRunner(args)
    try:
        runner.preflight()
    except RuntimeError as exc:
        assert "STOP" in str(exc)
        return runner, "continued"
    return runner, "refused"


def test_preflight_refuses_before_probing_anything_else(monkeypatch):
    """The refusal is FIRST: it must not cost a 180 s consumer settle wait."""
    runner, outcome = _preflight_gate(monkeypatch, 3.4, "22.0 1 1 1/1 1", False)
    assert outcome == "refused"
    assert runner.phases[-1]["phase"] == "preflight"
    assert runner.phases[-1]["status"] == "FAIL"
    quiet = runner.phases[-1]["evidence"]["host_quiet"]
    assert quiet["verdict"] == "REFUSED"
    assert quiet["free_gib"] == 3.4 and quiet["load1"] == 22.0
    assert len(quiet["violations"]) == 2
    assert runner.host_quiet == "UNQUIET"


def test_allow_unquiet_proceeds_and_stamps_unquiet(monkeypatch):
    runner, outcome = _preflight_gate(monkeypatch, 3.4, "22.0 1 1 1/1 1", True)
    assert outcome == "continued"          # the run went on to the next probe
    quiet = runner.phases[-1]["evidence"]["host_quiet"] if runner.phases else None
    # preflight aborted at the next probe, so no phase was recorded — the
    # STAMP is what matters and it is on the runner.
    assert quiet is None
    assert runner.host_quiet == "UNQUIET"


def test_a_quiet_host_records_ok_and_continues(monkeypatch):
    runner, outcome = _preflight_gate(monkeypatch, 40.0, "1.5 1 1 1/1 1", False)
    assert outcome == "continued"
    assert runner.host_quiet == "OK"


def test_report_parameters_carry_the_host_quiet_verdict():
    """A graded verdict can never silently come from an unquiet host: the
    stamp travels in report.json, not only in the console."""
    source = (ROOT / "scripts" / "scale-miniladder.py").read_text()
    params = source.split('"parameters": {', 1)[1].split("},", 1)[0]
    for key in ('"host_quiet"', '"min_free_gib"', '"max_load1"',
                '"allow_unquiet"'):
        assert key in params, f"{key} missing from report.json parameters"


# ---------------------------------------------------------------------------
# the settle (tracker 286)
# ---------------------------------------------------------------------------
# WHY. `scale-miniladder-nightly` was red every night from 2026-09-06 to
# 2026-09-12 with `host load1 N exceeds the 6.00 bound` at N = 6.91 / 7.18 /
# 7.48 / 7.78 / 8.09 / 8.24 / 8.55 — each reading taken seconds after the step
# that built two vite bundles, ran `install.py --tls=yes` and spent a JVM per
# topic across 16 topics on a 4-vCPU shared VM. load1 is a ~60 s exponential
# average, so a reading taken THEN describes work that had already stopped.
#
# The settle waits for that to decay and then judges a REAL reading. What these
# tests pin is that it is patience and nothing else:
#
#   * the bound is never raised and no reading is ever fabricated — a host that
#     stays loud still REFUSES, and refuses with the whole load1 curve in the
#     evidence;
#   * only a load1 violation is waited on. Disk headroom does not come back by
#     waiting, and an UNREADABLE probe is the exact failure the gate exists to
#     stop, so both refuse at once — waiting on them would be the gate looking
#     away (16.1);
#   * the DEFAULT is off, so every existing caller keeps today's instant
#     refusal, byte for byte.

class FakeWait:
    """An injectable sleep+clock, so the wait is tested without taking one.

    Every `sleep(n)` advances the clock by exactly `n` and appends it, which is
    what lets a test assert that NOTHING was waited on the paths that must
    refuse at once.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def clock(self) -> float:
        return self.now


def decaying_loadavg(monkeypatch, free_gib: float, load1s: list[str]):
    """Point the harness at a /proc/loadavg that reads a different value each
    time — the decay curve of a bring-up that has finished. The LAST value is
    what every further read returns.
    """
    def usage(_path):
        return FakeUsage(free_gib)
    monkeypatch.setattr(shutil, "disk_usage", usage)
    monkeypatch.setattr(ml.shutil, "disk_usage", usage)
    monkeypatch.setattr(ml, "LOADAVG_PATH", str(LOADAVG_FIXTURE))
    remaining = list(load1s)
    LOADAVG_FIXTURE.write_text(remaining[0])

    real_read = ml.read_load1

    def read(path=None):
        value = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        LOADAVG_FIXTURE.write_text(value)
        return real_read(path)

    monkeypatch.setattr(ml, "read_load1", read)


def test_a_quiet_host_is_never_waited_on(monkeypatch):
    """The settle must cost a quiet host nothing — not one poll."""
    patch_host(monkeypatch, 40.0, "1.50 1 1 1/1 1")
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 420.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    assert ml.host_quiet_problems(readings) == []
    assert trail["outcome"] == "quiet-on-first-reading"
    assert wait.slept == []


def test_the_default_is_off_so_a_loud_host_still_refuses_instantly(monkeypatch):
    """Every caller that does not opt in keeps today's behaviour exactly: one
    reading, an instant refusal, nothing touched."""
    patch_host(monkeypatch, 40.0, "8.55 7 6 1/1 1")
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 0.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    assert ml.host_quiet_problems(readings)      # still refused
    assert trail["outcome"] == "no-settle-requested"
    assert wait.slept == []
    assert ml.HOST_QUIET_SETTLE_SECONDS_DEFAULT == 0


def test_the_bring_up_decay_tail_settles(monkeypatch):
    """The nightly's actual shape: 8.55 at the gate, decaying once the bring-up
    stops. The verdict is passed on the reading taken AFTER the wait, and that
    reading is a real one."""
    decaying_loadavg(monkeypatch, 40.0,
                     ["8.55 7 6 1/1 1", "7.10 7 6 1/1 1", "5.20 7 6 1/1 1"])
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 420.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    assert ml.host_quiet_problems(readings) == []
    assert readings["load1"] == 5.2          # the reading judged is the real one
    assert trail["outcome"] == "settled"
    assert [p["load1"] for p in trail["polls"]] == [8.55, 7.1, 5.2]
    assert wait.slept == [ml.HOST_QUIET_SETTLE_POLL_S] * 2
    assert trail["waited_s"] == 2 * ml.HOST_QUIET_SETTLE_POLL_S


def test_a_host_that_never_comes_down_still_refuses(monkeypatch):
    """The bound is not raised and the wait is not a pass. This is the clause
    that keeps the settle from being `--allow-unquiet` with extra steps."""
    patch_host(monkeypatch, 40.0, "8.55 7 6 1/1 1")
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 42.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    problems = ml.host_quiet_problems(readings)
    assert len(problems) == 1 and "load1 8.55" in problems[0]
    assert trail["outcome"] == "timeout"
    assert trail["waited_s"] == pytest.approx(42.0)
    # …and it waited the WHOLE budget, in poll-sized steps with a short last one
    assert sum(wait.slept) == pytest.approx(42.0)
    assert wait.slept[-1] == pytest.approx(2.0)


def test_a_disk_violation_is_never_waited_on(monkeypatch):
    """Free space does not come back by itself, and it is the more dangerous of
    the two readings — s10 crossed OpenSearch's flood-stage watermark and lost
    291,296 evidence docs. Refuse at once, however large the budget."""
    patch_host(monkeypatch, 3.4, "1.50 1 1 1/1 1")
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 420.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    assert trail["outcome"] == "not-settleable"
    assert wait.slept == []
    assert ml.host_quiet_problems(readings)


def test_an_unreadable_probe_is_never_waited_on(monkeypatch):
    """An unmeasured host is not a quiet one, and it does not become one by
    waiting — the whole failure mode was that nobody was measuring (16.1)."""
    patch_host(monkeypatch, 40.0, "1.50 1 1 1/1 1",
               disk_exc=OSError("no such filesystem"))
    wait = FakeWait()
    _readings, trail = ml.settle_host_quiet(10.0, 6.0, 420.0,
                                            loadavg_path=ml.LOADAVG_PATH,
                                            sleep=wait.sleep, clock=wait.clock)
    assert trail["outcome"] == "not-settleable"
    assert wait.slept == []


def test_a_disk_violation_appearing_mid_settle_stops_the_wait(monkeypatch):
    """The load came down; the filesystem filled while we waited. That is no
    longer a settleable reading, so the wait ends there instead of burning the
    rest of the budget on a violation it cannot fix."""
    free = [40.0, 40.0, 3.4]

    def usage(_path):
        return FakeUsage(free.pop(0) if len(free) > 1 else free[0])
    monkeypatch.setattr(shutil, "disk_usage", usage)
    monkeypatch.setattr(ml.shutil, "disk_usage", usage)
    decaying_loadavg(monkeypatch, 40.0,
                     ["8.55 7 6 1/1 1", "7.10 7 6 1/1 1", "7.00 7 6 1/1 1"])
    monkeypatch.setattr(shutil, "disk_usage", usage)
    monkeypatch.setattr(ml.shutil, "disk_usage", usage)
    wait = FakeWait()
    readings, trail = ml.settle_host_quiet(10.0, 6.0, 420.0,
                                           loadavg_path=ml.LOADAVG_PATH,
                                           sleep=wait.sleep, clock=wait.clock)
    assert trail["outcome"] == "not-settleable"
    assert wait.slept == [ml.HOST_QUIET_SETTLE_POLL_S] * 2
    assert len(ml.host_quiet_problems(readings)) == 2


def test_the_summary_carries_the_decay_curve():
    """A refusal that says only "8.55 exceeds 6.00" cannot be told apart from
    one that waited seven minutes and watched it sit there. The curve is what
    the NEXT diagnosis starts from."""
    line = ml.settle_summary({
        "outcome": "timeout", "waited_s": 420.0, "requested_s": 420.0,
        "polls": [{"at_s": 0.0, "load1": 8.55}, {"at_s": 10.0, "load1": 8.40}]})
    assert "timeout" in line and "420s" in line
    assert "8.55@0s" in line and "8.40@10s" in line


# ---------------------------------------------------------------------------
# how preflight uses the settle
# ---------------------------------------------------------------------------
def _preflight_with_settle(monkeypatch, load1s, settle_seconds, free_gib=40.0):
    decaying_loadavg(monkeypatch, free_gib, load1s)
    wait = FakeWait()
    monkeypatch.setattr(ml.time, "sleep", wait.sleep)
    monkeypatch.setattr(ml.time, "monotonic", wait.clock)
    args = ml.parse_args(["--host-quiet-settle-seconds", str(settle_seconds)])
    runner = StubRunner(args)
    try:
        runner.preflight()
    except RuntimeError as exc:
        assert "STOP" in str(exc)
        return runner, "continued", wait
    return runner, "refused", wait


def test_preflight_waits_out_the_bring_up_and_continues(monkeypatch):
    runner, outcome, wait = _preflight_with_settle(
        monkeypatch, ["8.55 7 6 1/1 1", "5.10 7 6 1/1 1"], 420)
    assert outcome == "continued"
    assert runner.host_quiet == "OK"
    assert wait.slept == [ml.HOST_QUIET_SETTLE_POLL_S]


def test_preflight_refuses_after_a_settle_and_shows_the_curve(monkeypatch):
    """The refusal is unchanged; what is added is the evidence that we waited."""
    runner, outcome, _wait = _preflight_with_settle(
        monkeypatch, ["8.55 7 6 1/1 1"], 30)
    assert outcome == "refused"
    assert runner.host_quiet == "UNQUIET"
    phase = runner.phases[-1]
    assert phase["status"] == "FAIL"
    quiet = phase["evidence"]["host_quiet"]
    assert quiet["verdict"] == "REFUSED"
    assert quiet["settle"]["outcome"] == "timeout"
    assert [p["load1"] for p in quiet["settle"]["polls"]] == [8.55] * 4
    assert "host-quiet settle: timeout" in phase["notes"]
    assert "load1 8.55@0s" in phase["notes"]


def test_the_settle_flag_defaults_to_off_and_is_settable():
    assert ml.parse_args([]).host_quiet_settle_seconds == 0
    assert ml.parse_args(
        ["--host-quiet-settle-seconds", "420"]).host_quiet_settle_seconds == 420.0


def test_report_parameters_carry_the_settle_budget():
    """The wait is part of how a verdict was reached, so it travels with it."""
    source = (ROOT / "scripts" / "scale-miniladder.py").read_text()
    params = source.split('"parameters": {', 1)[1].split("},", 1)[0]
    assert '"host_quiet_settle_seconds"' in params


def test_the_nightly_opts_in_and_does_not_reach_for_allow_unquiet():
    """The workflow is the caller this was built for, and the two things it
    must NOT do are raise the bound and stamp UNQUIET."""
    wf = (ROOT.parent / ".github" / "workflows"
          / "scale-miniladder-nightly.yml").read_text()
    # The COMMAND, not the file: the comment above it names both rejected fixes
    # and has to keep saying why they were rejected.
    cmd = wf.split("python3 scripts/scale-miniladder.py", 1)[1].split("\n\n", 1)[0]
    assert "--host-quiet-settle-seconds 420" in cmd
    assert "--allow-unquiet" not in cmd
    assert "--max-load1" not in cmd
