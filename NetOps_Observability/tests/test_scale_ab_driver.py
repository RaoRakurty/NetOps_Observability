"""Unit tests for `scripts/scale-ab-driver.py` — the P3 aggregation-plane A/B driver.

The driver is unattended: it redeploys correlation, launches 2.5k-device storm
legs that each cost about an hour of lab time, and decides on its own whether a
leg's numbers are attributable. Everything it can get wrong is expensive, so
everything it can get wrong is tested here against a MOCKED host — no docker, no
harness, no ClickHouse is touched by this suite.

What is asserted, and why it matters:

  state machine / resume  A leg is skipped ONLY when it both ran and was
                          collected; a leg that ran but whose collection died is
                          re-collected, never re-run (that would burn an hour and
                          produce a second run dir for one table row). `--from`
                          overrides the state. A corrupt state file refuses.
  arm verification        OFF and ON differ by exactly one compose file. The arm
                          is read from BOTH replicas, from BOTH the env and the
                          engine's own `corr_agg_enabled`; any disagreement is a
                          MIXED ARM, which no run metric reveals and which
                          therefore must stop the wave before a leg starts.
  cron window             A leg must refuse to START between 03:10 and 04:40 UTC
                          (the 1K canary's onboard absorbs the leg's devices —
                          attempt p2-s012b-08290322), unless the refusal is
                          overridden deliberately.
  run lock                A live run is waited for, never stolen, with a bounded
                          wait and a loud message; a pgrep that fails is a
                          refusal, not "the host is probably idle".
  TTUR scope              The burst window comes from the leg's OWN report.json
                          phase stamps, and the tenant-constant storm-aggregate
                          cid is excluded — it is shared by every leg, so a naive
                          scope attributes it to whichever leg is queried.

Run:  PATH=/home/rao/.local/bin:$PATH python3 -m pytest tests/test_scale_ab_driver.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_driver():
    """Import the hyphen-named driver by path, asserting it does not touch PATH.

    The driver's cron-proof PATH is applied in main(), not at import — as
    module-scope code it leaks into every process that merely imports the file
    (the lesson scale-miniladder.py records, which broke the shellcheck suites).
    """
    path = ROOT / "scripts" / "scale-ab-driver.py"
    spec = importlib.util.spec_from_file_location("scale_ab_driver", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_ab_driver"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, (
        "importing the driver must not mutate PATH — pin it in main() instead")
    return mod


drv = _load_driver()


# ---------------------------------------------------------------------------
# fixtures: a mocked host
# ---------------------------------------------------------------------------
CORR_IDS = ["c" * 64, "d" * 64]
CH_ID = "e" * 64

SIDECAR_METRICS = (
    "# HELP corr_agg_enabled 1 when the Aggregation plane is collapsing repeats.\n"
    "# TYPE corr_agg_enabled gauge\n"
    "corr_agg_enabled {enabled}\n"
    "corr_agg_observed_total 12345\n"
    "corr_agg_suppressed_total 999\n"
)
APP_METRICS = SIDECAR_METRICS + "corr_engine_pending 0\ncorr_engine_cohorts_total 42\n"

TTUR_TSV = ("inc\tversions\tvpi\tsigs\tt1p50\tt1p95\tt1p99\tt1max\ttlast95\t"
            "merged\tundet\tconfirmed\n"
            "13528\t49654\t3.67\t900000\t120\t2100\t2400\t2600\t2700\t12\t44\t180\n")

CRONTAB_DISABLED = (
    "# DISABLED 2026-08-29 (owner): 1K canary paused during the P2-P4 programme\n"
    "#17 3 * * * /usr/bin/python3 /repo/scripts/scale-miniladder.py --devices 1000\n"
    "* * * * * /bin/bash /repo/scripts/stack-watchdog.sh\n"
)
CRONTAB_ENABLED = (
    "17 3 * * * /usr/bin/python3 /repo/scripts/scale-miniladder.py --devices 1000\n"
)


def report_json(runid: str = "08300101abcd", overall: str = "PASS") -> dict:
    """A report.json shaped like a real storm leg's (phases + burst evidence)."""
    return {
        "harness": "scale-miniladder",
        "runid": runid,
        "generated": "2026-08-30T02:10:00Z",
        "overall": overall,
        "phases": [
            {"phase": "preflight", "status": "PASS", "at": "2026-08-30T00:30:00Z",
             "evidence": {}},
            {"phase": "onboard", "status": "PASS", "at": "2026-08-30T00:32:00Z",
             "evidence": {}},
            {"phase": "burst", "status": "PASS", "at": "2026-08-30T00:47:37Z",
             "evidence": {"burst_seconds": 900.0, "injected_total": 900001}},
            {"phase": "drain", "status": "PASS", "at": "2026-08-30T01:04:47Z",
             "evidence": {}},
            {"phase": "correlation_completion", "status": "PASS",
             "at": "2026-08-30T01:06:45Z", "evidence": {}},
            {"phase": "cleanup", "status": "PASS", "at": "2026-08-30T02:10:00Z",
             "evidence": {}},
        ],
    }


class FakeHost:
    """Answers every subprocess the driver makes, and records the calls."""

    def __init__(self, arm: str = "off") -> None:
        self.arm = arm
        self.calls: list[list[str]] = []
        self.procs: list[str] = []
        self.crontab = CRONTAB_DISABLED
        self.pgrep_rc = 0
        self.cleanup_rc = 0
        self.twin_rc = 0
        self.compose_ups: list[tuple[list[str], dict]] = []
        self.ttur_queries: list[str] = []
        self.mtls_fail = False

    def __call__(self, cmd, timeout, cwd=None, env=None):
        self.calls.append(list(cmd))
        if cmd[:2] == ["docker", "ps"]:
            if any("service=correlation" in part for part in cmd):
                return 0, "\n".join(CORR_IDS) + "\n", ""
            if any("service=clickhouse" in part for part in cmd):
                return 0, CH_ID + "\n", ""
            return 0, "", ""
        if cmd[:2] == ["docker", "inspect"]:
            idx = CORR_IDS.index(cmd[2]) if cmd[2] in CORR_IDS else 0
            return 0, (f"/netops-correlation-{3 + idx}|true|healthy|"
                       f"2026-08-30T00:00:0{idx}Z|172.18.0.{9 + idx}\n"), ""
        if cmd[:2] == ["docker", "exec"]:
            return self._exec(cmd)
        if cmd[:2] == ["docker", "compose"]:
            self.compose_ups.append((list(cmd), dict(env or {})))
            self.arm = "on" if drv.AGG_OVERLAY in cmd else "off"
            return 0, "recreated\n", ""
        if cmd[0] == "pgrep":
            if self.pgrep_rc not in (0, 1):
                return self.pgrep_rc, "", "pgrep exploded"
            if not self.procs:
                return 1, "", ""
            return 0, "\n".join(self.procs) + "\n", ""
        if cmd[0] == "crontab":
            return 0, self.crontab, ""
        if cmd[:2] == ["git", "rev-parse"]:
            return 0, "abc123def456\n", ""
        if any(part.endswith("scale-miniladder.py") for part in cmd):
            return self.cleanup_rc, "cleanup-only: 0 devices remain\n", ""
        if any(part.endswith("twin.py") for part in cmd):
            return self.twin_rc, "stories 322/345 (93%)\n", ""
        raise AssertionError(f"unexpected command: {cmd}")

    def _exec(self, cmd):
        target = cmd[2]
        if target == CH_ID:
            sql = cmd[-1]
            if sql.strip() == "SELECT 1":
                return 0, "1\n", ""
            self.ttur_queries.append(sql)
            return 0, TTUR_TSV, ""
        if cmd[3] == "env":
            env = "PATH=/usr/bin\nCORR_HEALTH_SIDECAR_PORT=8094\n"
            if self.arm == "on":
                env += "CORR_AGGREGATION_PLANE=1\n"
            return 0, env, ""
        if cmd[3] == "python":
            probe = cmd[-1]
            enabled = 1 if self.arm == "on" else 0
            if "8094" in probe:
                return 0, SIDECAR_METRICS.format(enabled=enabled), ""
            if self.mtls_fail:
                return 1, "", "ssl handshake failed"
            return 0, APP_METRICS.format(enabled=enabled), ""
        raise AssertionError(f"unexpected docker exec: {cmd}")


class FakeClock:
    def __init__(self, moment: datetime | None = None) -> None:
        self.moment = moment or datetime(2026, 8, 30, 0, 30, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.moment


def make_args(tmp_path: Path, **over):
    args = drv.parse_args(["--run-root", str(tmp_path)])
    args.lock_file = str(tmp_path / ".lock")
    args.log_file = str(tmp_path / "ab-driver.log")
    args.project = "netops"
    args.python = "/usr/bin/python3"
    args.wait_lock_seconds = 120
    args.wait_log_seconds = 0
    args.leg_timeout = 120
    for key, value in over.items():
        setattr(args, key, value)
    return args


def make_driver(tmp_path: Path, host: FakeHost, sleeper=None, clock=None,
                launcher=None, **over):
    args = make_args(tmp_path, **over)
    driver = drv.Driver(args, runner=host, sleeper=sleeper or (lambda _s: None),
                        clock=clock or FakeClock(),
                        launcher=launcher or (lambda *a, **k: None))
    driver.state = {"schema": drv.STATE_SCHEMA, "created": "x", "legs": {}}
    return driver


# ---------------------------------------------------------------------------
# state machine / resume
# ---------------------------------------------------------------------------
def test_legs_to_run_fresh_state_runs_every_leg():
    assert [leg.id for leg in drv.legs_to_run({"legs": {}})] == list(drv.LEG_IDS)


def test_legs_to_run_skips_only_complete_and_collected():
    state = {"legs": {
        "L1": {"status": "complete", "collected": True},
        "L2": {"status": "complete", "collected": False},   # collection died
        "L3": {"status": "running", "collected": False},    # driver was killed
    }}
    assert [leg.id for leg in drv.legs_to_run(state)] == ["L2", "L3", "L4", "L5"]


def test_from_leg_overrides_recorded_state():
    state = {"legs": {leg: {"status": "complete", "collected": True}
                      for leg in drv.LEG_IDS}}
    assert [leg.id for leg in drv.legs_to_run(state, "L3")] == ["L3", "L4", "L5"]


def test_from_leg_rejects_an_unknown_leg():
    with pytest.raises(drv.DriverAbort) as exc:
        drv.legs_to_run({"legs": {}}, "L9")
    assert "not a leg id" in str(exc.value)


def test_state_round_trips_and_is_written_atomically(tmp_path):
    path = str(tmp_path / "ab-state.json")
    state = drv.load_state(path)
    state["legs"]["L1"] = {"status": "complete", "collected": True}
    drv.save_state(path, state)
    assert not os.path.exists(path + ".tmp"), "the temp file must be replaced"
    again = drv.load_state(path)
    assert again["legs"]["L1"]["collected"] is True
    assert again["updated"]


def test_corrupt_state_file_refuses_rather_than_replanning(tmp_path):
    path = tmp_path / "ab-state.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(drv.DriverAbort) as exc:
        drv.load_state(str(path))
    assert "unreadable" in str(exc.value)


def test_foreign_schema_state_file_refuses(tmp_path):
    path = tmp_path / "ab-state.json"
    path.write_text(json.dumps({"schema": "something/else", "legs": {}}),
                    encoding="utf-8")
    with pytest.raises(drv.DriverAbort):
        drv.load_state(str(path))


def test_completed_leg_is_skipped_without_touching_the_host(tmp_path):
    host = FakeHost()
    driver = make_driver(tmp_path, host)
    driver.state["legs"]["L1"] = {"leg": "L1", "status": "complete",
                                  "collected": True, "run_dir": "/x"}
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.run_leg(drv.leg_by_id("L1"))
    assert host.calls == [], "a completed leg must not touch docker at all"


def test_a_leg_that_ran_but_was_not_collected_is_re_collected_not_re_run(tmp_path):
    host = FakeHost()
    run_dir = tmp_path / "agg-10-off-08300030"
    run_dir.mkdir()
    (run_dir / "report.json").write_text(json.dumps(report_json()), encoding="utf-8")
    driver = make_driver(tmp_path, host)
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.state["legs"]["L1"] = {"leg": "L1", "status": "complete",
                                  "collected": False, "run_dir": str(run_dir),
                                  "verdict": "PASS", "problems": []}
    driver.run_leg(drv.leg_by_id("L1"))
    assert driver.state["legs"]["L1"]["collected"] is True
    assert (run_dir / "metrics-final.txt").exists()
    assert (run_dir / "ttur.tsv").exists()
    assert not any(part.endswith("scale-miniladder.py") and "--profile" in cmd
                   for cmd in host.calls for part in cmd), "it must NOT re-run"


def test_a_dead_launched_run_refuses_to_silently_start_a_second_one(tmp_path):
    host = FakeHost()
    run_dir = tmp_path / "agg-10-off-08300030"
    run_dir.mkdir()
    driver = make_driver(tmp_path, host)
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.state["legs"]["L1"] = {"leg": "L1", "status": "running",
                                  "collected": False, "run_dir": str(run_dir),
                                  "problems": []}
    with pytest.raises(drv.DriverAbort) as exc:
        driver.run_leg(drv.leg_by_id("L1"))
    assert "will not silently start a second run" in str(exc.value)


# ---------------------------------------------------------------------------
# arm verification
# ---------------------------------------------------------------------------
def test_compose_argv_differs_by_exactly_one_file():
    off = drv.Driver(make_args(Path("/tmp"))).compose_argv("off", ["up"])
    on = drv.Driver(make_args(Path("/tmp"))).compose_argv("on", ["up"])
    assert drv.AGG_OVERLAY not in off
    assert on[-1] == "up" and on[-2] == drv.AGG_OVERLAY
    assert [part for part in on if part not in off] == [drv.AGG_OVERLAY]


@pytest.mark.parametrize("readings,expected", [
    ([{"env": "1", "metric": 1.0, "error": ""}] * 2, "on"),
    ([{"env": None, "metric": 0.0, "error": ""}] * 2, "off"),
    ([{"env": "0", "metric": 0.0, "error": ""}] * 2, "off"),
    ([{"env": "1", "metric": 1.0, "error": ""},
      {"env": None, "metric": 0.0, "error": ""}], "mixed"),
    ([{"env": "1", "metric": 0.0, "error": ""}] * 2, "mixed"),
    ([{"env": "1", "metric": 1.0, "error": ""},
      {"env": None, "metric": None, "error": "probe failed"}], "unknown"),
    ([], "unknown"),
])
def test_classify_arm(readings, expected):
    assert drv.classify_arm(readings) == expected


def test_prom_value_and_env_flag():
    assert drv.prom_value(SIDECAR_METRICS.format(enabled=1), "corr_agg_enabled") == 1.0
    assert drv.prom_value(SIDECAR_METRICS.format(enabled=0), "corr_agg_enabled") == 0.0
    assert drv.prom_value("# corr_agg_enabled 1\n", "corr_agg_enabled") is None
    assert drv.prom_value("corr_agg_enabled\n", "corr_agg_enabled") is None
    assert drv.env_flag("A=1\nCORR_AGGREGATION_PLANE=1\n",
                        "CORR_AGGREGATION_PLANE") == "1"
    assert drv.env_flag("A=1\n", "CORR_AGGREGATION_PLANE") is None


def test_arm_already_correct_does_not_redeploy(tmp_path):
    host = FakeHost(arm="off")
    driver = make_driver(tmp_path, host)
    driver.ensure_arm("off", "L1")
    assert host.compose_ups == [], "a verified arm must never be redeployed"


def test_arm_switch_uses_the_overlay_and_exports_git_sha(tmp_path):
    host = FakeHost(arm="off")
    driver = make_driver(tmp_path, host)
    driver.ensure_arm("on", "L3")
    assert len(host.compose_ups) == 1
    cmd, env = host.compose_ups[0]
    assert drv.AGG_OVERLAY in cmd
    assert cmd[-4:] == ["--scale", "correlation=2", "correlation"] or \
        cmd[-1] == "correlation"
    assert "--force-recreate" in cmd and "--no-deps" in cmd
    assert "--scale" in cmd and "correlation=2" in cmd
    assert env.get("GIT_SHA") == "abc123def456"


def test_restore_drops_the_overlay(tmp_path):
    host = FakeHost(arm="on")
    driver = make_driver(tmp_path, host)
    driver.ensure_arm("off", "restore")
    cmd, _env = host.compose_ups[0]
    assert drv.AGG_OVERLAY not in cmd, "the OFF arm is the file's ABSENCE"


def test_mixed_arm_aborts_and_never_redeploys(tmp_path):
    host = FakeHost(arm="off")
    original = host._exec

    def half_flagged(cmd):
        if cmd[2] == CORR_IDS[0] and cmd[3] == "env":
            return 0, "CORR_AGGREGATION_PLANE=1\n", ""
        if cmd[2] == CORR_IDS[0] and cmd[3] == "python":
            return 0, SIDECAR_METRICS.format(enabled=1), ""
        return original(cmd)

    host._exec = half_flagged
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.ensure_arm("off", "L1")
    assert "MIXED ARM" in str(exc.value)
    assert host.compose_ups == [], "a mixed arm is diagnosed, never papered over"


def test_arm_that_does_not_take_after_a_redeploy_aborts(tmp_path):
    host = FakeHost(arm="off")

    def deaf_compose(cmd, timeout, cwd=None, env=None):
        if cmd[:2] == ["docker", "compose"]:
            host.compose_ups.append((list(cmd), dict(env or {})))
            return 0, "", ""            # accepted, but the flag never lands
        return FakeHost.__call__(host, cmd, timeout, cwd, env)

    driver = make_driver(tmp_path, host)
    driver.runner = deaf_compose
    with pytest.raises(drv.DriverAbort) as exc:
        driver.ensure_arm("on", "L3")
    assert "UNVERIFIED arm" in str(exc.value)


def test_unreadable_replica_is_never_assumed_to_match(tmp_path):
    host = FakeHost(arm="on")
    original = host._exec

    def one_dead(cmd):
        if cmd[2] == CORR_IDS[1] and cmd[3] == "python":
            return 1, "", "container is not running"
        return original(cmd)

    host._exec = one_dead
    driver = make_driver(tmp_path, host)
    arm, readings = driver.read_arm()
    assert arm == "unknown"
    assert any(r["error"] for r in readings)


# ---------------------------------------------------------------------------
# cron window
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("hhmm,inside", [
    ((3, 9), False), ((3, 10), True), ((3, 17), True), ((4, 39), True),
    ((4, 40), False), ((12, 0), False), ((0, 0), False),
])
def test_in_cron_window(hhmm, inside):
    now = datetime(2026, 8, 30, hhmm[0], hhmm[1], tzinfo=timezone.utc)
    assert drv.in_cron_window(now) is inside


def test_in_cron_window_converts_to_utc():
    from datetime import timedelta as td
    local = datetime(2026, 8, 30, 5, 17,
                     tzinfo=timezone(td(hours=2)))    # 03:17 UTC
    assert drv.in_cron_window(local) is True


def test_leg_refuses_to_start_inside_the_window(tmp_path):
    host = FakeHost()
    driver = make_driver(tmp_path, host,
                         clock=FakeClock(datetime(2026, 8, 30, 3, 17,
                                                  tzinfo=timezone.utc)))
    with pytest.raises(drv.DriverAbort) as exc:
        driver.check_cron_window(drv.leg_by_id("L1"))
    assert "canary window" in str(exc.value)


def test_ignore_cron_window_allows_it_deliberately(tmp_path):
    host = FakeHost()
    driver = make_driver(tmp_path, host, ignore_cron_window=True,
                         clock=FakeClock(datetime(2026, 8, 30, 3, 17,
                                                  tzinfo=timezone.utc)))
    driver.check_cron_window(drv.leg_by_id("L1"))     # must not raise


def test_outside_the_window_is_allowed(tmp_path):
    driver = make_driver(tmp_path, FakeHost())
    driver.check_cron_window(drv.leg_by_id("L1"))


def test_canary_enabled_detection():
    assert drv.canary_enabled(CRONTAB_DISABLED) is False
    assert drv.canary_enabled(CRONTAB_ENABLED) is True


# ---------------------------------------------------------------------------
# run lock / idleness
# ---------------------------------------------------------------------------
def test_lock_status_classification():
    live = json.dumps({"pid": 4055876, "runid": "08292148kdz4",
                       "started": "2026-08-29T21:48:53Z"})
    assert drv.lock_status(live, True)[0] == "busy"
    assert drv.lock_status(live, False)[0] == "stale"
    assert drv.lock_status(live, None)[0] == "unknown"
    assert drv.lock_status("half-written", True)[0] == "unknown"
    assert drv.lock_status(json.dumps({"runid": "x"}), True)[0] == "unknown"


def test_wait_for_idle_waits_for_a_live_run_then_proceeds(tmp_path):
    host = FakeHost()
    lock = tmp_path / ".lock"
    lock.write_text(json.dumps({"pid": 424242, "runid": "storm-s03"}),
                    encoding="utf-8")
    host.procs = ["424242 python3 scale-miniladder.py --run-dir /var/tmp/x"]
    slept = []

    def sleeper(seconds):
        slept.append(seconds)
        if len(slept) == 2:                 # the run lands on the third poll
            host.procs = []
            lock.unlink()

    driver = make_driver(tmp_path, host, sleeper=sleeper)
    driver.pid_alive = lambda pid: True
    driver.wait_for_idle(drv.leg_by_id("L1"))
    assert len(slept) == 2, "it must poll, not race the live run"


def test_wait_for_idle_is_bounded_and_never_forces(tmp_path):
    host = FakeHost()
    (tmp_path / ".lock").write_text(json.dumps({"pid": 1, "runid": "r"}),
                                    encoding="utf-8")
    host.procs = ["1 python3 scale-miniladder.py"]
    driver = make_driver(tmp_path, host, wait_lock_seconds=0)
    driver.pid_alive = lambda pid: True
    with pytest.raises(drv.DriverAbort) as exc:
        driver.wait_for_idle(drv.leg_by_id("L1"))
    assert "NOT forcing" in str(exc.value)
    assert (tmp_path / ".lock").exists(), "the lock must never be removed"


def test_a_failing_pgrep_refuses_rather_than_assuming_idle(tmp_path):
    host = FakeHost()
    host.pgrep_rc = 2
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.wait_for_idle(drv.leg_by_id("L1"))
    assert "cannot prove the host is idle" in str(exc.value)


def test_stale_lock_is_reported_but_not_removed(tmp_path):
    host = FakeHost()
    lock = tmp_path / ".lock"
    lock.write_text(json.dumps({"pid": 999999, "runid": "dead"}), encoding="utf-8")
    driver = make_driver(tmp_path, host)
    driver.pid_alive = lambda pid: False
    driver.wait_for_idle(drv.leg_by_id("L1"))
    assert lock.exists(), "reclaiming a stale lock is the harness's job, not ours"


# ---------------------------------------------------------------------------
# residue / ClickHouse / replicas
# ---------------------------------------------------------------------------
def test_residue_failure_stops_the_leg(tmp_path):
    host = FakeHost()
    host.cleanup_rc = 1
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.residue_check(drv.leg_by_id("L1"))
    assert "residue check FAILED" in str(exc.value)


def test_residue_check_only_ever_names_the_mlx_prefix(tmp_path):
    host = FakeHost()
    driver = make_driver(tmp_path, host)
    driver.residue_check(drv.leg_by_id("L1"))
    cleanup = [cmd for cmd in host.calls if "--cleanup-only" in cmd][0]
    assert cleanup[cleanup.index("--cleanup-only") + 1] == "mlx-"


def test_clickhouse_silence_stops_the_leg_without_restarting_it(tmp_path):
    host = FakeHost()
    original = host._exec

    def dead_ch(cmd):
        if cmd[2] == CH_ID:
            return 1, "", "connection refused"
        return original(cmd)

    host._exec = dead_ch
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.clickhouse_ok(drv.leg_by_id("L1"))
    assert "NOT restarting it" in str(exc.value)
    assert not any("restart" in cmd for cmd in host.calls)


def test_a_missing_replica_stops_the_leg(tmp_path):
    host = FakeHost()

    def one_replica(cmd, timeout, cwd=None, env=None):
        if cmd[:2] == ["docker", "ps"] and any("correlation" in p for p in cmd):
            host.calls.append(list(cmd))
            return 0, CORR_IDS[0] + "\n", ""
        return FakeHost.__call__(host, cmd, timeout, cwd, env)

    driver = make_driver(tmp_path, host)
    driver.runner = one_replica
    with pytest.raises(drv.DriverAbort) as exc:
        driver.replicas_healthy(drv.leg_by_id("L1"))
    assert "expected 2 correlation replicas" in str(exc.value)


# ---------------------------------------------------------------------------
# TTUR scope + SQL
# ---------------------------------------------------------------------------
def test_burst_scope_from_report_phase_stamps():
    scope = drv.burst_scope(report_json())
    assert scope["burst_start"] == "2026-08-30 00:32:37"     # 00:47:37 - 900 s
    assert scope["burst_end"] == "2026-08-30 00:47:37"
    assert scope["converged"] == "2026-08-30 01:06:45"


def test_burst_scope_refuses_a_report_without_a_burst_phase():
    report = report_json()
    report["phases"] = [p for p in report["phases"] if p["phase"] != "burst"]
    with pytest.raises(drv.DriverAbort) as exc:
        drv.burst_scope(report)
    assert "no `burst` phase" in str(exc.value)


def test_burst_scope_refuses_a_missing_duration():
    report = report_json()
    for phase in report["phases"]:
        if phase["phase"] == "burst":
            phase["evidence"] = {}
    with pytest.raises(drv.DriverAbort):
        drv.burst_scope(report)


def test_burst_scope_refuses_an_empty_window():
    report = report_json()
    for phase in report["phases"]:
        if phase["phase"] == "correlation_completion":
            phase["at"] = "2026-08-30T00:40:00Z"      # before the burst ended
    with pytest.raises(drv.DriverAbort) as exc:
        drv.burst_scope(report)
    assert "not after the burst end" in str(exc.value)


def test_burst_scope_falls_back_to_the_last_phase_stamp():
    report = report_json()
    report["phases"] = [p for p in report["phases"]
                        if p["phase"] != "correlation_completion"]
    assert drv.burst_scope(report)["converged"] == "2026-08-30 02:10:00"


def test_agg_cid_is_the_recorded_tenant_constant_id():
    # docs/scale/P1_2P5K_EQUIVALENCE_2026-08-28.md section on the storm aggregate:
    # for tenant `global` the id is bb1e46d6-5462-54dc-8465-777c707b9329.
    assert drv.agg_cid("global") == "bb1e46d6-5462-54dc-8465-777c707b9329"


def test_ttur_sql_scopes_the_burst_and_excludes_the_storm_aggregate():
    sql = drv.ttur_sql(drv.burst_scope(report_json()), drv.agg_cid("global"))
    assert "netops.corr_objects" in sql
    assert "correlation_id != toUUID('bb1e46d6-5462-54dc-8465-777c707b9329')" in sql
    assert "HAVING t0 >= '2026-08-30 00:32:37' AND t0 < '2026-08-30 00:47:37'" in sql
    assert "created_at < '2026-08-30 01:06:45'" in sql
    assert "tenant_scope='__all__'" in sql
    assert sql.rstrip().endswith("FORMAT TSVWithNames")
    assert sql.lstrip().upper().startswith("WITH"), "read-only by construction"


def test_ttur_sql_refuses_unvalidated_literals():
    scope = drv.burst_scope(report_json())
    bad = dict(scope, burst_start="2026-08-30 00:32:37' OR 1=1 --")
    with pytest.raises(drv.DriverAbort):
        drv.ttur_sql(bad, drv.agg_cid("global"))
    with pytest.raises(drv.DriverAbort):
        drv.ttur_sql(scope, "not-a-uuid")


def test_empty_ttur_result_is_an_error_not_a_silent_zero(tmp_path):
    host = FakeHost()
    original = host._exec

    def empty(cmd):
        if cmd[2] == CH_ID and cmd[-1].strip() != "SELECT 1":
            return 0, "inc\tversions\n", ""      # header only
        return original(cmd)

    host._exec = empty
    run_dir = tmp_path / "agg-10-off-08300030"
    run_dir.mkdir()
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.ttur(drv.leg_by_id("L1"), str(run_dir), report_json())
    assert "no data row" in str(exc.value)


# ---------------------------------------------------------------------------
# launch + wait + collect (the whole leg)
# ---------------------------------------------------------------------------
class FakeLauncher:
    """Writes what a real harness writes, and registers itself in the fake
    process table so the driver's liveness check sees it."""

    def __init__(self, host: FakeHost, verdict: str = "PASS",
                 runid: str = "08300101abcd", write_report: bool = True) -> None:
        self.host = host
        self.verdict = verdict
        self.runid = runid
        self.write_report = write_report
        self.argv: list[str] = []

    def __call__(self, argv, log_path, cwd):
        self.argv = list(argv)
        run_dir = argv[argv.index("--run-dir") + 1]
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write("miniladder: preflight PASS\n")
            if self.verdict:
                fh.write(f"miniladder: VERDICT {self.verdict} run {self.runid}: "
                         f"residue 0\n")
        if self.write_report:
            with open(os.path.join(run_dir, "report.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(report_json(self.runid, self.verdict), fh)
        self.host.procs = [f"777 python3 scale-miniladder.py --run-dir {run_dir}"]
        return drv.LaunchHandle(777)


def test_full_leg_happy_path(tmp_path):
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host)
    slept = []

    def sleeper(seconds):
        slept.append(seconds)
        host.procs = []            # the harness exits on the first poll

    driver = make_driver(tmp_path, host, sleeper=sleeper, launcher=launcher)
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.run_leg(drv.leg_by_id("L1"))

    entry = driver.state["legs"]["L1"]
    assert entry["status"] == "complete" and entry["collected"] is True
    assert entry["verdict"] == "PASS" and entry["runid"] == "08300101abcd"
    run_dir = Path(entry["run_dir"])
    assert run_dir.name.startswith("agg-10-off-")
    # the launch is exactly the plan's command, detached
    assert launcher.argv[:2] == ["setsid", "nohup"]
    assert "--profile" in launcher.argv and "t-storm-10-2.5k" in launcher.argv
    assert "2500" in launcher.argv and "1000" in launcher.argv
    # evidence
    assert (run_dir / "metrics-final.txt").exists()
    assert (run_dir / "ttur.tsv").read_text(encoding="utf-8") == TTUR_TSV
    assert (run_dir / "ttur-scope.json").exists()
    assert (run_dir / "ab-leg.json").exists()
    assert (run_dir / "twin-score.log").exists()
    link = tmp_path / "x-08300101abcd"
    assert link.is_symlink() and os.path.realpath(link) == os.path.realpath(run_dir)
    # the OFF arm never redeploys, since the stack already is OFF
    assert host.compose_ups == []
    # both replicas were scraped, and the file names their identity
    metrics = (run_dir / "metrics-final.txt").read_text(encoding="utf-8")
    assert "netops-correlation-3" in metrics and "netops-correlation-4" in metrics
    assert "corr_engine_cohorts_total 42" in metrics, "the mTLS :8443 body"
    leg_evidence = json.loads((run_dir / "ab-leg.json").read_text(encoding="utf-8"))
    assert len(leg_evidence["arm_verification"]) == 2
    assert leg_evidence["ttur"]["row"][0] == "13528"


def test_on_leg_switches_the_arm_once_then_runs(tmp_path):
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host, runid="08300202wxyz")
    driver = make_driver(tmp_path, host, launcher=launcher,
                         sleeper=lambda _s: setattr(host, "procs", []))
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.run_leg(drv.leg_by_id("L3"))
    assert len(host.compose_ups) == 1
    assert drv.AGG_OVERLAY in host.compose_ups[0][0]
    assert host.arm == "on"
    assert driver.state["legs"]["L3"]["collected"] is True


def test_metrics_fall_back_to_the_sidecar_when_mtls_fails(tmp_path):
    host = FakeHost(arm="on")
    host.mtls_fail = True
    run_dir = tmp_path / "agg-10-on-08300030"
    run_dir.mkdir()
    driver = make_driver(tmp_path, host)
    captured = driver.metrics_final(drv.leg_by_id("L3"), str(run_dir))
    body = (run_dir / "metrics-final.txt").read_text(encoding="utf-8")
    assert "FALLBACK" in body, "the source of a number is part of the evidence"
    assert all(c["corr_agg_enabled"] == 1.0 for c in captured)


def test_metrics_failure_on_both_ports_stops_the_leg(tmp_path):
    host = FakeHost(arm="on")

    def all_dead(cmd):
        if cmd[3] == "python":
            return 1, "", "no route to host"
        return 0, "", ""

    host._exec = all_dead
    run_dir = tmp_path / "agg-10-on-08300030"
    run_dir.mkdir()
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.metrics_final(drv.leg_by_id("L3"), str(run_dir))
    assert "either 8443 or 8094" in str(exc.value)


def test_a_harness_that_dies_without_a_verdict_stops_the_wave(tmp_path):
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host, verdict="", write_report=False)
    driver = make_driver(tmp_path, host, launcher=launcher,
                         sleeper=lambda _s: setattr(host, "procs", []))
    driver.state_path = str(tmp_path / "ab-state.json")
    with pytest.raises(drv.DriverAbort) as exc:
        driver.run_leg(drv.leg_by_id("L1"))
    assert "no VERDICT line was written" in str(exc.value)


def test_a_leg_that_overruns_its_budget_stops_the_driver_but_not_the_run(tmp_path):
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host)
    driver = make_driver(tmp_path, host, launcher=launcher, leg_timeout=0,
                         sleeper=lambda _s: None)
    driver.state_path = str(tmp_path / "ab-state.json")
    with pytest.raises(drv.DriverAbort) as exc:
        driver.run_leg(drv.leg_by_id("L1"))
    assert "left alive" in str(exc.value)
    assert host.procs, "the harness keeps running; killing it would leave residue"


def test_a_failed_verdict_is_still_collected(tmp_path):
    """A FAIL leg is data (L0a FAILed `stability` and is a plan baseline)."""
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host, verdict="FAIL")
    driver = make_driver(tmp_path, host, launcher=launcher,
                         sleeper=lambda _s: setattr(host, "procs", []))
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.run_leg(drv.leg_by_id("L1"))
    assert driver.state["legs"]["L1"]["verdict"] == "FAIL"
    assert driver.state["legs"]["L1"]["collected"] is True


def test_symlink_refuses_to_repoint_another_legs_runid(tmp_path):
    host = FakeHost()
    other = tmp_path / "agg-25-off-08300100"
    other.mkdir()
    (tmp_path / "x-08300101abcd").symlink_to(other)
    run_dir = tmp_path / "agg-10-off-08300030"
    run_dir.mkdir()
    driver = make_driver(tmp_path, host)
    with pytest.raises(drv.DriverAbort) as exc:
        driver.symlink_runid("08300101abcd", str(run_dir))
    assert "refusing to repoint" in str(exc.value)


def test_run_dir_is_never_reused(tmp_path):
    host = FakeHost()
    driver = make_driver(tmp_path, host)
    (tmp_path / "agg-10-off-08300030").mkdir()
    with pytest.raises(drv.DriverAbort) as exc:
        driver.launch(drv.leg_by_id("L1"))
    assert "already exists" in str(exc.value)


# ---------------------------------------------------------------------------
# the wave
# ---------------------------------------------------------------------------
def test_run_stops_on_the_first_failure_and_documents_the_stack(tmp_path):
    host = FakeHost(arm="off")
    host.cleanup_rc = 1                      # residue check fails on L1
    driver = make_driver(tmp_path, host)
    driver.state_path = str(tmp_path / "ab-state.json")
    rc = driver.run()
    assert rc == 1
    state = json.loads((tmp_path / "ab-state.json").read_text(encoding="utf-8"))
    assert "residue check FAILED" in state["stop_reason"]
    assert state["stack_state"]
    assert "L2" not in state["legs"], "no later leg may be started or recorded"


def test_run_completes_the_wave_and_restores_the_default_arm(tmp_path):
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host)
    runids = iter(f"0830010{i}abcd" for i in range(1, 9))

    def launch(argv, log_path, cwd):
        launcher.runid = next(runids)
        return launcher(argv, log_path, cwd)

    driver = make_driver(tmp_path, host, launcher=launch,
                         sleeper=lambda _s: setattr(host, "procs", []))
    driver.state_path = str(tmp_path / "ab-state.json")
    rc = driver.run()
    assert rc == 0
    state = json.loads((tmp_path / "ab-state.json").read_text(encoding="utf-8"))
    assert all(state["legs"][leg]["collected"] for leg in drv.LEG_IDS)
    assert state["final_arm_restored"] is True
    # exactly two redeploys: OFF->ON before L3, ON->OFF after L5 (plan section 3)
    assert len(host.compose_ups) == 2
    assert drv.AGG_OVERLAY in host.compose_ups[0][0]
    assert drv.AGG_OVERLAY not in host.compose_ups[1][0]
    assert host.arm == "off"


def test_rerunning_a_finished_wave_is_a_no_op(tmp_path):
    host = FakeHost(arm="off")
    state = {"schema": drv.STATE_SCHEMA, "created": "x", "legs": {
        leg: {"status": "complete", "collected": True, "run_dir": "/x"}
        for leg in drv.LEG_IDS}}
    (tmp_path / "ab-state.json").write_text(json.dumps(state), encoding="utf-8")
    driver = make_driver(tmp_path, host, restore_arm=False)
    assert driver.run() == 0
    assert not any(cmd[:2] == ["docker", "compose"] for cmd in host.calls)


def test_dry_run_touches_nothing(tmp_path, capsys):
    host = FakeHost()
    driver = make_driver(tmp_path, host)
    assert driver.dry_run() == 0
    assert host.calls == []
    out = capsys.readouterr().out
    for leg in drv.LEG_IDS:
        assert leg in out
    assert "compose.agg.yml" in out
    assert not (tmp_path / "ab-state.json").exists()


def test_the_five_legs_are_the_plans_legs():
    assert [(leg.id, leg.profile, leg.arm, leg.dir_prefix) for leg in drv.LEGS] == [
        ("L1", "t-storm-10-2.5k", "off", "agg-10-off"),
        ("L2", "t-storm-25-2.5k", "off", "agg-25-off"),
        ("L3", "t-storm-10-2.5k", "on", "agg-10-on"),
        ("L4", "t-storm-25-2.5k", "on", "agg-25-on"),
        ("L5", "t-storm-2.5k", "on", "agg-2p5k-on"),
    ]


def test_a_transient_pgrep_failure_does_not_tear_down_a_live_leg(tmp_path):
    """Mid-leg, an unreadable process table means 'still running', not 'done'.

    The opposite reading would declare a running leg finished and start the next
    one on top of it — two harnesses on one 198.18/15 fleet.
    """
    host = FakeHost(arm="off")
    launcher = FakeLauncher(host)
    polls = []

    def sleeper(_seconds):
        polls.append(1)
        if len(polls) == 1:
            host.pgrep_rc = 2          # the process table goes unreadable
        else:
            host.pgrep_rc = 0
            host.procs = []            # then the harness really is gone

    driver = make_driver(tmp_path, host, launcher=launcher, sleeper=sleeper)
    driver.state_path = str(tmp_path / "ab-state.json")
    driver.run_leg(drv.leg_by_id("L1"))
    assert len(polls) >= 2, "it must keep waiting through the failed probe"
    assert driver.state["legs"]["L1"]["collected"] is True


def test_only_real_harness_processes_count_as_busy(tmp_path):
    """`pgrep -af scale-miniladder.py` also matches command lines that merely
    MENTION the harness — a grep, a tool wrapper quoting the name (observed on
    this host). Waiting on one of those would stall the wave for its whole lock
    budget; running while a real one lives would put two harnesses on one fleet.
    """
    host = FakeHost()
    host.procs = [
        "24420 /bin/bash -c eval 'pgrep -af scale-miniladder.py | head -3'",
        "99 grep -n scale-miniladder.py",
    ]
    driver = make_driver(tmp_path, host)
    assert driver.harness_processes() == [], "mentions are not processes"
    host.procs = [
        "4055876 python3 scripts/scale-miniladder.py --profile t-storm-2.5k "
        "--run-dir /var/tmp/scale-runs/storm-s03-08292148",
        "17 /usr/bin/python3 /repo/scripts/scale-miniladder.py --devices 1000",
    ]
    assert len(driver.harness_processes()) == 2, "both real invocations count"
    assert len(driver.leg_running("/var/tmp/scale-runs/storm-s03-08292148")) == 1
