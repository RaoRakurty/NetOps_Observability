# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The CI stability gate (scripts/ci/stack_stability.py), fed fake `docker inspect`.

Installer self-healing FMEA 2026-09-15 §4.7: a single `docker compose ps` sample
reads `running` for a container restarting every 20 s (Keycloak on .123:
RestartCount=106, "Up 17 seconds"). The gate compares two inspections a window
apart. These tests pin its policy without Docker.

Run:  python3 -m pytest tests/test_ci_stack_stability.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "ci"))
import stack_stability as ss

T0 = datetime(2026, 9, 15, 4, 0, 0, tzinfo=timezone.utc)


def _ts(dt: datetime) -> str:
    # Docker's own shape: nanoseconds and a Z suffix.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


def container(cid: str, service: str, *, status: str = "running", restarts: int = 0,
              started: datetime = T0 - timedelta(minutes=5), exit_code: int = 0,
              health: str | None = "healthy", policy: str = "unless-stopped",
              restarting: bool = False) -> dict:
    state: dict = {"Status": status, "Restarting": restarting, "ExitCode": exit_code,
                   "StartedAt": _ts(started)}
    if health is not None:
        state["Health"] = {"Status": health}
    return {"Id": cid, "Name": f"/netops-{service}-1", "RestartCount": restarts,
            "State": state,
            "Config": {"Labels": {ss.SERVICE_LABEL: service,
                                  ss.PROJECT_LABEL: "netops"}},
            "HostConfig": {"RestartPolicy": {"Name": policy}}}


def verdict(before: list[dict], after: list[dict]) -> ss.Verdict:
    return ss.evaluate(ss.parse_inspect(before), ss.parse_inspect(after), T0)


def test_a_steady_stack_is_stable() -> None:
    snap = [container("a", "postgres"), container("b", "keycloak", health=None),
            container("c", "kafka-init", status="exited", policy="no", health=None)]
    v = verdict(snap, snap)
    assert v.stable, v.problems
    assert v.long_running == ["keycloak", "postgres"]
    assert v.one_shots == ["kafka-init"]


def test_a_restart_inside_the_window_fails_even_though_it_reads_running() -> None:
    # The .123 shape: the second sample says "running" again.
    before = [container("k", "keycloak", restarts=105, health=None)]
    after = [container("k", "keycloak", restarts=106, health=None,
                       started=T0 + timedelta(seconds=17))]
    v = verdict(before, after)
    assert not v.stable
    assert any("restarted 1 time" in p for p in v.problems)
    assert any("inside the window" in p for p in v.problems)


def test_a_start_inside_the_window_fails_without_a_restart_count_change() -> None:
    # e.g. `docker compose restart` or a daemon-driven start: RestartCount
    # does not move, StartedAt does.
    before = [container("a", "api", health=None)]
    after = [container("a", "api", health=None, started=T0 + timedelta(seconds=1))]
    v = verdict(before, after)
    assert [p for p in v.problems if "inside the window" in p]


def test_a_start_just_before_the_window_is_fine() -> None:
    snap = [container("a", "api", health=None, started=T0 - timedelta(seconds=1))]
    assert verdict(snap, snap).stable


def test_unhealthy_at_the_end_fails() -> None:
    before = [container("o", "opensearch")]
    after = [container("o", "opensearch", health="unhealthy")]
    v = verdict(before, after)
    assert v.problems == ["netops-opensearch-1: health is unhealthy"]


def test_health_starting_is_a_warning_not_a_failure() -> None:
    snap = [container("d", "opensearch-dashboards", health="starting")]
    v = verdict(snap, snap)
    assert v.stable
    assert v.warnings and "starting" in v.warnings[0]


def test_restarting_state_fails() -> None:
    snap = [container("k", "keycloak", status="restarting", restarting=True,
                      health=None)]
    assert any("crash loop" in p for p in verdict(snap, snap).problems)


@pytest.mark.parametrize("status,exit_code", [("exited", 1), ("created", 0),
                                              ("dead", 137)])
def test_a_long_running_service_not_running_fails(status: str, exit_code: int) -> None:
    snap = [container("n", "nginx", status=status, exit_code=exit_code, health=None)]
    v = verdict(snap, snap)
    assert any(f"state is '{status}'" in p for p in v.problems)


def test_a_one_shot_must_have_exited_zero() -> None:
    ok = [container("i", "opensearch-init", status="exited", policy="no", health=None)]
    bad = [container("i", "opensearch-init", status="exited", exit_code=3,
                     policy="no", health=None)]
    running = [container("i", "opensearch-init", status="running", policy="no",
                         health=None)]
    assert verdict(ok, ok).stable
    assert verdict(bad, bad).problems == [
        "netops-opensearch-init-1: one-shot exited with code 3"]
    assert "expected it to have exited 0" in verdict(running, running).problems[0]


def test_a_one_shot_is_recognised_by_its_init_suffix_even_with_a_restart_policy() -> None:
    snap = [container("g", "gotenberg-tls-init", status="exited", health=None,
                      policy="unless-stopped")]
    v = verdict(snap, snap)
    assert v.stable and v.one_shots == ["gotenberg-tls-init"]


def test_a_one_shot_started_long_ago_is_not_judged_on_its_start_time() -> None:
    snap = [container("i", "kafka-init", status="exited", policy="no", health=None,
                      started=T0 + timedelta(seconds=5))]
    assert verdict(snap, snap).stable


def test_a_recreated_container_fails_both_ways() -> None:
    before = [container("old", "postgres")]
    after = [container("new", "postgres", started=T0 - timedelta(seconds=1))]
    problems = verdict(before, after).problems
    assert any("removed or recreated" in p for p in problems)
    assert any("created or recreated" in p for p in problems)


def test_an_empty_project_is_not_stable() -> None:
    v = verdict([], [])
    assert not v.stable and "observed nothing" in v.problems[0]


def test_never_started_zero_time_parses_as_none() -> None:
    assert ss.parse_docker_time("0001-01-01T00:00:00Z") is None


@pytest.mark.parametrize("raw,expected", [
    ("2026-09-15T03:11:00.123456789Z", datetime(2026, 9, 15, 3, 11, 0, 123456,
                                                 tzinfo=timezone.utc)),
    ("2026-09-15T03:11:00Z", datetime(2026, 9, 15, 3, 11, tzinfo=timezone.utc)),
    ("2026-09-15T05:11:00.5+02:00", datetime(2026, 9, 15, 3, 11, 0, 500000,
                                              tzinfo=timezone.utc)),
])
def test_docker_timestamps_parse(raw: str, expected: datetime) -> None:
    assert ss.parse_docker_time(raw) == expected


def test_an_unparseable_start_time_cannot_be_assessed() -> None:
    bad = container("a", "api")
    bad["State"]["StartedAt"] = "yesterday"
    with pytest.raises(ss.AssessError):
        ss.parse_inspect([bad])


def test_baseline_reports_a_lost_service() -> None:
    snap = [container("a", "postgres")]
    v = verdict(snap, snap)
    lost = ss.compare_baseline({"long_running": ["postgres", "keycloak"],
                                "one_shots": ["kafka-init"]}, v)
    assert lost == ["keycloak: was a running service before, is missing now",
                    "kafka-init: one-shot seen before is missing now"]


# ── the docker seam and the CLI ──────────────────────────────────────────────

class FakeDocker:
    """Serves `docker ps` / `docker inspect` from a queue of snapshots."""

    def __init__(self, snapshots: list[list[dict]], *, ps_rc: int = 0) -> None:
        self.snapshots = snapshots
        self.ps_rc = ps_rc
        self.calls: list[list[str]] = []
        self.current: list[dict] = []

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ["docker", "ps"]:
            if self.ps_rc:
                return subprocess.CompletedProcess(argv, self.ps_rc, "", "daemon down")
            self.current = self.snapshots.pop(0)
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(c["Id"] for c in self.current), "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.current), "")
        raise AssertionError(f"unexpected docker call {argv}")


def test_the_cli_samples_twice_a_window_apart_and_filters_by_project(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snap = [container("a", "postgres")]
    fake = FakeDocker([snap, snap])
    slept: list[float] = []
    out = tmp_path / "services.json"
    rc = ss.main(["--window", "60", "--save-services", str(out)], run=fake,
                 sleep=slept.append)
    assert rc == 0, capsys.readouterr().out
    assert slept == [60.0]
    ps_calls = [c for c in fake.calls if c[:2] == ["docker", "ps"]]
    assert len(ps_calls) == 2
    assert "label=com.docker.compose.project=netops" in ps_calls[0]
    assert json.loads(out.read_text()) == {"long_running": ["postgres"], "one_shots": []}


def test_the_cli_fails_on_a_restart_and_names_it(capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeDocker([[container("k", "keycloak", restarts=1, health=None)],
                       [container("k", "keycloak", restarts=2, health=None)]])
    assert ss.main(["--window", "5"], run=fake, sleep=lambda s: None) == 1
    out = capsys.readouterr().out
    assert "netops-keycloak-1: restarted 1 time" in out and "NOT STABLE" in out


def test_the_cli_fails_against_a_baseline_it_regressed_from(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"long_running": ["postgres", "api"], "one_shots": []}))
    snap = [container("a", "postgres")]
    fake = FakeDocker([snap, snap])
    assert ss.main(["--window", "1", "--baseline-services", str(base)], run=fake,
                   sleep=lambda s: None) == 1


def test_the_cli_reports_could_not_assess_when_docker_is_down(
        capsys: pytest.CaptureFixture[str]) -> None:
    assert ss.main(["--window", "1"], run=FakeDocker([], ps_rc=1),
                   sleep=lambda s: None) == 2
    assert "could not assess" in capsys.readouterr().err


def test_the_cli_rejects_an_absurd_window() -> None:
    assert ss.main(["--window", "0"], run=FakeDocker([]), sleep=lambda s: None) == 2
