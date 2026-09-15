# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The CI chaos wrapper (scripts/ci/chaos_install.py) without Docker.

Installer self-healing FMEA 2026-09-15 §3.7 T1: SIGKILL postgres after TLS
phase A converged and before phase B, and the install must still exit 0. The
wrapper must fire exactly then, exactly once, and must FAIL when no chaos was
injected — a chaos leg that killed nothing and went green is a test that lied.

Run:  python3 -m pytest tests/test_ci_chaos_install.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "ci"))
import chaos_install as ci


def stage(sid: str, status: str) -> str:
    return "@CX@ " + json.dumps({"kind": "stage", "id": sid, "title": sid,
                                 "status": status}, separators=(",", ":")) + "\n"


# The real order install.py emits: step(up-b) closes mint and opens up-b in
# the same instant, then stop_stores_cleanly runs.
TLS_LINES = [
    "=== starting stack (TLS phase A: mint identities) ===\n",
    stage("up-a", "start"), "[ ok  ] services started\n",
    stage("up-a", "ok"), stage("mint", "start"),
    "[ ok  ] identities minted\n",
    stage("mint", "ok"), stage("up-b", "start"),
    "[info ] stopping postgres, clickhouse, kafka, opensearch cleanly…\n",
    stage("up-b", "ok"),
    '@CX@ {"kind":"result","status":"ok"}\n',
]


class FakeDocker:
    def __init__(self, *, running: list[str] | None = None, kill_rc: int = 0,
                 states: list[dict] | None = None) -> None:
        self.running = ["pgid123456789"] if running is None else running
        self.kill_rc = kill_rc
        self.states = states if states is not None else [{"Status": "exited",
                                                          "ExitCode": 137}]
        self.calls: list[list[str]] = []

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, "\n".join(self.running), "")
        if argv[:2] == ["docker", "kill"]:
            err = "" if self.kill_rc == 0 else "Error: container is not running"
            return subprocess.CompletedProcess(argv, self.kill_rc, "", err)
        if argv[:2] == ["docker", "inspect"]:
            st = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return subprocess.CompletedProcess(
                argv, 0, json.dumps(st) + "|/netops-postgres-1\n", "")
        raise AssertionError(f"unexpected docker call {argv}")


def drive(lines: list[str], fake: FakeDocker):
    trigger = ci.Trigger()
    ev = ci.Evidence(service="postgres")
    seen: list[str] = []
    ci.watch(iter(lines), seen.append, trigger,
             ci.Docker("netops", "postgres", fake, sleep=lambda s: None), ev)
    return trigger, ev, seen


def test_it_kills_once_between_mint_ok_and_the_phase_b_stop() -> None:
    fake = FakeDocker()
    trigger, ev, seen = drive(TLS_LINES, fake)
    kills = [c for c in fake.calls if c[:2] == ["docker", "kill"]]
    assert kills == [["docker", "kill", "-s", "KILL", "pgid123456789"]]
    assert ev.triggered_on == "mint:ok"
    # The kill happens before the installer's clean-stop line is even read.
    kill_note = next(i for i, s in enumerate(seen) if s.startswith("[chaos] docker kill"))
    stop_line = next(i for i, s in enumerate(seen) if "stopping postgres" in s)
    assert kill_note < stop_line
    assert ev.landed()
    assert ci.verdict(0, trigger, ev) == (
        0, ("postgres was SIGKILLed between phase A and B and the install still "
            "exited 0"))


def test_the_container_is_resolved_at_phase_a_so_the_kill_is_one_call() -> None:
    fake = FakeDocker()
    drive(TLS_LINES, fake)
    kinds = [c[1] for c in fake.calls]
    assert kinds.index("ps") < kinds.index("kill")
    # Only one ps: resolution happened on up-a ok, not again at the trigger.
    assert kinds.count("ps") == 1
    ps = fake.calls[0]
    assert "label=com.docker.compose.project=netops" in ps
    assert "label=com.docker.compose.service=postgres" in ps
    assert "status=running" in ps


def test_up_b_start_alone_is_also_a_trigger() -> None:
    lines = [stage("up-a", "start"), stage("up-a", "ok"), stage("up-b", "start")]
    trigger, ev, _ = drive(lines, FakeDocker())
    assert trigger.fired and ev.triggered_on == "up-b:start"


def test_it_never_fires_twice() -> None:
    fake = FakeDocker()
    drive(TLS_LINES + [stage("mint", "ok"), stage("up-b", "start")], fake)
    assert len([c for c in fake.calls if c[:2] == ["docker", "kill"]]) == 1


def test_a_plaintext_install_injects_nothing_and_fails_the_leg() -> None:
    lines = [stage("up-a", "start"), stage("up-a", "ok"), stage("status", "start"),
             stage("status", "ok")]
    trigger, ev, _ = drive(lines, FakeDocker())
    code, msg = ci.verdict(0, trigger, ev)
    assert code == ci.EXIT_NOT_TRIGGERED and "never injected" in msg


def test_a_trigger_before_phase_a_closed_is_refused() -> None:
    fake = FakeDocker()
    trigger, ev, _ = drive([stage("mint", "ok")], fake)
    assert not [c for c in fake.calls if c[:2] == ["docker", "kill"]]
    code, msg = ci.verdict(0, trigger, ev)
    assert code == ci.EXIT_NOT_TRIGGERED and "before phase A" in msg


def test_the_clean_stop_winning_the_race_fails_the_leg() -> None:
    fake = FakeDocker(kill_rc=1, states=[{"Status": "exited", "ExitCode": 0}])
    trigger, ev, _ = drive(TLS_LINES, fake)
    code, msg = ci.verdict(0, trigger, ev)
    assert code == ci.EXIT_KILL_DID_NOT_LAND and "did not land" in msg


def test_no_running_container_fails_the_leg() -> None:
    trigger, ev, _ = drive(TLS_LINES, FakeDocker(running=[]))
    code, msg = ci.verdict(0, trigger, ev)
    assert code == ci.EXIT_KILL_DID_NOT_LAND
    assert "no container to kill" in msg


def test_the_state_is_polled_until_the_exit_is_recorded() -> None:
    fake = FakeDocker(states=[{"Status": "running", "ExitCode": 0},
                              {"Status": "exited", "ExitCode": 137}])
    _, ev, _ = drive(TLS_LINES, fake)
    assert ev.landed()


def test_an_install_that_did_not_heal_keeps_its_exit_code() -> None:
    trigger, ev, _ = drive(TLS_LINES, FakeDocker())
    code, msg = ci.verdict(1, trigger, ev)
    assert code == 1 and "did not heal" in msg


def test_a_timeout_is_124() -> None:
    trigger, ev, _ = drive(TLS_LINES, FakeDocker())
    assert ci.verdict(124, trigger, ev)[0] == 124


def test_main_streams_a_real_child_and_writes_evidence(tmp_path: Path) -> None:
    # A real subprocess prints a TLS run without markers ever reaching phase B:
    # the leg must fail with "never injected", and the log must hold the output.
    script = tmp_path / "fake_install.py"
    script.write_text(
        "import json\n"
        "for sid in ('up-a',):\n"
        "    for st in ('start', 'ok'):\n"
        "        print('@CX@ ' + json.dumps({'kind':'stage','id':sid,'status':st}),"
        " flush=True)\n"
        "print('@CX@ ' + json.dumps({'kind':'result','status':'ok'}), flush=True)\n",
        encoding="utf-8")
    log, evidence = tmp_path / "install.log", tmp_path / "ev.json"
    rc = ci.main(["--log", str(log), "--evidence", str(evidence), "--service",
                  "definitely-not-a-service", "--project", "ci-test-nonexistent",
                  "--", sys.executable, str(script)])
    assert rc == ci.EXIT_NOT_TRIGGERED
    assert '"kind": "result"' in log.read_text() or '"kind":"result"' in log.read_text()
    doc = json.loads(evidence.read_text())
    assert doc["install_rc"] == 0 and doc["landed"] is False


def test_main_requires_a_command() -> None:
    assert ci.main(["--log", "x", "--evidence", "y"]) == 2
    assert ci.main(["--log", "x", "--evidence", "y", "--"]) == 2


@pytest.mark.parametrize("marker", [
    {"kind": "result", "status": "ok"},
    {"kind": "timing", "status": "ok"},
    {"kind": "stage", "id": "status", "status": "ok"},
])
def test_unrelated_markers_do_nothing(marker: dict) -> None:
    assert ci.Trigger().feed(marker) is None
