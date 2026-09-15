# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Installer start convergence and the TLS phase-B restart (2026-09-15, .123).

A fresh GUI install failed at "Restarting under encryption". Evidence on the box:
phase B recreated postgres, the 10 s default stop window SIGKILLed it mid-
shutdown, the next start ran crash recovery (107 s of per-file fsync + a 31 s
checkpoint), its health gate (5 × 10 s, no start_period) said "unhealthy" at
~50 s, and three blind `compose up` passes 30 s apart gave up while the
database healed itself. Keycloak then crash-looped on a missing database
because its create step only ran after the stack converged.

These tests pin what replaced that:
  (a) compose: stateful stores get a shutdown window; postgres gets a
      start_period and syncfs crash recovery;
  (b) compose_up diagnoses a failed pass — waits through a dependency that is
      still healing (and says why), fails fast with the service's own logs on
      a crash loop or exit, fails on the first pass for port/image/disk, and
      stays bounded by a budget;
  (c) the stores are stopped cleanly before phase B, and a SIGKILL is reported;
  (d) Keycloak's database is created before the first start.

No docker: Docker is behind injected seams.
Run:  python3 -m pytest tests/test_install_converge.py -v
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"
sys.path.insert(0, str(SCRIPTS))

import install

BLOCKED_PG = (" Container netops-postgres-1  Error\n"
              "dependency failed to start: container netops-postgres-1 is unhealthy\n")


# ── fakes ────────────────────────────────────────────────────────────────────

def st(status="running", health="starting", restarts=0, exit_code=0):
    return {"state": {"Status": status, "Restarting": status == "restarting",
                      "ExitCode": exit_code, "Health": {"Status": health}},
            "restarts": restarts}


class FakeOps:
    def __init__(self, ups, states=None, logs=""):
        self.ups = list(ups)
        self.states = {k: list(v) for k, v in (states or {}).items()}
        self.log_text = logs
        self.up_calls = 0

    def up(self, build_flag):
        self.up_calls += 1
        return self.ups.pop(0) if len(self.ups) > 1 else self.ups[0]

    def inspect(self, name):
        seq = self.states[name]
        return seq.pop(0) if len(seq) > 1 else seq[0]

    def logs(self, name, n=40):
        return self.log_text


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.sleeps: list[float] = []

    def clock(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += max(s, 0.001)


def run_up(tmp_path, ops, budget=900):
    fc = FakeClock()
    install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops,
                       sleep=fc.sleep, clock=fc.clock, budget_s=budget)
    return fc


# ── (a) compose contract ─────────────────────────────────────────────────────

def service_block(name: str) -> str:
    src = COMPOSE.read_text()
    m = re.search(rf"^  {name}:\n", src, re.MULTILINE)
    assert m, f"no {name} service"
    nxt = re.search(r"^  [a-z0-9-]+:\n", src[m.end():], re.MULTILINE)
    return src[m.end(): m.end() + nxt.start() if nxt else len(src)]


def seconds(value: str) -> int:
    m = re.fullmatch(r"(\d+)(s|m)", value.strip())
    assert m, f"unparsed duration {value!r}"
    return int(m.group(1)) * (60 if m.group(2) == "m" else 1)


@pytest.mark.parametrize("svc", ["postgres", "clickhouse", "kafka", "opensearch"])
def test_stateful_stores_get_a_real_shutdown_window(svc):
    m = re.search(r"^    stop_grace_period: (\S+)$", service_block(svc), re.MULTILINE)
    assert m, f"{svc} has no stop_grace_period — compose SIGKILLs it after 10 s on recreate"
    assert seconds(m.group(1)) >= 60


def test_postgres_health_gate_has_a_start_period_long_enough_for_recovery():
    m = re.search(r"^      start_period: (\S+)$", service_block("postgres"), re.MULTILINE)
    assert m, "postgres healthcheck has no start_period — a recovering start is 'unhealthy' at 50 s"
    assert seconds(m.group(1)) >= 180


def test_postgres_crash_recovery_uses_syncfs():
    assert "- recovery_init_sync_method=syncfs" in service_block("postgres")


# ── (b) convergence policy ───────────────────────────────────────────────────

def test_a_recovering_dependency_is_waited_for_not_failed(tmp_path, capsys):
    ops = FakeOps(ups=[(1, BLOCKED_PG), (0, "")],
                  states={"netops-postgres-1": [st(health="unhealthy")] * 20 + [st(health="healthy")]},
                  logs="LOG:  syncing data directory (fsync), elapsed time: 10.00 s")
    fc = run_up(tmp_path, ops)
    out = capsys.readouterr()
    assert ops.up_calls == 2
    assert "recovering from an unclean stop" in out.out
    assert "converged on pass 2" in out.out
    assert fc.t < 900


def test_a_crash_looping_dependency_fails_fast_with_its_own_logs(tmp_path, capsys):
    ops = FakeOps(ups=[(1, "dependency failed to start: container netops-keycloak-1 is unhealthy\n")],
                  states={"netops-keycloak-1": [st(restarts=0), st(restarts=1), st(restarts=2), st(restarts=3)]},
                  logs='ERROR: FATAL: database "keycloak" does not exist')
    with pytest.raises(SystemExit):
        run_up(tmp_path, ops)
    err = capsys.readouterr().err
    assert "netops-keycloak-1 keeps restarting" in err
    assert 'database "keycloak" does not exist' in err
    assert "Re-running the installer is safe" in err


def test_an_exited_dependency_fails_with_its_exit_code(tmp_path, capsys):
    ops = FakeOps(ups=[(1, "dependency failed to start: container netops-kafka-1 exited (1)\n")],
                  states={"netops-kafka-1": [st(status="exited", health="unhealthy", exit_code=1)]},
                  logs="ERROR Invalid cluster.id")
    with pytest.raises(SystemExit):
        run_up(tmp_path, ops)
    err = capsys.readouterr().err
    assert "stopped with exit code 1" in err and "Invalid cluster.id" in err


def test_the_wait_is_bounded_and_names_the_service_and_the_knob(tmp_path, capsys):
    ops = FakeOps(ups=[(1, BLOCKED_PG)], states={"netops-postgres-1": [st(health="starting")]})
    with pytest.raises(SystemExit):
        run_up(tmp_path, ops, budget=120)
    err = capsys.readouterr().err
    assert "netops-postgres-1 is still starting after the 120s start budget" in err
    assert "CORRELIX_CONVERGE_BUDGET_S" in err


@pytest.mark.parametrize("output,expect", [
    ("Error response from daemon: Bind for 0.0.0.0:443 failed: port is already allocated", "already in use"),
    ("Error response from daemon: No such image: correlix/api:2026.09.15", "bundle load did not complete"),
    ("write /var/lib/docker/tmp: no space left on device", "disk is full"),
])
def test_failures_no_wait_can_fix_fail_on_the_first_pass(tmp_path, capsys, output, expect):
    ops = FakeOps(ups=[(1, output)])
    fc = FakeClock()
    with pytest.raises(SystemExit):
        install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops,
                           sleep=fc.sleep, clock=fc.clock, budget_s=900)
    assert ops.up_calls == 1 and fc.sleeps == []
    assert expect in capsys.readouterr().err


def test_log_lines_that_may_carry_credentials_are_withheld(tmp_path, capsys):
    ops = FakeOps(ups=[(1, BLOCKED_PG)],
                  states={"netops-postgres-1": [st(status="exited", exit_code=1)]},
                  logs="FATAL: password authentication failed for user netops PASSWORD=hunter2\nplain line")
    with pytest.raises(SystemExit):
        run_up(tmp_path, ops)
    err = capsys.readouterr().err
    assert "hunter2" not in err and "line withheld" in err and "plain line" in err


def test_an_unclassified_failure_retries_within_the_budget_then_gives_up(tmp_path, capsys):
    ops = FakeOps(ups=[(1, "something unexpected")])
    with pytest.raises(SystemExit):
        fc = FakeClock()
        try:
            install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops,
                               sleep=fc.sleep, clock=fc.clock, budget_s=120)
        finally:
            assert 1 < ops.up_calls <= install._UP_MAX_PASSES
            assert fc.t <= 150
    assert "did not converge within 120s" in capsys.readouterr().err


def test_budget_env_is_clamped_and_validated(monkeypatch):
    monkeypatch.setenv("CORRELIX_CONVERGE_BUDGET_S", "5")
    assert install._converge_budget() == 120
    monkeypatch.setenv("CORRELIX_CONVERGE_BUDGET_S", "99999")
    assert install._converge_budget() == 3600
    monkeypatch.setenv("CORRELIX_CONVERGE_BUDGET_S", "ten minutes")
    assert install._converge_budget() == install._CONVERGE_BUDGET_DEFAULT_S


# ── (c) clean stop before phase B ────────────────────────────────────────────

def fake_run(responses, calls):
    def run(argv, **kw):
        calls.append(argv)
        key = " ".join(argv[2:4])
        rc, out = responses.get(key, (0, ""))
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")
    return run


def test_only_running_stores_are_stopped_with_the_window(tmp_path, capsys):
    calls: list[list[str]] = []
    run = fake_run({"ps --status": (0, "postgres\nkafka\napi\n")}, calls)
    install.stop_stores_cleanly(tmp_path, run=run)
    stop = [c for c in calls if c[2] == "stop"]
    assert stop == [["docker", "compose", "stop", "--timeout", "120", "postgres", "kafka"]]
    assert "stopped cleanly" in capsys.readouterr().out


def test_a_store_killed_mid_shutdown_is_reported(tmp_path, capsys):
    calls: list[list[str]] = []
    responses = {"ps --status": (0, "postgres\n"), "ps -a": (0, "137\n")}
    install.stop_stores_cleanly(tmp_path, run=fake_run(responses, calls))
    assert "crash recovery" in capsys.readouterr().err


def test_phase_b_stops_the_stores_before_recreating_them():
    main_src = (SCRIPTS / "install.py").read_text()
    main_src = main_src[main_src.index("def main("):]
    first_up = main_src.index("compose_up(compose_dir")
    stop = main_src.index("stop_stores_cleanly(compose_dir)")
    second_up = main_src.index("compose_up(compose_dir", first_up + 1)
    assert first_up < stop < second_up


# ── (d) Keycloak's database exists before Keycloak first starts ─────────────

def test_keycloak_database_is_created_before_the_first_start():
    main_src = (SCRIPTS / "install.py").read_text()
    main_src = main_src[main_src.index("def main("):]
    early = main_src.index("bootstrap_keycloak_db(compose_dir, _parse_env(env_path), start_postgres=True)")
    assert early < main_src.index("compose_up(compose_dir")


def test_early_keycloak_bootstrap_starts_postgres_then_creates(tmp_path, monkeypatch):
    order: list[str] = []

    def run(argv, **kw):
        order.append("up:" + " ".join(argv[2:]))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(install.subprocess, "run", run)
    monkeypatch.setattr(install, "wait_for_postgres",
                        lambda *a, **k: (order.append("wait") or (True, "ready")))
    answers = iter([types.SimpleNamespace(returncode=0, stdout="", stderr=""),
                    types.SimpleNamespace(returncode=0, stdout="CREATE DATABASE", stderr="")])

    def exec_(self, service, argv, stdin="", timeout=60):
        order.append("sql:" + argv[-1].split()[0])
        return next(answers)

    monkeypatch.setattr(install.ComposeRunner, "exec", exec_)
    install.bootstrap_keycloak_db(tmp_path, {"DB_USER": "netops", "KEYCLOAK_DB_NAME": "keycloak"},
                                  start_postgres=True)
    assert order == ["up:up -d postgres", "wait", "sql:SELECT", "sql:CREATE"]
