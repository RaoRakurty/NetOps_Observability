# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tiered bring-up (FMEA 2026-09-15 §4.5, §2 row 11).

On .123 phase A and phase B each created and started ~25 containers at once on
4 cores with a slow disk; every first-boot timer competed for the same IO. On a
slow or very slow host, or when the resource plan over-commits memory, the
installer now starts the stack in groups — stores, store bootstraps, engines,
dashboard/ingress, add-ons — each group settling before the next, then one
final full `up -d` so nothing is left out. Fast and normal hosts keep today's
single `up -d`.

  * group membership comes from the effective compose config
    (`docker compose config --services`), never a hard-coded assumption;
  * a store that cannot settle fails the install (the single start would
    fail on it too); a later group that cannot settle is reported and the final
    pass decides, exactly as a single start would;
  * the mode and the reason are printed.

No docker, ever: an autouse fixture makes any real subprocess call fail the test.
Run:  python3 -m pytest tests/test_install_tiers.py -v
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install

# What `docker compose config --services` printed for a TLS + sso +
# self-monitoring install (order as compose prints it: unordered).
CONFIG_SERVICES = """\
nginx
api
postgres
keycloak
secrets-seal
kafka
kafka-init
clickhouse
opensearch
opensearch-security-init
opensearch-init
victoria
correlation
vector-aggregator
vector-router
syslog-ng
goflow2
gnmic
prober
vmalert
frontend
grafana
cadvisor
node-exporter
kafka-exporter
gotenberg-tls-init
redis
"""


@pytest.fixture(autouse=True)
def no_real_commands(monkeypatch):
    """Any real subprocess (docker above all) fails the test loudly."""
    def refuse(*a, **k):
        raise AssertionError(f"test tried to run a real command: {a!r}")
    monkeypatch.setattr(install.subprocess, "run", refuse)
    monkeypatch.setattr(install.subprocess, "Popen", refuse)
    monkeypatch.setattr(install.subprocess, "check_output", refuse)
    monkeypatch.setattr(install.subprocess, "call", refuse)
    # compose_up stamps build provenance with `git rev-parse`; keep it offline.
    monkeypatch.setattr(install, "_git_sha", lambda root: "test-sha")


def test_the_guard_is_armed():
    with pytest.raises(AssertionError, match="real command"):
        install.subprocess.Popen(["docker", "compose", "up", "-d"])


# ── fakes ────────────────────────────────────────────────────────────────────

def running(health="healthy", restarts=0):
    return {"state": {"Status": "running", "ExitCode": 0, "Health": {"Status": health}},
            "restarts": restarts}


def exited(code):
    return {"state": {"Status": "exited", "ExitCode": code, "Health": {"Status": ""}},
            "restarts": 0}


class TierOps:
    """Records every compose call in order. States are per container name; the
    default for an unknown container is running + healthy."""

    def __init__(self, services=CONFIG_SERVICES, states=None, logs="", services_error=""):
        self.config = services
        self.services_error = services_error
        self.states = {k: list(v) for k, v in (states or {}).items()}
        self.log_text = logs
        self.events: list[tuple] = []

    def up(self, build_flag, services=None):
        self.events.append(("up", tuple(services) if services is not None else None))
        return 0, ""

    def services(self):
        self.events.append(("config",))
        if self.services_error:
            return None, self.services_error
        return [s for s in self.config.split()], ""

    def containers(self, services):
        self.events.append(("ps", tuple(services)))
        return [f"netops-{s}-1" for s in services], ""

    def inspect(self, name):
        self.events.append(("inspect", name))
        seq = self.states.get(name)
        if not seq:
            return running()
        return seq.pop(0) if len(seq) > 1 else seq[0]

    def logs(self, name, n=40):
        return self.log_text

    @property
    def ups(self):
        return [e[1] for e in self.events if e[0] == "up"]


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.001)


def up(tmp_path, ops, *, tiered, budget=900):
    fc = FakeClock()
    install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops, sleep=fc.sleep,
                       clock=fc.clock, budget_s=budget, tiered=tiered)
    return fc


# ── tier plan ────────────────────────────────────────────────────────────────

def test_tiers_follow_the_design_order_and_only_active_services():
    tiers, rest = install.plan_tiers(CONFIG_SERVICES.split())
    assert [(label, names) for label, names, _req in tiers] == [
        ("data stores", ["postgres", "clickhouse", "kafka", "opensearch", "redis",
                         "victoria", "secrets-seal"]),
        ("store bootstraps", ["kafka-init", "opensearch-security-init"]),
        ("engines", ["api", "correlation", "vector-aggregator", "vector-router", "syslog-ng",
                     "goflow2", "gnmic", "prober", "vmalert"]),        # vmauth: not active
        ("dashboard and ingress", ["frontend", "nginx"]),
        ("add-ons", ["grafana", "cadvisor", "node-exporter", "kafka-exporter", "keycloak"]),
    ]
    # Not in any group: started by the final full pass. opensearch-init stays
    # there on purpose — its ISM script can wait a long time (FMEA row 9).
    assert rest == ["gotenberg-tls-init", "opensearch-init"]
    assert [req for _l, _n, req in tiers] == [True, False, False, False, False]


def test_a_plaintext_minimal_config_gives_short_groups():
    tiers, rest = install.plan_tiers(["postgres", "api", "nginx", "frontend"])
    assert [n for _l, n, _r in tiers] == [["postgres"], [], ["api"], ["frontend", "nginx"], []]
    assert rest == []


# ── mode choice ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cls,overcommit,tiered", [
    ("fast", "", False), ("normal", "", False), ("unknown", "", False),
    ("slow", "", True), ("very-slow", "", True),
    ("normal", "the resource plan reserves more memory than this host can guarantee", True),
])
def test_the_mode_follows_host_speed_and_planner_overcommit(cls, overcommit, tiered):
    chosen, why = install.choose_bring_up_mode(cls, overcommit)
    assert chosen is tiered
    assert why
    if tiered:
        assert "in groups" in why
    else:
        assert "together" in why
    if overcommit:
        assert overcommit in why


def plan_json(tmp_path, reservations, allocatable, limits, budget):
    p = tmp_path / "resource-plan.json"
    p.write_text(json.dumps({"reservations_bytes": {"a": reservations},
                             "reserves": {"allocatable_bytes": allocatable},
                             "totals": {"limits_bytes": limits, "budget_bytes": budget}}))
    return p


def test_planner_overcommit_is_read_from_the_recorded_plan(tmp_path, capsys):
    assert install.planner_overcommit(plan_json(tmp_path, 10, 9, 5, 9)) != ""
    assert install.planner_overcommit(plan_json(tmp_path, 5, 9, 10, 9)) != ""
    assert install.planner_overcommit(plan_json(tmp_path, 5, 9, 5, 9)) == ""
    assert install.planner_overcommit(tmp_path / "missing.json") == ""
    bad = tmp_path / "bad.json"
    bad.write_text('{"reserves": 3}')
    assert install.planner_overcommit(bad) == ""
    assert "resource plan" in capsys.readouterr().err


# ── fast host: today's single start ─────────────────────────────────────────

def test_a_fast_host_runs_one_up_and_never_reads_the_config(tmp_path, capsys):
    ops = TierOps()
    up(tmp_path, ops, tiered=False)
    assert ops.events == [("up", None)]
    assert "services started" in capsys.readouterr().out


# ── slow host: groups, each settling first, then a full pass ────────────────

def test_a_very_slow_host_starts_group_by_group_then_everything(tmp_path, capsys):
    ops = TierOps()
    up(tmp_path, ops, tiered=True)
    tiers, _rest = install.plan_tiers(CONFIG_SERVICES.split())
    assert ops.events[0] == ("config",)
    assert ops.ups == [tuple(n) for _l, n, _r in tiers if n] + [None]
    # each group is inspected (settled) before the next group's `up`
    for i, (_l, names, _r) in enumerate(tiers):
        start = ops.events.index(("up", tuple(names)))
        nxt = (ops.events.index(("up", tuple(tiers[i + 1][1]))) if i + 1 < len(tiers)
               else ops.events.index(("up", None)))
        inspected = {e[1] for e in ops.events[start:nxt] if e[0] == "inspect"}
        assert inspected == {f"netops-{n}-1" for n in names}
    out = capsys.readouterr().out
    assert "data stores" in out and "final pass" in out
    assert "gotenberg-tls-init" in out      # the leftovers are named


def test_the_next_group_waits_until_the_stores_are_healthy(tmp_path, capsys):
    ops = TierOps(states={"netops-postgres-1": [running("starting")] * 5 + [running("healthy")]},
                  logs="LOG:  database system was interrupted; last known up at 03:03:57")
    fc = up(tmp_path, ops, tiered=True)
    pg_done = max(i for i, e in enumerate(ops.events) if e == ("inspect", "netops-postgres-1"))
    assert pg_done < ops.events.index(("up", ("kafka-init", "opensearch-security-init")))
    assert fc.t > 0
    assert "recovering from an unclean stop" in capsys.readouterr().out


def test_a_crash_looping_store_fails_and_nothing_later_starts(tmp_path, capsys):
    ops = TierOps(states={"netops-kafka-1": [running("starting", r) for r in range(5)]},
                  logs="ERROR Invalid cluster.id")
    with pytest.raises(SystemExit):
        up(tmp_path, ops, tiered=True)
    assert len(ops.ups) == 1
    err = capsys.readouterr().err
    assert "netops-kafka-1 keeps restarting" in err and "Invalid cluster.id" in err


def test_a_store_still_starting_at_the_budget_fails_naming_it(tmp_path, capsys):
    ops = TierOps(states={"netops-opensearch-1": [running("starting")]})
    with pytest.raises(SystemExit):
        up(tmp_path, ops, tiered=True, budget=120)
    assert "netops-opensearch-1 is still starting after the 120s" in capsys.readouterr().err


def test_a_one_shot_bootstrap_that_exits_zero_has_settled(tmp_path):
    ops = TierOps(states={"netops-kafka-init-1": [running(""), exited(0)]})
    up(tmp_path, ops, tiered=True)
    assert ops.ups[-1] is None


def test_a_failing_later_group_is_reported_and_the_final_pass_decides(tmp_path, capsys):
    ops = TierOps(states={"netops-kafka-init-1": [exited(1)]},
                  logs="kafka-init: describe netops.flows failed")
    up(tmp_path, ops, tiered=True)
    assert ops.ups[-1] is None                      # the final full pass still ran
    err = capsys.readouterr().err
    assert "stopped with exit code 1" in err and "describe netops.flows failed" in err
    assert "final start pass" in err


def test_an_unreadable_config_falls_back_to_one_start(tmp_path, capsys):
    ops = TierOps(services_error="service \"api\" refers to undefined volume")
    up(tmp_path, ops, tiered=True)
    assert ops.ups == [None]
    assert "together instead" in capsys.readouterr().err


def test_an_empty_service_list_starts_nothing(tmp_path):
    ops = TierOps()
    fc = FakeClock()
    install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops, sleep=fc.sleep,
                       clock=fc.clock, budget_s=900, services=[])
    assert ops.ups == []


def test_named_services_are_started_and_settled(tmp_path):
    ops = TierOps()
    fc = FakeClock()
    install.compose_up(tmp_path, offline=True, root=tmp_path, ops=ops, sleep=fc.sleep,
                       clock=fc.clock, budget_s=900, services=["postgres"])
    assert ops.events == [("up", ("postgres",)), ("ps", ("postgres",)),
                          ("inspect", "netops-postgres-1")]


# ── ComposeOps: the real argv, through a fake runner ────────────────────────

def test_compose_ops_passes_the_group_to_up(tmp_path, monkeypatch):
    seen: list[list[str]] = []

    class P:
        def __init__(self, argv, **kw):
            seen.append(list(argv))
            self.stdout = iter(["Container netops-postgres-1  Started\n"])

        def wait(self):
            return 0

        def kill(self):
            pass
    monkeypatch.setattr(install.subprocess, "Popen", P)
    ops = install.ComposeOps(tmp_path, {})
    assert ops.up("--no-build", ["postgres", "kafka"])[0] == 0
    assert ops.up("--no-build")[0] == 0
    assert seen == [["docker", "compose", "up", "-d", "--no-build", "postgres", "kafka"],
                    ["docker", "compose", "up", "-d", "--no-build"]]


def fake_run(stdout="", rc=0, stderr="", calls=None):
    def run(argv, **kw):
        if calls is not None:
            calls.append((list(argv), kw))
        return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)
    return run


def test_compose_ops_reads_services_from_the_effective_config(tmp_path, monkeypatch):
    calls: list = []
    monkeypatch.setattr(install.subprocess, "run", fake_run("postgres\napi\n", calls=calls))
    names, why = install.ComposeOps(tmp_path, {"COMPOSE_PROFILES": "x"}).services()
    assert names == ["postgres", "api"] and why == ""
    argv, kw = calls[0]
    assert argv == ["docker", "compose", "config", "--services"]
    assert kw["cwd"] == str(tmp_path) and kw["timeout"] and kw["env"] == {"COMPOSE_PROFILES": "x"}


@pytest.mark.parametrize("stdout,rc", [("", 0), ("postgres\n--volumes\n", 0), ("x", 1)])
def test_compose_ops_rejects_a_service_list_it_cannot_trust(tmp_path, monkeypatch, stdout, rc):
    monkeypatch.setattr(install.subprocess, "run", fake_run(stdout, rc, "boom"))
    names, why = install.ComposeOps(tmp_path, {}).services()
    assert names is None and why


def test_compose_ops_config_errors_are_redacted(tmp_path, monkeypatch):
    monkeypatch.setattr(install.subprocess, "run",
                        fake_run("", 1, "invalid interpolation: DB_PASSWORD=hunter2"))
    _names, why = install.ComposeOps(tmp_path, {}).services()
    assert "hunter2" not in why


def test_compose_ops_lists_group_containers(tmp_path, monkeypatch):
    calls: list = []
    monkeypatch.setattr(install.subprocess, "run",
                        fake_run("netops-postgres-1\nnetops-kafka-1\n", calls=calls))
    names, _why = install.ComposeOps(tmp_path, {}).containers(["postgres", "kafka"])
    assert names == ["netops-postgres-1", "netops-kafka-1"]
    assert calls[0][0] == ["docker", "compose", "ps", "-a", "--format", "{{.Name}}",
                           "postgres", "kafka"]


def test_compose_ops_docker_missing_is_a_reason_not_a_crash(tmp_path, monkeypatch):
    def run(*a, **k):
        raise FileNotFoundError(2, "No such file or directory", "docker")
    monkeypatch.setattr(install.subprocess, "run", run)
    ops = install.ComposeOps(tmp_path, {})
    assert ops.services()[0] is None and ops.containers(["api"])[0] is None


# ── main wiring ─────────────────────────────────────────────────────────────

def main_src() -> str:
    src = (SCRIPTS / "install.py").read_text()
    return src[src.index("def main("):]


def test_both_phases_use_the_chosen_mode_and_the_choice_is_printed():
    src = main_src()
    assert src.count("budget_s=budgets.converge_s, tiered=tiered)") == 2
    choose = src.index("tiered, why = choose_bring_up_mode(")
    assert choose < src.index("compose_up(compose_dir")
    assert "info(why)" in src[choose:src.index("compose_up(compose_dir")]
    assert "planner_overcommit(compose_dir / \"resource-plan.json\")" in src
