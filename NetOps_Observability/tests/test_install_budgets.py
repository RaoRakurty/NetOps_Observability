# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Host-profile wait budgets (FMEA 2026-09-15 §4.3, §2 row 3, §3.7 T1(c)/T3).

A slow disk makes every fixed installer wait too short: on .123 the install
quit about 25 s before postgres would have answered. install-correlix.sh's
preflight writes data/.host-profile.json with a speed class and a
budget_factor; install.py scales every wait from it:

  * a missing, unreadable or invalid profile means factor 1 and says so;
  * the factor is clamped to [1, 4];
  * an explicit setting always wins (CORRELIX_CONVERGE_BUDGET_S,
    CORRELIX_PG_READY_TIMEOUT, STORE_STOP_GRACE, PG_START_PERIOD);
  * on a slower host the stores' shutdown window and postgres' start period are
    written into .env through the atomic writer, and never shortened;
  * the wiring in main() passes the scaled budgets to every wait.

No docker, ever: an autouse fixture makes any real subprocess call fail the
test (a previous draft of a test reached the live lab stack).
Run:  python3 -m pytest tests/test_install_budgets.py -v
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

BUDGET_ENV = ("CORRELIX_CONVERGE_BUDGET_S", "CORRELIX_PG_READY_TIMEOUT",
              "STORE_STOP_GRACE", "PG_START_PERIOD")


@pytest.fixture(autouse=True)
def no_real_commands(monkeypatch):
    """Any real subprocess (docker above all) fails the test loudly."""
    def refuse(*a, **k):
        raise AssertionError(f"test tried to run a real command: {a!r}")
    monkeypatch.setattr(install.subprocess, "run", refuse)
    monkeypatch.setattr(install.subprocess, "Popen", refuse)
    monkeypatch.setattr(install.subprocess, "check_output", refuse)
    monkeypatch.setattr(install.subprocess, "call", refuse)
    for name in BUDGET_ENV:
        monkeypatch.delenv(name, raising=False)


def test_the_guard_is_armed():
    with pytest.raises(AssertionError, match="real command"):
        install.subprocess.run(["docker", "ps"])


def profile_file(tmp_path: Path, doc) -> Path:
    p = tmp_path / ".host-profile.json"
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return p


# ── reading the profile ──────────────────────────────────────────────────────

@pytest.mark.parametrize("cls,factor", [("fast", 1), ("normal", 1), ("slow", 2),
                                        ("very-slow", 3)])
def test_a_valid_profile_gives_its_class_and_factor(tmp_path, cls, factor):
    hp = install.load_host_profile(profile_file(tmp_path, {"class": cls, "budget_factor": factor,
                                                           "fsync_p99_ms": 61.0}))
    assert (hp.host_class, hp.factor) == (cls, float(factor))


def test_a_missing_profile_means_unscaled_and_says_so(tmp_path, capsys):
    hp = install.load_host_profile(tmp_path / "nope.json")
    assert (hp.host_class, hp.factor) == ("unknown", 1.0)
    assert "not scaled" in capsys.readouterr().out


@pytest.mark.parametrize("doc", [
    "{not json",
    "[1, 2]",
    {"budget_factor": 3},                          # no class
    {"class": "ludicrous", "budget_factor": 3},    # unknown class
    {"class": "slow"},                             # no factor
    {"class": "slow", "budget_factor": "3"},       # string factor
    {"class": "slow", "budget_factor": True},      # bool is not a number here
    '{"class": "slow", "budget_factor": NaN}',     # json.loads accepts NaN
    '{"class": "slow", "budget_factor": Infinity}',
])
def test_an_invalid_profile_means_factor_one_with_a_named_reason(tmp_path, capsys, doc):
    hp = install.load_host_profile(profile_file(tmp_path, doc))
    assert hp.factor == 1.0 and hp.host_class == "unknown"
    out = capsys.readouterr()
    assert "not scaled" in out.out + out.err


def test_an_oversized_profile_is_not_read_whole(tmp_path, capsys):
    p = tmp_path / ".host-profile.json"
    p.write_text('{"class": "slow", "budget_factor": 2, "pad": "' + "x" * 200_000 + '"}')
    assert install.load_host_profile(p).factor == 1.0


def test_an_unreadable_profile_means_factor_one(tmp_path, capsys):
    p = tmp_path / ".host-profile.json"
    p.mkdir()   # reading a directory raises IsADirectoryError (an OSError)
    hp = install.load_host_profile(p)
    assert hp.factor == 1.0
    out = capsys.readouterr()
    assert "not scaled" in out.out + out.err


@pytest.mark.parametrize("raw,expect", [(0.2, 1.0), (-5, 1.0), (1.5, 1.5), (4, 4.0),
                                        (9, 4.0), (1e9, 4.0)])
def test_the_factor_is_clamped_to_one_through_four(tmp_path, raw, expect):
    hp = install.load_host_profile(profile_file(tmp_path, {"class": "very-slow",
                                                           "budget_factor": raw}))
    assert hp.factor == expect


# ── scaling ──────────────────────────────────────────────────────────────────

def hp(cls="very-slow", factor=3.0):
    return install.HostProfile(cls, factor)


def test_every_wait_scales_with_the_factor():
    b = install.resolve_budgets(hp(), environ={}, dotenv={})
    assert b.converge_s == 2700
    assert b.pg_ready_s == 540.0
    assert b.mint_s == 900
    assert b.acl_apply_s == 2700
    assert b.bus_consumers_s == 1260
    assert b.store_stop_grace_s == 360
    assert b.pg_start_period_s == 900
    assert b.yours == frozenset()


def test_factor_one_keeps_todays_constants():
    b = install.resolve_budgets(hp("normal", 1.0), environ={}, dotenv={})
    assert (b.converge_s, b.pg_ready_s, b.mint_s, b.acl_apply_s, b.bus_consumers_s,
            b.store_stop_grace_s, b.pg_start_period_s) == (
        install._CONVERGE_BUDGET_DEFAULT_S, install.PG_READY_BUDGET_S, 300, 900, 420, 120, 300)


def test_the_converge_budget_keeps_its_ceiling_when_scaled():
    assert install.resolve_budgets(hp("very-slow", 4.0), environ={}, dotenv={}).converge_s == 3600


def test_explicit_settings_win_over_the_profile():
    env = {"CORRELIX_CONVERGE_BUDGET_S": "600", "CORRELIX_PG_READY_TIMEOUT": "90",
           "STORE_STOP_GRACE": "2m30s", "PG_START_PERIOD": "20m"}
    b = install.resolve_budgets(hp(), environ=env, dotenv={})
    assert (b.converge_s, b.pg_ready_s, b.store_stop_grace_s, b.pg_start_period_s) == (
        600, 90.0, 150, 1200)
    assert b.yours == {"converge", "pg_ready", "store_stop_grace", "pg_start_period"}


def test_an_invalid_explicit_number_warns_and_falls_back_to_the_scaled_value(capsys):
    b = install.resolve_budgets(hp(), environ={"CORRELIX_CONVERGE_BUDGET_S": "soon"}, dotenv={})
    assert b.converge_s == 2700 and "converge" not in b.yours
    assert "not a number" in capsys.readouterr().err


def test_an_invalid_explicit_duration_stops_before_compose_does(capsys):
    with pytest.raises(SystemExit):
        install.resolve_budgets(hp(), environ={"STORE_STOP_GRACE": "120"}, dotenv={})
    assert "STORE_STOP_GRACE" in capsys.readouterr().err


@pytest.mark.parametrize("raw,secs", [("120s", 120), ("2m", 120), ("1m30s", 90),
                                      ("1h", 3600), ("300ms", None), ("120", None),
                                      ("", None), ("-5s", None), ("2 m", None)])
def test_compose_durations_are_parsed_strictly(raw, secs):
    assert install.parse_compose_seconds(raw) == secs


def test_a_longer_window_already_in_env_is_never_shortened():
    b = install.resolve_budgets(hp("slow", 2.0), environ={},
                                dotenv={"STORE_STOP_GRACE": "10m", "PG_START_PERIOD": "30s"})
    assert b.store_stop_grace_s == 600      # kept: longer than 240
    assert b.pg_start_period_s == 600       # scaled 300×2 beats the shorter .env value


# ── compose reads the windows from .env, with today's values as defaults ────

COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"


def service_block(name: str) -> str:
    import re
    src = COMPOSE.read_text()
    m = re.search(rf"^  {name}:\n", src, re.MULTILINE)
    assert m, f"no {name} service"
    nxt = re.search(r"^  [a-z0-9-]+:\n", src[m.end():], re.MULTILINE)
    return src[m.end(): m.end() + nxt.start() if nxt else len(src)]


@pytest.mark.parametrize("svc", ["postgres", "clickhouse", "kafka", "opensearch"])
def test_store_stop_windows_come_from_env_with_the_120s_default(svc):
    assert "    stop_grace_period: ${STORE_STOP_GRACE:-120s}\n" in service_block(svc)


def test_postgres_start_period_comes_from_env_with_the_300s_default():
    assert "      start_period: ${PG_START_PERIOD:-300s}\n" in service_block("postgres")


def test_the_compose_defaults_equal_the_installer_bases():
    assert install.STORE_STOP_GRACE_BASE_S == 120 and install.PG_START_PERIOD_BASE_S == 300


# ── the plain-words line ─────────────────────────────────────────────────────

def test_the_budget_line_says_how_much_longer_in_plain_words():
    line = install.describe_budgets(install.resolve_budgets(hp(), environ={}, dotenv={}))
    assert "very slow" in line and "3× longer" in line
    assert "45 min" in line and "services to start" in line


def test_the_budget_line_marks_the_operators_own_settings():
    line = install.describe_budgets(install.resolve_budgets(
        hp("normal", 1.0), environ={"CORRELIX_PG_READY_TIMEOUT": "600"}, dotenv={}))
    assert "standard waits" in line and "(your setting)" in line


# ── .env: written through the atomic writer, only when it matters ───────────

@pytest.fixture
def env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text("DB_USER=netops\n")
    return p


def spy_writes(monkeypatch):
    writes: list[tuple[str, str]] = []
    real = install.write_env_text

    def spy(env_path, text, *, what):
        writes.append((what, text))
        real(env_path, text, what=what)
    monkeypatch.setattr(install, "write_env_text", spy)
    monkeypatch.setattr(install, "required_env_keys", lambda compose_dir: set())
    return writes


def test_a_slow_host_writes_the_scaled_windows_atomically(env_file, monkeypatch):
    writes = spy_writes(monkeypatch)
    install.write_budget_env(env_file, install.resolve_budgets(hp(), environ={}, dotenv={}),
                             environ={})
    assert len(writes) == 1
    env = install._parse_env(env_file)
    assert env["STORE_STOP_GRACE"] == "360s" and env["PG_START_PERIOD"] == "900s"
    assert env["DB_USER"] == "netops"


def test_a_normal_host_leaves_env_alone(env_file, monkeypatch):
    writes = spy_writes(monkeypatch)
    install.write_budget_env(env_file, install.resolve_budgets(hp("normal", 1.0), environ={},
                                                               dotenv={}), environ={})
    assert writes == [] and "STORE_STOP_GRACE" not in env_file.read_text()


def test_a_rerun_with_the_same_windows_does_not_rewrite(env_file, monkeypatch):
    writes = spy_writes(monkeypatch)
    b = install.resolve_budgets(hp(), environ={}, dotenv={})
    install.write_budget_env(env_file, b, environ={})
    install.write_budget_env(env_file, install.resolve_budgets(
        hp(), environ={}, dotenv=install._parse_env(env_file)), environ={})
    assert len(writes) == 1


def test_a_process_env_override_is_not_baked_into_env(env_file, monkeypatch):
    spy_writes(monkeypatch)
    environ = {"STORE_STOP_GRACE": "900s"}
    install.write_budget_env(env_file, install.resolve_budgets(hp(), environ=environ, dotenv={}),
                             environ=environ)
    env = install._parse_env(env_file)
    assert "STORE_STOP_GRACE" not in env and env["PG_START_PERIOD"] == "900s"


def test_a_broken_window_in_env_is_repaired_even_on_a_normal_host(env_file, monkeypatch, capsys):
    env_file.write_text("DB_USER=netops\nSTORE_STOP_GRACE=soon\n")
    spy_writes(monkeypatch)
    b = install.resolve_budgets(hp("normal", 1.0), environ={}, dotenv=install._parse_env(env_file))
    install.write_budget_env(env_file, b, environ={})
    assert install._parse_env(env_file)["STORE_STOP_GRACE"] == "120s"
    assert "STORE_STOP_GRACE" in capsys.readouterr().err


# ── every wait receives its budget ──────────────────────────────────────────

def test_the_store_stop_uses_the_scaled_grace(tmp_path):
    calls: list[tuple[list[str], dict]] = []

    def run(argv, **kw):
        calls.append((list(argv), kw))
        out = {"ps --status": "kafka\n", "ps -a": "0\n"}.get(" ".join(argv[2:4]), "")
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
    install.stop_stores_cleanly(tmp_path, run=run, grace_s=360)
    stop = [(a, kw) for a, kw in calls if a[2] == "stop"]
    assert stop[0][0] == ["docker", "compose", "stop", "--timeout", "360", "kafka"]
    assert stop[0][1]["timeout"] == 480


def test_bus_authorization_passes_both_waits(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("COMPOSE_PROFILES=embedded-bus\n")
    seen: dict[str, int] = {}
    monkeypatch.setattr(install, "apply_kafka_acls",
                        lambda d, timeout_s: seen.__setitem__("acl", timeout_s))
    monkeypatch.setattr(install, "verify_bus_consumers",
                        lambda d, timeout_s: seen.__setitem__("consumers", timeout_s))
    monkeypatch.setattr(install, "record_bus_authorization_time", lambda root: None)
    install.apply_bus_authorization(tmp_path, env_path, True, acl_timeout_s=2700,
                                    consumers_timeout_s=1260)
    assert seen == {"acl": 2700, "consumers": 1260}


def test_the_app_state_role_waits_with_the_scaled_database_budget(tmp_path, monkeypatch):
    seen: dict[str, float] = {}
    monkeypatch.setattr(install.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""))

    def wait(runner, *, user, db, budget_s=None, **kw):
        seen["budget"] = budget_s
        return False, "not ready"
    monkeypatch.setattr(install, "wait_for_postgres", wait)
    with pytest.raises(SystemExit):
        install.bootstrap_app_state_role(tmp_path, {
            "STORE_BACKEND": "postgres",
            "DATABASE_URL": "postgres://netops_app:pw@postgres:5432/netops"},
            pg_budget_s=540.0)
    assert seen["budget"] == 540.0


def test_the_keycloak_database_check_waits_with_the_scaled_budget(tmp_path, monkeypatch):
    seen: list[float | None] = []

    def wait(runner, *, user, db, budget_s=None, **kw):
        seen.append(budget_s)
        return False, "not ready"
    monkeypatch.setattr(install, "wait_for_postgres", wait)
    env = {"DB_USER": "netops", "KEYCLOAK_DB_NAME": "keycloak"}
    assert install.bootstrap_keycloak_db(tmp_path, env, pg_budget_s=540.0) is False
    with pytest.raises(SystemExit):
        install.confirm_keycloak_db(tmp_path, env, pg_budget_s=540.0, attempts=1)
    assert seen == [540.0, 540.0]


def main_src() -> str:
    src = (SCRIPTS / "install.py").read_text()
    return src[src.index("def main("):]


@pytest.mark.parametrize("call", [
    "compose_up(compose_dir, offline=args.offline, root=root, budget_s=budgets.converge_s",
    "wait_for_minted_certs(root, timeout_s=budgets.mint_s)",
    "stop_stores_cleanly(compose_dir, grace_s=budgets.store_stop_grace_s)",
    "acl_timeout_s=budgets.acl_apply_s",
    "consumers_timeout_s=budgets.bus_consumers_s",
    "bootstrap_app_state_role(compose_dir, _parse_env(env_path), pg_budget_s=budgets.pg_ready_s)",
    "start_postgres=True, pg_budget_s=budgets.pg_ready_s)",
    "confirm_keycloak_db(compose_dir, _parse_env(env_path), pg_budget_s=budgets.pg_ready_s)",
])
def test_main_hands_every_wait_its_budget(call):
    assert call in main_src()


def test_main_resolves_budgets_once_before_anything_starts():
    src = main_src()
    install_proper = src[src.index("_TIMING[\"record\"] = True"):]
    resolve = install_proper.index("budgets = resolve_budgets(")
    assert install_proper.count("info(describe_budgets(budgets))") == 1
    assert resolve < install_proper.index("write_budget_env(env_path, budgets)")
    assert resolve < install_proper.index("bootstrap_app_state_role(")
    assert resolve < install_proper.index("compose_up(compose_dir")
    # after the .env is generated and planned, so the windows land in the final file
    assert install_proper.index("run_resource_plan(env_path") < resolve
