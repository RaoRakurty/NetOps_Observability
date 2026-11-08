# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Secret-rotation policy tests (audit FUNC-HIGH-1).

`install.py --reset-env` is documented as "rotate all secrets". It used to
regenerate every value in .env and apply none of them, which on a running
install bricked the stack: KAFKA_CLUSTER_ID no longer matched the formatted
broker volume, and the Postgres/ClickHouse/NetBox passwords no longer matched
the stores that had only ever read them once.

These tests pin the contract that replaced it:

  (a) a rotation the tool cannot complete REFUSES, non-zero, .env untouched
  (b) an install that has never started rotates everything
  (c) freely-rotatable secrets still rotate on a running install
  (d) every store reconciliation is idempotent (and verified)

Everything runs against temp dirs and a fake compose runner — no docker, no
real .env, no data/ dir, no running stack.

Run:  python3 -m pytest tests/test_secret_rotation.py -v
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import secret_rotation as sr          # noqa: E402
import install                        # noqa: E402
import overlap_rotation as orot       # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def no_secret_chown(monkeypatch):
    """rotate_secrets re-renders data/secrets from the final .env (tracker 367
    layer 1). Handing root-run consumers their files needs a chown this
    non-root test cannot do (and must not reach docker for): record nothing,
    change nothing — test_install_vmauth_secrets_render.py owns that step."""
    monkeypatch.setattr(install, "_chown_secret_paths", lambda base, rels, uid, gid: None)


def make_install(tmp_path: Path, *, started_stores=(), env_extra=None) -> Path:
    """A throwaway project root: deployment/docker/.env + data/<store> dirs.

    `started_stores` marks stores as already initialized by planting the exact
    marker file the real service would leave behind.
    """
    markers = {
        "postgres": "data/postgres/PG_VERSION",
        "clickhouse": "data/clickhouse/status",
        "kafka": "data/kafka/meta.properties",
        "netbox-postgres": "data/netbox-postgres/PG_VERSION",
        "grafana": "data/grafana/grafana.db",
        "api-users": "data/api/users.json",
    }
    for store in started_stores:
        p = tmp_path / markers[store]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("16\n")
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True, exist_ok=True)
    # The vmauth template the credential renderer reads (tracker 367).
    (tmp_path / "src" / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src" / "config" / "vmauth.yml").write_text(
        (ROOT / "src" / "config" / "vmauth.yml").read_text())
    env = {
        "BASE_PORT": "8000",
        "DB_USER": "netops",
        "DB_NAME": "netops",
        "CLICKHOUSE_USER": "netops",
        "COMPOSE_PROFILES": "embedded-bus,prober",
        # An operator edit that MUST survive any rotation.
        "SLACK_WEBHOOK_URL": "https://hooks.example/T000/B000/keepme",
    }
    env.update(install.generate_secrets())
    env.update(env_extra or {})
    (compose_dir / ".env").write_text(
        "# generated\n" + "".join(f"{k}={v}\n" for k, v in env.items()))
    return compose_dir / ".env"


class FakeStores:
    """A stand-in for the live stack: remembers which password each store
    currently validates, and records every call. No docker anywhere."""

    def __init__(self, env: dict[str, str], *, reachable=True,
                 ch_alterable=True, ch_reads_env_on_start=True):
        self.pg = {"postgres": env["DB_PASSWORD"],
                   "netbox-postgres": env.get("NETBOX_DB_PASSWORD", "")}
        self.ch_admin = env["CLICKHOUSE_PASSWORD"]
        self.ch_grafana = env.get("GRAFANA_CH_PASSWORD", "")
        self.env = env
        self.reachable = reachable
        self.ch_alterable = ch_alterable
        self.ch_reads_env_on_start = ch_reads_env_on_start
        self.calls: list[tuple[str, tuple[str, ...], str]] = []
        self.recreated: list[str] = []

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _quoted(script: str, prefix: str) -> str:
        """Pull a single-quoted value out of the shell script we were handed."""
        after = script.split(prefix, 1)[1]
        assert after.startswith("'")
        return after[1:].split("'", 1)[0]

    def exec(self, service, argv, stdin="", timeout=60):
        self.calls.append((service, tuple(argv), stdin))
        if not self.reachable:
            return sr.ExecResult(1, "", "connection refused")
        if service in self.pg:
            if argv[:1] == ["psql"]:
                if "ALTER USER" in stdin:                    # apply
                    self.pg[service] = stdin.split("PASSWORD '", 1)[1].split("'", 1)[0]
                    return sr.ExecResult(0)
                return sr.ExecResult(0, "1\n")               # local-socket probe
            if argv[:1] == ["sh"]:                           # TCP verify
                got = self._quoted(stdin, "PGPASSWORD=")
                return sr.ExecResult(0 if got == self.pg[service] else 2, "",
                                     "password authentication failed")
        if service == "clickhouse":
            pw = self._quoted(stdin, "PW=")
            user = self._quoted(stdin, "--user ")
            held = self.ch_admin if user == "netops" else self.ch_grafana
            if pw != held:
                return sr.ExecResult(516, "", "AUTHENTICATION_FAILED")
            if "ALTER USER \"netops\"" in stdin:
                if not self.ch_alterable:
                    return sr.ExecResult(497, "", "Cannot update user `netops` in users.xml")
                self.ch_admin = stdin.split("IDENTIFIED BY '", 1)[1].split("'", 1)[0]
            elif "CREATE USER IF NOT EXISTS grafana" in stdin:
                self.ch_grafana = stdin.split("IDENTIFIED BY '", 1)[1].split("'", 1)[0]
            return sr.ExecResult(0, "1\n")
        return sr.ExecResult(0)

    def recreate(self, service, timeout=300):
        self.recreated.append(service)
        if service == "clickhouse" and self.ch_reads_env_on_start:
            # The official image regenerates users.d/default-user.xml from
            # CLICKHOUSE_PASSWORD at every start.
            self.ch_admin = self.env_now("CLICKHOUSE_PASSWORD")
        return sr.ExecResult(0)

    def env_now(self, key):
        return self.env[key]


def parse_env(path: Path) -> dict[str, str]:
    return install._parse_env(path)


def run_rotation(env_path: Path, stores: FakeStores, **kw):
    """Drive install.rotate_secrets with the fake stack; sleeps are no-ops."""
    root = env_path.parent.parent.parent
    stores.env = parse_env(env_path)          # recreate() must see live .env
    orig = install._parse_env

    def tracking_parse(p):
        out = orig(p)
        if Path(p) == env_path:
            stores.env = out
        return out

    install._parse_env = tracking_parse
    try:
        return install.rotate_secrets(
            root, env_path.parent, env_path, runner=_LiveEnvRunner(stores, env_path),
            sleep=lambda _s: None,
            **{"strict": kw.pop("strict", False),
               "allow_kafka_wipe": kw.pop("allow_kafka_wipe", False),
               "assume_yes": kw.pop("assume_yes", True), **kw})
    finally:
        install._parse_env = orig


class _LiveEnvRunner:
    """Wraps FakeStores so `recreate` re-reads .env from disk, exactly like a
    real container recreate does."""

    def __init__(self, stores: FakeStores, env_path: Path):
        self.stores, self.env_path = stores, env_path

    def exec(self, service, argv, stdin="", timeout=60):
        return self.stores.exec(service, argv, stdin, timeout)

    def recreate(self, service, timeout=300):
        self.stores.env = parse_env(self.env_path)
        return self.stores.recreate(service, timeout)


# ── (0) the classification itself ────────────────────────────────────────────

def test_every_generated_secret_is_classified():
    """A new secret in install.py without a rotation class is the FUNC-HIGH-1
    defect re-entering the build."""
    missing = sorted(set(install.generate_secrets()) - set(sr.POLICY))
    assert not missing, f"unclassified secrets: {missing}"


def test_no_stale_policy_entries():
    stale = sorted(set(sr.POLICY) - set(install.generate_secrets()))
    assert not stale, f"policy entries for secrets nobody generates: {stale}"


def test_kafka_cluster_id_is_immutable_and_db_creds_are_not_free():
    assert sr.POLICY["KAFKA_CLUSTER_ID"].cls == sr.IMMUTABLE
    for name in ("DB_PASSWORD", "CLICKHOUSE_PASSWORD", "NETBOX_DB_PASSWORD"):
        assert sr.POLICY[name].cls != sr.FREE, name


def test_store_state_is_fail_safe_for_unknown_stores(tmp_path):
    assert sr.store_initialized(tmp_path, "something-new") is True


def test_started_store_detected_from_marker_and_from_stray_content(tmp_path):
    assert sr.store_initialized(tmp_path, "postgres") is False
    (tmp_path / "data" / "postgres").mkdir(parents=True)
    assert sr.store_initialized(tmp_path, "postgres") is False   # created, empty
    (tmp_path / "data" / "postgres" / "PG_VERSION").write_text("16\n")
    assert sr.store_initialized(tmp_path, "postgres") is True


def test_keycloak_only_counts_as_started_under_the_sso_profile(tmp_path):
    (tmp_path / "data" / "postgres").mkdir(parents=True)
    (tmp_path / "data" / "postgres" / "PG_VERSION").write_text("16\n")
    assert sr.store_initialized(tmp_path, "keycloak", "embedded-bus") is False
    assert sr.store_initialized(tmp_path, "keycloak", "embedded-bus,sso") is True


# ── (a) refusal on an already-initialized install ────────────────────────────

def test_reset_env_refuses_on_an_initialized_install_and_writes_nothing(tmp_path):
    env_path = make_install(tmp_path, started_stores=("kafka", "postgres",
                                                      "api-users", "grafana"))
    before = env_path.read_text()
    stores = FakeStores(parse_env(env_path))
    with pytest.raises(SystemExit) as exc:
        run_rotation(env_path, stores, strict=True)
    assert exc.value.code == 2, "a refusal must be non-zero and distinct from a crash"
    assert env_path.read_text() == before, ".env must be byte-identical after a refusal"
    assert not list(tmp_path.glob("deployment/docker/.env.*bak")), "no backup either"


def test_refusal_names_the_blocked_secrets_and_the_way_out(capsys, tmp_path):
    env_path = make_install(tmp_path, started_stores=("kafka", "api-users"))
    stores = FakeStores(parse_env(env_path))
    with pytest.raises(SystemExit):
        run_rotation(env_path, stores, strict=True)
    err = capsys.readouterr().err
    assert "KAFKA_CLUSTER_ID" in err and "immutable after first start" in err
    assert "ADMIN_INITIAL_PASSWORD" in err
    assert "--rotate-app-secrets" in err, "the refusal must offer the safe path"
    assert "--rotate-kafka-cluster-id" in err, "and the destructive opt-in"
    assert "Nothing was written" in err


def test_refusal_never_prints_a_secret_value(capsys, tmp_path):
    env_path = make_install(tmp_path, started_stores=("kafka",))
    live = parse_env(env_path)
    with pytest.raises(SystemExit):
        run_rotation(env_path, FakeStores(live), strict=True)
    out = capsys.readouterr()
    for name, value in live.items():
        if name in sr.POLICY and len(value) >= 12:
            assert value not in out.out + out.err, f"{name} leaked into the console"


def test_refuses_when_a_store_it_must_reconcile_is_unreachable(tmp_path):
    env_path = make_install(tmp_path, started_stores=("postgres",))
    before = env_path.read_text()
    stores = FakeStores(parse_env(env_path), reachable=False)
    with pytest.raises(SystemExit) as exc:
        run_rotation(env_path, stores, strict=True)
    assert exc.value.code == 2
    assert env_path.read_text() == before


def test_immutable_id_rotates_only_with_the_destructive_opt_in(tmp_path):
    env_path = make_install(tmp_path, started_stores=("kafka",))
    old = parse_env(env_path)["KAFKA_CLUSTER_ID"]
    stores = FakeStores(parse_env(env_path))
    rotated, failures = run_rotation(env_path, stores, strict=True,
                                     allow_kafka_wipe=True, assume_yes=True)
    assert failures == 0
    now = parse_env(env_path)
    assert now["KAFKA_CLUSTER_ID"] != old
    assert not (tmp_path / "data" / "kafka").exists(), "the formatted volume must be moved aside"
    moved = list((tmp_path / "data").glob("kafka.pre-rotate-*"))
    assert len(moved) == 1 and (moved[0] / "meta.properties").exists()


def test_destructive_opt_in_refuses_without_consent(tmp_path, monkeypatch):
    """Aborting at the confirmation must leave the install exactly as found —
    including every live store, so consent is taken BEFORE any store is
    ALTERed."""
    env_path = make_install(tmp_path, started_stores=("kafka", "postgres"))
    before = env_path.read_text()
    pg_before = parse_env(env_path)["DB_PASSWORD"]
    stores = FakeStores(parse_env(env_path))
    monkeypatch.setattr(install.sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as exc:
        run_rotation(env_path, stores, strict=True,
                     allow_kafka_wipe=True, assume_yes=False)
    assert exc.value.code == 2
    assert env_path.read_text() == before
    assert (tmp_path / "data" / "kafka").exists()
    assert stores.pg["postgres"] == pg_before, \
        "a store was changed before the operator consented — that is a brick"
    assert not [c for c in stores.calls if "ALTER USER" in c[2]]


# ── (b) a fresh install rotates everything ───────────────────────────────────

def test_fresh_install_rotates_every_secret(tmp_path):
    env_path = make_install(tmp_path)          # no store initialized
    root = tmp_path
    assert sr.install_started(root) is False
    verdicts = sr.classify(root, "", names=install.generate_secrets().keys())
    assert all(v.rotatable for v in verdicts), \
        [v.name for v in verdicts if not v.rotatable]
    assert not any(v.reconcile for v in verdicts), "nothing to reconcile on a fresh volume"

    before = parse_env(env_path)
    rotated, failures = run_rotation(env_path, FakeStores(before), strict=True)
    after = parse_env(env_path)
    assert failures == 0
    for name in install.generate_secrets():
        assert after[name] != before[name], f"{name} was not rotated"


def test_fresh_install_write_env_regenerates_the_whole_template(tmp_path):
    """The never-started path keeps the old behaviour: full template rewrite."""
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    env_path = compose_dir / ".env"
    first = install.write_env(env_path, 8000, force=False)
    second = install.write_env(env_path, 8000, force=True)
    assert first["KAFKA_CLUSTER_ID"] != second["KAFKA_CLUSTER_ID"]
    assert oct(env_path.stat().st_mode)[-3:] == "600"


def test_write_env_preserves_the_values_the_gate_ruled_out(tmp_path):
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    env_path = compose_dir / ".env"
    first = install.write_env(env_path, 8000, force=False)
    keep = {"KAFKA_CLUSTER_ID": first["KAFKA_CLUSTER_ID"],
            "ADMIN_INITIAL_PASSWORD": first["ADMIN_INITIAL_PASSWORD"]}
    second = install.write_env(env_path, 8000, force=True, preserve=keep)
    assert second["KAFKA_CLUSTER_ID"] == keep["KAFKA_CLUSTER_ID"]
    assert second["ADMIN_INITIAL_PASSWORD"] == keep["ADMIN_INITIAL_PASSWORD"]
    assert second["JWT_SECRET"] != first["JWT_SECRET"]
    assert parse_env(env_path)["KAFKA_CLUSTER_ID"] == keep["KAFKA_CLUSTER_ID"]


def test_reset_env_no_longer_deletes_the_user_store(tmp_path):
    """It used to unlink data/api/users.json, destroying every local account."""
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    users = tmp_path / "data" / "api" / "users.json"
    users.parent.mkdir(parents=True)
    users.write_text('[{"username":"alice"}]')
    install.write_env(compose_dir / ".env", 8000, force=True)
    assert users.exists() and "alice" in users.read_text()


# ── (c) freely-rotatable secrets still rotate on a running install ───────────

def test_app_secrets_rotate_on_a_running_install(tmp_path):
    env_path = make_install(tmp_path, started_stores=(
        "postgres", "clickhouse", "kafka", "grafana", "api-users",
        "netbox-postgres"))
    before = parse_env(env_path)
    stores = FakeStores(before)
    rotated, failures = run_rotation(env_path, stores, strict=False)
    after = parse_env(env_path)

    assert failures == 0
    for name in ("JWT_SECRET", "ENCRYPTION_KEY", "INGEST_TOKEN", "NETBOX_SECRET_KEY"):
        assert after[name] != before[name], f"{name} (free) must rotate"
    # …and the ones that cannot be honoured are untouched, not re-randomised.
    for name in ("KAFKA_CLUSTER_ID", "ADMIN_INITIAL_PASSWORD",
                 "GRAFANA_ADMIN_PASSWORD", "NETBOX_SUPERUSER_PASSWORD",
                 "NETBOX_TOKEN"):
        assert after[name] == before[name], f"{name} must be left alone"
    # Keycloak never ran here (no `sso` profile), so its bootstrap admin
    # password is still just a first-boot seed and rotates freely.
    assert after["KEYCLOAK_ADMIN_PASSWORD"] != before["KEYCLOAK_ADMIN_PASSWORD"]


def test_keycloak_admin_is_frozen_once_the_sso_profile_has_run(tmp_path):
    env_path = make_install(
        tmp_path, started_stores=("postgres",),
        env_extra={"COMPOSE_PROFILES": "embedded-bus,prober,sso"})
    before = parse_env(env_path)
    _rotated, failures = run_rotation(env_path, FakeStores(before), strict=False)
    after = parse_env(env_path)
    assert failures == 0
    assert after["KEYCLOAK_ADMIN_PASSWORD"] == before["KEYCLOAK_ADMIN_PASSWORD"]


def test_store_credentials_rotate_and_are_applied_to_the_live_store(tmp_path):
    env_path = make_install(tmp_path, started_stores=("postgres", "clickhouse",
                                                      "netbox-postgres"))
    before = parse_env(env_path)
    stores = FakeStores(before)
    _rotated, failures = run_rotation(env_path, stores, strict=False)
    after = parse_env(env_path)

    assert failures == 0
    assert after["DB_PASSWORD"] != before["DB_PASSWORD"]
    assert stores.pg["postgres"] == after["DB_PASSWORD"], \
        "the live server must validate exactly what .env now says"
    assert stores.pg["netbox-postgres"] == after["NETBOX_DB_PASSWORD"]
    assert stores.ch_admin == after["CLICKHOUSE_PASSWORD"]
    assert stores.ch_grafana == after["GRAFANA_CH_PASSWORD"]


def test_rotation_preserves_operator_edits_and_backs_the_file_up(tmp_path):
    env_path = make_install(tmp_path, started_stores=("postgres", "clickhouse"))
    before_text = env_path.read_text()
    run_rotation(env_path, FakeStores(parse_env(env_path)), strict=False)
    after = parse_env(env_path)
    assert after["SLACK_WEBHOOK_URL"] == "https://hooks.example/T000/B000/keepme"
    assert after["COMPOSE_PROFILES"] == "embedded-bus,prober"
    backup = env_path.with_suffix(env_path.suffix + ".rotate.bak")
    assert backup.exists() and backup.read_text() == before_text
    assert oct(backup.stat().st_mode)[-3:] == "600"
    assert oct(env_path.stat().st_mode)[-3:] == "600"


def test_a_store_that_refuses_the_new_credential_is_rolled_back_in_env(tmp_path):
    """.env must never advertise a credential the store rejected."""
    env_path = make_install(tmp_path, started_stores=("clickhouse",))
    before = parse_env(env_path)
    stores = FakeStores(before, ch_alterable=False, ch_reads_env_on_start=False)
    _rotated, failures = run_rotation(env_path, stores, strict=False)
    after = parse_env(env_path)
    assert failures >= 1
    assert after["CLICKHOUSE_PASSWORD"] == before["CLICKHOUSE_PASSWORD"], \
        "a failed rotation must leave the value the store still accepts"
    assert stores.ch_admin == after["CLICKHOUSE_PASSWORD"]
    assert after["JWT_SECRET"] != before["JWT_SECRET"], \
        "one store failing must not block the freely-rotatable secrets"


def test_clickhouse_rotates_via_recreate_when_the_user_is_config_defined(tmp_path):
    """Config-file users cannot be ALTERed; the image re-reads the env at start."""
    env_path = make_install(tmp_path, started_stores=("clickhouse",))
    before = parse_env(env_path)
    stores = FakeStores(before, ch_alterable=False, ch_reads_env_on_start=True)
    _rotated, failures = run_rotation(env_path, stores, strict=False)
    after = parse_env(env_path)
    assert failures == 0
    assert after["CLICKHOUSE_PASSWORD"] != before["CLICKHOUSE_PASSWORD"]
    assert stores.ch_admin == after["CLICKHOUSE_PASSWORD"]
    assert "clickhouse" in stores.recreated


# ── (d) reconciliation is idempotent ─────────────────────────────────────────

def test_postgres_reconcile_is_idempotent(tmp_path):
    env = {"DB_PASSWORD": "old-pw-000000", "CLICKHOUSE_PASSWORD": "ch-old-000000"}
    stores = FakeStores(env)
    first = sr.reconcile_postgres(stores, service="postgres", user="netops",
                                  db="netops", new_password="new-pw-111111")
    assert first[0] and "verified" in first[1]
    assert stores.pg["postgres"] == "new-pw-111111"
    alters = [c for c in stores.calls if "ALTER USER" in c[2]]
    second = sr.reconcile_postgres(stores, service="postgres", user="netops",
                                   db="netops", new_password="new-pw-111111")
    assert second[0] and "already applied" in second[1]
    assert [c for c in stores.calls if "ALTER USER" in c[2]] == alters, \
        "a second run must not re-issue the ALTER"


def test_clickhouse_reconcile_is_idempotent(tmp_path):
    env = {"DB_PASSWORD": "x" * 12, "CLICKHOUSE_PASSWORD": "ch-old-000000"}
    stores = FakeStores(env)
    for _ in range(3):
        done, msg = sr.reconcile_clickhouse_admin(
            stores, user="netops", old_password="ch-old-000000",
            new_password="ch-new-111111", sleep=lambda _s: None)
        assert done, msg
        assert stores.ch_admin == "ch-new-111111"
    assert stores.recreated == [], "the ALTER path must not recreate the container"


def test_grafana_ch_user_reconcile_is_idempotent(tmp_path):
    env = {"DB_PASSWORD": "x" * 12, "CLICKHOUSE_PASSWORD": "ch-000000",
           "GRAFANA_CH_PASSWORD": "gf-000000"}
    stores = FakeStores(env)
    for _ in range(3):
        done, msg = sr.reconcile_grafana_ch_user(
            stores, admin_user="netops", admin_password="ch-000000",
            grafana_password="gf-111111")
        assert done, msg
    assert stores.ch_grafana == "gf-111111"


def test_whole_rotation_is_rerunnable(tmp_path):
    env_path = make_install(tmp_path, started_stores=("postgres", "clickhouse"))
    stores = FakeStores(parse_env(env_path))
    for _ in range(3):
        _rotated, failures = run_rotation(env_path, stores, strict=False)
        assert failures == 0
        after = parse_env(env_path)
        assert stores.pg["postgres"] == after["DB_PASSWORD"]
        assert stores.ch_admin == after["CLICKHOUSE_PASSWORD"]


# ── plumbing invariants ──────────────────────────────────────────────────────

def test_substitute_env_is_surgical():
    text = "# c\nA=1\nB=2\n\n# B=nope\nC=3\n"
    out, missing = sr.substitute_env(text, {"B": "two", "D": "four"})
    assert out == "# c\nA=1\nB=two\n\n# B=nope\nC=3\n"
    assert missing == ["D"]


def test_no_secret_ever_reaches_the_host_command_line(tmp_path):
    """Credentials go in on stdin. argv is visible to every user on the box."""
    env_path = make_install(tmp_path, started_stores=("postgres", "clickhouse",
                                                      "netbox-postgres"))
    live = parse_env(env_path)
    stores = FakeStores(live)
    run_rotation(env_path, stores, strict=False)
    after = parse_env(env_path)
    values = {v for k, v in {**live, **after}.items()
              if k in sr.POLICY and len(v) >= 12}
    for _service, argv, _stdin in stores.calls:
        for arg in argv:
            assert arg not in values, f"secret passed as an argument: {argv[0]}"


def test_redact_strips_credentials_from_store_error_text():
    msg = sr.redact("FATAL: password 'sup3rsecret-value' rejected", ["sup3rsecret-value"])
    assert "sup3rsecret-value" not in msg and "***" in msg


def test_install_py_still_compiles_and_the_cli_loads():
    """The rotation work must not have broken the installer entry point."""
    subprocess.run([sys.executable, "-m", "py_compile",
                    str(SCRIPTS / "install.py")], check=True, timeout=60)
    r = subprocess.run([sys.executable, str(SCRIPTS / "install.py"), "--help"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    assert "--rotate-app-secrets" in r.stdout


def test_docs_do_not_promise_a_blanket_reset_env_rotation():
    """The runbook/README claim that started FUNC-HIGH-1 must stay corrected."""
    runbook = ROOT / "docs" / "runbooks" / "secret-rotation.md"
    assert runbook.exists(), "docs/runbooks/secret-rotation.md is the documented path"
    body = runbook.read_text()
    for name in ("KAFKA_CLUSTER_ID", "DB_PASSWORD", "--rotate-app-secrets"):
        assert name in body


# ── customer reset/reinstall robustness (2026-08-16) ────────────────────────

def test_store_initialized_treats_unreadable_marker_as_initialized(tmp_path, monkeypatch):
    """A store marker inside a service-owned mode-0700 data dir (e.g. Postgres'
    PG_VERSION under uid 70) is unreadable to the installer user. store_initialized
    must treat the PermissionError as "initialized" (conservative), not crash the
    --reset-env preflight with a raw traceback."""
    import secret_rotation as sr

    orig_exists = Path.exists

    def boom(self, *a, **k):
        # Only the store marker stat raises; everything else behaves normally.
        if self.name in ("PG_VERSION",) or "postgres" in str(self):
            raise PermissionError(13, "Permission denied", str(self))
        return orig_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", boom)
    # Must not raise, and must report initialized rather than "fresh".
    assert sr.store_initialized(tmp_path, "postgres") is True


def test_normalize_database_url_strips_verify_full_for_phase_a(tmp_path):
    """TLS phase-A minting needs a plaintext DB DSN. A .env that baked in
    sslmode=verify-full + sslrootcert (older install / manual edit / backup
    restore) must be normalized to sslmode=disable so the api can boot and mint
    the mesh CA; verify-full is re-supplied by compose.tls.yml in phase B."""
    import install

    env = tmp_path / ".env"
    env.write_text(
        "FOO=1\n"
        "DATABASE_URL=postgres://netops_app:pw@postgres:5432/netops"
        "?sslmode=verify-full&sslrootcert=/data/tls/ca.pem\n"
        "BAR=2\n"
    )
    install.normalize_database_url_for_bootstrap(env)
    dsn = next(l for l in env.read_text().splitlines() if l.startswith("DATABASE_URL="))
    assert "sslmode=disable" in dsn
    assert "verify-full" not in dsn and "sslrootcert" not in dsn
    # Unrelated lines and the DSN's userinfo/host/db are untouched.
    txt = env.read_text()
    assert "FOO=1" in txt and "BAR=2" in txt
    assert "netops_app:pw@postgres:5432/netops" in dsn


# ═════════════════════════════════════════════════════════════════════════════
# OVERLAP — zero-downtime vmauth rotation (`install.py --rotate-secret`,
# tracker 367 layer 3, scripts/overlap_rotation.py).
#
# The fake below is a small vmauth + client simulation driven ONLY through the
# argv/stdin the real Stack builds, so the tests exercise the real command
# construction (and can prove no credential ever reaches argv):
#   * vmauth loads the REAL rendered data/secrets/vmauth/vmauth/auth.yml on
#     SIGHUP (`docker compose kill -s HUP vmauth`), refuses a config with two
#     identical credentials (as v1.101.0 does), resets per-user counters on
#     every load and exports them with the `cred` label — all as verified on
#     the pinned image;
#   * each running client sends one request per fake-clock tick: re-reading
#     clients (api, prober, vmalert) read their client file every time,
#     restart-only clients (grafana, gnmic, vector) only on `compose restart`;
#   * every refused client request is counted, so "zero downtime" is an
#     assertion (no client ever saw a 401), not a hope.
# ═════════════════════════════════════════════════════════════════════════════

ALL_SERVICES = {"vmauth", "api", "prober", "vmalert", "grafana", "gnmic", "vector-aggregator"}


class FakeClock:
    def __init__(self, stack: FakeVmauthStack | None = None) -> None:
        self.t = 1000.0
        self.stack = stack

    def now(self) -> float:
        return self.t

    def sleep(self, dt: float) -> None:
        self.t += dt
        if self.stack is not None:
            self.stack.tick()


class FakeVmauthStack:
    def __init__(self, root: Path, *, running=ALL_SERVICES, reload_breaks=False,
                 refuse_current=False, keep_accepting=False, stuck=(),
                 restart_fails=()) -> None:
        self.root = root
        self.running = set(running)
        self.reload_breaks = reload_breaks       # vmauth rejects the next config
        self.refuse_current = refuse_current     # the cred=current block never authenticates
        self.keep_accepting = keep_accepting     # vmauth ignores the block removal
        self.stuck = set(stuck)                  # aliases whose client never moves
        self.restart_fails = set(restart_fails)
        self.calls: list[tuple[list[str], str]] = []
        self.users: dict[str, tuple[str, str, str]] = {}
        self.ghosts: set[tuple[str, str]] = set()
        self._ghost_name = "(ghost)"
        self.counts: dict[str, int] = {}
        self.reload_ok = 1
        self.unauthorized: list[str] = []        # aliases of refused CLIENT requests
        self.hups = 0
        self.restarts: list[str] = []
        self._load(initial=True)
        self.cached = {i.alias: self._client_file(i) for i in orot.IDENTITIES}

    # -- vmauth ---------------------------------------------------------------
    def _auth_yml(self) -> Path:
        return self.root / "data" / "secrets" / "vmauth" / "vmauth" / "auth.yml"

    def _load(self, initial: bool = False) -> None:
        if self.reload_breaks and not initial:
            self.reload_ok = 0
            return
        users = yaml.safe_load(self._auth_yml().read_text())["users"]
        tokens = [(u["username"], u["password"]) for u in users]
        if len(set(tokens)) != len(tokens):      # vmauth: duplicate auth token
            self.reload_ok = 0
            return
        loaded = {u["name"]: (u["username"], u["password"], u["metric_labels"]["cred"])
                  for u in users}
        if self.keep_accepting and not initial:
            # A (hypothetically) broken vmauth: drops the block from its
            # metrics but still authenticates the removed credential.
            self.ghosts |= {(u, p) for n, (u, p, _) in self.users.items() if n not in loaded}
        self.users = loaded
        self.counts = {n: 0 for n in self.users}   # vmauth recreates per-user metrics
        self.counts[self._ghost_name] = 0
        self.reload_ok = 1

    def _authenticate(self, username: str, password: str) -> str | None:
        for name, (u, p, cred) in self.users.items():
            if u == username and p == password:
                if self.refuse_current and cred == "current" and f"{name}-previous" in self.users:
                    return None
                return name
        for (u, p) in self.ghosts:
            if u == username and p == password:
                return self._ghost_name
        return None

    def _exposition(self) -> str:
        lines = [f"vmauth_config_last_reload_successful {self.reload_ok}",
                 "vmauth_config_last_reload_total 99"]
        for name, (_, _, cred) in sorted(self.users.items()):  # ghosts stay hidden
            lines.append(f'vmauth_user_requests_total{{cred="{cred}",username="{name}"}} '
                         f"{self.counts[name]}")
        return "\n".join(lines) + "\n"

    # -- clients ----------------------------------------------------------------
    def _client_file(self, ident) -> str:
        return (self.root / "data" / "secrets" / "vmauth" / ident.alias / "password").read_text()

    def tick(self) -> None:
        for i in orot.IDENTITIES:
            if not set(i.services) & self.running:
                continue
            if i.alias in self.stuck:
                pw = self.cached[i.alias]
            elif i.rereads:
                pw = self._client_file(i)
            else:
                pw = self.cached[i.alias]
            name = self._authenticate(i.username, pw)
            if name is None:
                self.unauthorized.append(i.alias)
            else:
                self.counts[name] += 1

    # -- the runner interface the real Stack uses ------------------------------
    def run(self, argv: list[str], stdin: str = "", timeout: int = 60) -> sr.ExecResult:
        assert timeout and timeout > 0, "every call must be bounded"
        self.calls.append((list(argv), stdin))
        if argv[:3] == ["docker", "compose", "ps"]:
            return sr.ExecResult(0, "0123456789ab\n" if argv[-1] in self.running else "")
        if argv[:3] == ["docker", "compose", "kill"]:
            assert argv[3:] == ["-s", "HUP", "vmauth"], argv
            self.hups += 1
            # Clients keep talking between the render and the reload: a client
            # handed the new value BEFORE vmauth holds it would 401 right here.
            self.tick()
            self._load()
            return sr.ExecResult(0)
        if argv[:3] == ["docker", "compose", "restart"]:
            svc = argv[-1]
            if svc in self.restart_fails:
                return sr.ExecResult(1, "", "Error response from daemon: boom")
            self.restarts.append(svc)
            for i in orot.IDENTITIES:
                if svc in i.services and i.alias not in self.stuck:
                    self.cached[i.alias] = self._client_file(i)
            return sr.ExecResult(0)
        if argv[:2] == ["docker", "run"]:
            assert argv[-2:] == ["-K", "-"] and "--pull=never" in argv, argv
            cfg = dict(re.findall(r'^([a-z-]+) = "(.*)"$', stdin, re.MULTILINE))
            url = cfg["url"]
            if url.endswith("/metrics"):
                return sr.ExecResult(0, self._exposition() + "\n200")
            user, _, pw = cfg.get("user", ":").partition(":")
            name = self._authenticate(user, pw)
            if name is None:
                return sr.ExecResult(0, "Unauthorized\n401")
            self.counts[name] += 1
            return sr.ExecResult(0, "\n204" if cfg.get("request") == "POST" else '{"status":"success"}\n200')
        raise AssertionError(f"unexpected command: {argv}")


@pytest.fixture
def ovl(tmp_path, monkeypatch):
    """A started install with rendered credential files, a fake stack, the
    install lock marked held, and a fake clock wired to the fake's clients."""
    env_path = make_install(tmp_path)
    root = env_path.parent.parent.parent
    install.render_service_secrets(root, parse_env(env_path))
    monkeypatch.setattr(install, "_LOCK", {"held": object()})

    def make(**kw):
        stack = FakeVmauthStack(root, **kw)
        clock = FakeClock(stack)
        return stack, clock

    def rotate(spec, stack, clock, dry_run=False):
        return install.rotate_overlap_secrets(root, env_path.parent, env_path, spec,
                                              dry_run=dry_run, runner=stack,
                                              clock=clock.now, sleep=clock.sleep)

    class Ctx:
        pass
    c = Ctx()
    c.root, c.env_path, c.make, c.rotate = root, env_path, make, rotate
    return c


def _assert_no_secret_in_argv(stack: FakeVmauthStack, values) -> None:
    vals = [v for v in values if v]
    assert vals
    for argv, _ in stack.calls:
        joined = " ".join(argv)
        for v in vals:
            assert v not in joined, "a credential reached a process argv"


def _secrets_snapshot(root: Path) -> dict[Path, bytes]:
    base = root / "data" / "secrets"
    return {p: p.read_bytes() for p in base.rglob("*") if p.is_file()}


# ── policy ───────────────────────────────────────────────────────────────────

def test_the_six_vmauth_credentials_are_overlap_and_nothing_else_is():
    assert sr.overlap_names() == sorted(i.env_key for i in orot.IDENTITIES)
    assert len(sr.overlap_names()) == 6
    for name in ("OS_API_PASSWORD", "OS_BOOTSTRAP_PASSWORD", "OS_ROUTER_PASSWORD"):
        assert sr.POLICY[name].cls == sr.FREE, f"{name}: OpenSearch holds one hash per user"


def test_overlap_still_rotates_on_the_one_shot_paths(tmp_path):
    """--reset-env / --rotate-app-secrets keep rotating the vmauth credentials
    (classified rotatable, no store reconcile) — OVERLAP adds a path, removes none."""
    v = {x.name: x for x in sr.classify(tmp_path, names=sr.overlap_names())}
    assert all(x.rotatable and not x.reconcile for x in v.values())


def test_identity_table_matches_vmauth_yml_and_compose_mounts():
    users = {u["username"]: u["password"]
             for u in yaml.safe_load((ROOT / "src/config/vmauth.yml").read_text())["users"]}
    tls = (ROOT / "deployment/docker/compose.tls.yml").read_text()
    rendered = {s.env_key: s.rel for s in install.SERVICE_SECRETS}
    for i in orot.IDENTITIES:
        assert users[i.username] == "%{" + i.env_key + "}", i.alias
        assert rendered[i.env_key] == f"vmauth/{i.alias}", "every identity has a client file"
        mount = f"../../data/secrets/vmauth/{i.alias}:/run/secrets/vmauth/{i.alias}:ro"
        assert mount in tls, f"{i.alias}: client file not mounted"
        for svc in i.services:
            m = re.search(rf"\n  {re.escape(svc)}:\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", tls, re.DOTALL)
            assert m and mount in m.group(1), f"{svc} does not mount {mount}"


def test_curl_image_is_the_one_the_stack_already_ships():
    compose = (ROOT / "deployment/docker/docker-compose.yml").read_text()
    assert f"image: {orot.CURL_IMAGE}@sha256:" in compose


@pytest.mark.parametrize("spec, aliases, unknown", [
    ("vmauth-all", [i.alias for i in orot.IDENTITIES], []),
    ("vmauth-api,vmauth-grafana", ["api", "grafana"], []),
    ("VMAUTH_GNMIC_PASSWORD, vmauth-gnmic", ["gnmic"], []),
    ("vmauth-api,DB_PASSWORD,nope", ["api"], ["DB_PASSWORD", "nope"]),
])
def test_parse_names(spec, aliases, unknown):
    got, bad = orot.parse_names(spec)
    assert [i.alias for i in got] == aliases and bad == unknown


def test_edit_env_inserts_previous_beside_its_key_and_removes_cleanly():
    text = "# keep me\nA=1\nVMAUTH_API_PASSWORD=old\nZ=9\n"
    mid = orot.edit_env(text, {"VMAUTH_API_PASSWORD": "new", "VMAUTH_API_PASSWORD_PREVIOUS": "old"})
    assert mid == "# keep me\nA=1\nVMAUTH_API_PASSWORD=new\nVMAUTH_API_PASSWORD_PREVIOUS=old\nZ=9\n"
    assert orot.edit_env(mid, {}, ["VMAUTH_API_PASSWORD_PREVIOUS"]) == \
        "# keep me\nA=1\nVMAUTH_API_PASSWORD=new\nZ=9\n"


def test_duration_parsing():
    assert orot.duration_s("30s", 9) == 30 and orot.duration_s("1m30s", 9) == 90
    assert orot.duration_s("", 9) == 9 and orot.duration_s("soon", 9) == 9


# ── the state machine ────────────────────────────────────────────────────────

def test_happy_path_all_six_with_zero_client_401s(ovl, capsys):
    stack, clock = ovl.make()
    old = parse_env(ovl.env_path)
    code = ovl.rotate("vmauth-all", stack, clock)
    out = capsys.readouterr()
    assert code == orot.OK, out.err
    new = parse_env(ovl.env_path)
    for i in orot.IDENTITIES:
        assert new[i.env_key] != old[i.env_key], i.alias
        assert i.env_key + "_PREVIOUS" not in new, "state cleared on completion"
        assert (ovl.root / f"data/secrets/vmauth/{i.alias}/password").read_text() == new[i.env_key]
    # vmauth ends with exactly one block per identity, holding the new values
    assert {n: p for n, (_, p, _) in stack.users.items()} == \
        {i.username: new[i.env_key] for i in orot.IDENTITIES}
    assert stack.unauthorized == [], "a client saw a 401 — the rotation was not zero-downtime"
    assert sorted(stack.restarts) == ["gnmic", "grafana", "vector-aggregator"]
    assert stack.hups == 2, "one reload into the overlap, one out of it"
    assert new["SLACK_WEBHOOK_URL"] == "https://hooks.example/T000/B000/keepme"
    # the old credentials are proven revoked: the last probe of each got 401
    for k in install.generate_secrets():
        for v in (old.get(k), new.get(k)):
            if v and len(v) >= 8:
                assert v not in out.out and v not in out.err, f"{k} reached the log"
    _assert_no_secret_in_argv(stack, [old[i.env_key] for i in orot.IDENTITIES]
                              + [new[i.env_key] for i in orot.IDENTITIES])
    assert "rotation audit" in out.out and "drain:" in out.out


def test_single_identity_touches_only_that_identity(ovl):
    stack, clock = ovl.make()
    old = parse_env(ovl.env_path)
    assert ovl.rotate("vmauth-api", stack, clock) == orot.OK
    new = parse_env(ovl.env_path)
    changed = sorted(k for k in old if old[k] != new.get(k))
    assert changed == ["VMAUTH_API_PASSWORD"]
    assert stack.restarts == [], "the api re-reads its file — no restart"
    assert stack.unauthorized == []


def test_reload_failure_rolls_back_and_touches_no_client(ovl, capsys):
    stack, clock = ovl.make(reload_breaks=True)
    before_env = ovl.env_path.read_text()
    before_files = _secrets_snapshot(ovl.root)
    code = ovl.rotate("vmauth-gnmic", stack, clock)
    assert code == orot.FAILED
    err = capsys.readouterr().err
    assert "rejected the new config" in err and "rolled back" in err.lower()
    assert parse_env(ovl.env_path) == install._parse_env_text(before_env)
    assert _secrets_snapshot(ovl.root) == before_files, "auth.yml back to single-block, clients untouched"
    assert stack.restarts == [] and stack.unauthorized == []


def test_new_credential_proof_failure_rolls_back(ovl, capsys):
    stack, clock = ovl.make(refuse_current=True)
    old = parse_env(ovl.env_path)
    before_clients = (ovl.root / "data/secrets/vmauth/vector/password").read_bytes()
    code = ovl.rotate("vmauth-vector", stack, clock)
    assert code == orot.FAILED
    assert "NEW credential of vmauth-vector is refused" in capsys.readouterr().err
    now = parse_env(ovl.env_path)
    assert now["VMAUTH_VECTOR_PASSWORD"] == old["VMAUTH_VECTOR_PASSWORD"]
    assert "VMAUTH_VECTOR_PASSWORD_PREVIOUS" not in now
    assert (ovl.root / "data/secrets/vmauth/vector/password").read_bytes() == before_clients
    assert [n for n in stack.users if n.endswith("-previous")] == [], "vmauth back to one block"
    assert stack.restarts == []


def test_drain_timeout_stops_with_both_credentials_valid(ovl, capsys):
    stack, clock = ovl.make(stuck={"gnmic"})
    old = parse_env(ovl.env_path)
    code = ovl.rotate("vmauth-gnmic", stack, clock)
    assert code == orot.INCOMPLETE_SAFE
    err = capsys.readouterr().err
    assert "svc-gnmic" in err and "BOTH credentials remain valid" in err
    now = parse_env(ovl.env_path)
    assert now["VMAUTH_GNMIC_PASSWORD_PREVIOUS"] == old["VMAUTH_GNMIC_PASSWORD"], "state kept for resume"
    names = {n: p for n, (_, p, _) in stack.users.items()}
    assert names["svc-gnmic-previous"] == old["VMAUTH_GNMIC_PASSWORD"]
    assert names["svc-gnmic"] == now["VMAUTH_GNMIC_PASSWORD"]
    assert stack.unauthorized == [], "the stuck client kept working throughout"
    assert clock.t - 1000.0 >= orot.DRAIN_TIMEOUT_S


def test_resume_from_previous_completes_without_reminting(ovl):
    stack, clock = ovl.make(stuck={"gnmic"})
    assert ovl.rotate("vmauth-gnmic", stack, clock) == orot.INCOMPLETE_SAFE
    mid = parse_env(ovl.env_path)
    # the operator fixes the client (it now reads the new file on restart)
    stack.stuck.clear()
    assert ovl.rotate("vmauth-gnmic", stack, clock) == orot.OK
    end = parse_env(ovl.env_path)
    assert end["VMAUTH_GNMIC_PASSWORD"] == mid["VMAUTH_GNMIC_PASSWORD"], "resume must not re-mint"
    assert "VMAUTH_GNMIC_PASSWORD_PREVIOUS" not in end
    assert "svc-gnmic-previous" not in stack.users
    assert stack.unauthorized == []


def test_resume_after_a_crash_right_after_the_env_write(ovl):
    """.env is written before any effect: a crash there leaves <KEY>_PREVIOUS
    and an untouched stack, and the next run completes it."""
    env = parse_env(ovl.env_path)
    text = orot.edit_env(ovl.env_path.read_text(), {
        "VMAUTH_PROBER_PASSWORD": "fresh-prober-value-0123456789",
        "VMAUTH_PROBER_PASSWORD_PREVIOUS": env["VMAUTH_PROBER_PASSWORD"]})
    ovl.env_path.write_text(text)
    stack, clock = ovl.make()
    assert ovl.rotate("vmauth-prober", stack, clock) == orot.OK
    end = parse_env(ovl.env_path)
    assert end["VMAUTH_PROBER_PASSWORD"] == "fresh-prober-value-0123456789"
    assert "VMAUTH_PROBER_PASSWORD_PREVIOUS" not in end
    assert stack.unauthorized == []


def test_another_identity_in_progress_is_refused(ovl, capsys):
    env = parse_env(ovl.env_path)
    ovl.env_path.write_text(orot.edit_env(ovl.env_path.read_text(), {
        "VMAUTH_API_PASSWORD": "x" * 24, "VMAUTH_API_PASSWORD_PREVIOUS": env["VMAUTH_API_PASSWORD"]}))
    before = ovl.env_path.read_text()
    stack, clock = ovl.make()
    assert ovl.rotate("vmauth-grafana", stack, clock) == orot.REFUSED
    assert "vmauth-api is still in progress" in capsys.readouterr().err
    assert ovl.env_path.read_text() == before


def test_finalize_refuses_to_commit_when_the_old_credential_still_works(ovl, capsys):
    stack, clock = ovl.make(keep_accepting=True)
    code = ovl.rotate("vmauth-api", stack, clock)
    assert code == orot.INCOMPLETE_SAFE
    assert "still gets HTTP" in capsys.readouterr().err
    assert "VMAUTH_API_PASSWORD_PREVIOUS" in parse_env(ovl.env_path), "not committed"


def test_restart_failure_stops_safe(ovl, capsys):
    stack, clock = ovl.make(restart_fails={"grafana"})
    assert ovl.rotate("vmauth-grafana", stack, clock) == orot.INCOMPLETE_SAFE
    assert "restarting grafana failed" in capsys.readouterr().err
    assert "VMAUTH_GRAFANA_PASSWORD_PREVIOUS" in parse_env(ovl.env_path)
    assert stack.unauthorized == []


def test_a_stopped_restart_only_client_is_not_restarted(ovl):
    stack, clock = ovl.make(running=ALL_SERVICES - {"grafana"})
    assert ovl.rotate("vmauth-grafana", stack, clock) == orot.OK
    assert stack.restarts == []


def test_dry_run_changes_nothing(ovl, capsys):
    stack, clock = ovl.make()
    env_before = ovl.env_path.read_text()
    files_before = _secrets_snapshot(ovl.root)
    assert ovl.rotate("vmauth-all", stack, clock, dry_run=True) == orot.OK
    out = capsys.readouterr().out
    assert "plan:" in out and "dry run" in out
    assert ovl.env_path.read_text() == env_before
    assert _secrets_snapshot(ovl.root) == files_before
    assert not (ovl.env_path.parent / ".env.snapshot").exists()
    mutating = [a for a, _ in stack.calls if a[:3] in (["docker", "compose", "kill"],
                                                       ["docker", "compose", "restart"])]
    assert mutating == [] and stack.hups == 0


def test_preflight_refuses_when_vmauth_is_down(ovl, capsys):
    stack, clock = ovl.make(running=ALL_SERVICES - {"vmauth"})
    before = ovl.env_path.read_text()
    assert ovl.rotate("vmauth-api", stack, clock) == orot.REFUSED
    assert "vmauth is not running" in capsys.readouterr().err
    assert ovl.env_path.read_text() == before


def test_preflight_refuses_when_env_and_vmauth_already_disagree(ovl, capsys):
    stack, clock = ovl.make()
    ovl.env_path.write_text(orot.edit_env(ovl.env_path.read_text(),
                                          {"VMAUTH_API_PASSWORD": "drifted-value-0123456789"}))
    before = ovl.env_path.read_text()
    assert ovl.rotate("vmauth-api", stack, clock) == orot.REFUSED
    assert "already disagree" in capsys.readouterr().err
    assert ovl.env_path.read_text() == before


def test_non_overlap_names_are_refused_with_the_right_pointer(ovl, capsys):
    stack, clock = ovl.make()
    assert ovl.rotate("DB_PASSWORD", stack, clock) == orot.REFUSED
    assert "--rotate-app-secrets" in capsys.readouterr().err
    assert stack.calls == []


def test_rotation_requires_the_install_lock(ovl, monkeypatch, capsys):
    monkeypatch.setattr(install, "_LOCK", {"held": None})
    stack, clock = ovl.make()
    with pytest.raises(SystemExit):
        ovl.rotate("vmauth-api", stack, clock)
    assert stack.calls == []


def test_lock_contention_refuses_the_real_script_with_exit_3(tmp_path):
    """A concurrent install/update holds deployment/docker/.install.lock: the
    real script refuses (exit 3) before reading a byte of .env."""
    import fcntl
    import shutil
    (tmp_path / "scripts").mkdir()
    for f in ("install.py", "secret_rotation.py", "overlap_rotation.py"):
        shutil.copy2(SCRIPTS / f, tmp_path / "scripts" / f)
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    env = compose_dir / ".env"
    env.write_text("VMAUTH_API_PASSWORD=" + "a" * 24 + "\n")
    lock = compose_dir / ".install.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.pwrite(fd, b"pid=4242\ncmd=install.py\nstarted_utc=2026-11-08T00:00:00Z\n", 0)
    try:
        r = subprocess.run([sys.executable, str(tmp_path / "scripts" / "install.py"),
                            "--rotate-secret", "vmauth-api", "--dry-run"],
                           capture_output=True, text=True, timeout=60, check=False,
                           env={k: v for k, v in os.environ.items()
                                if k != install.INSTALL_LOCK_FD_ENV})
    finally:
        os.close(fd)
    assert r.returncode == 3, r.stderr
    assert "pid 4242" in r.stderr
    assert env.read_text() == "VMAUTH_API_PASSWORD=" + "a" * 24 + "\n"


def test_dry_run_flag_requires_rotate_secret(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPTS / "install.py"), "--dry-run"],
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 2 and "only meaningful with --rotate-secret" in r.stderr
