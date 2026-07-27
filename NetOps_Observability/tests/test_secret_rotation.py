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
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import secret_rotation as sr          # noqa: E402
import install                        # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────

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
