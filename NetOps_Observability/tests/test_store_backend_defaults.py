"""Registry/app-state backend defaults and upgrade safety (tracker 245).

Two invariants, and they pull in opposite directions on purpose:

  FRESH INSTALL  → PostgreSQL. It is the authoritative durable state backend;
                   the Applications registry exists ONLY there, and on the file
                   backend it used to fall through to an in-memory store that
                   lost every record on restart.
  EXISTING INSTALL → whatever it already runs. Changing STORE_BACKEND does not
                   move an install's data, so an upgrade that flipped the
                   backend would make every file-backed registry read as empty.

Everything here runs against temp dirs and fakes — no docker, no real .env.

Run:  python3 -m pytest tests/test_store_backend_defaults.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install                        # noqa: E402
import secret_rotation as sr          # noqa: E402


def parse_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


# ── fresh install ───────────────────────────────────────────────────────────

def test_a_fresh_install_defaults_to_postgres(tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=False)
    env = parse_env(env_path)
    assert env["STORE_BACKEND"] == "postgres", \
        "a new installation must use the authoritative durable state backend"
    dsn = env["DATABASE_URL"]
    user, pw, host, db = install._split_app_dsn(dsn)
    assert user == install.APP_STATE_ROLE, "the api must not connect as the cluster superuser"
    assert user != env["DB_USER"], "the app role must be distinct from the superuser role"
    assert len(pw) >= 20, "the app-state role needs a real generated password"
    assert pw != env["DB_PASSWORD"], "the app role must not reuse the superuser password"
    assert (host, db) == ("postgres", "netops")
    assert "sslmode=disable" in dsn, "the bootstrap DSN is plaintext until TLS phase B"
    # The one-time file→Postgres importer is declared and OFF on a fresh install:
    # there is nothing to import, and a stale value would re-import on every boot.
    assert env["IMPORT_FILE_STATE_DIR"] == ""


def test_a_fresh_install_mints_a_unique_app_role_password(tmp_path):
    a, b = tmp_path / "a.env", tmp_path / "b.env"
    install.write_env(a, 8000, force=False)
    install.write_env(b, 8000, force=False)
    _, pw_a, _, _ = install._split_app_dsn(parse_env(a)["DATABASE_URL"])
    _, pw_b, _, _ = install._split_app_dsn(parse_env(b)["DATABASE_URL"])
    assert pw_a != pw_b


# ── upgrade safety ──────────────────────────────────────────────────────────

def test_an_upgrade_never_flips_an_existing_file_install(tmp_path):
    """The critical one: an install whose registries live in JSON on the data
    volume must stay on that backend. Flipping it would point every registry at
    an empty database and read as total state loss."""
    env_path = tmp_path / ".env"
    env_path.write_text("STORE_BACKEND=file\nADMIN_USERNAME=admin\nDB_USER=netops\n")
    install.write_env(env_path, 8000, force=False)
    env = parse_env(env_path)
    assert env["STORE_BACKEND"] == "file"
    assert "DATABASE_URL" not in env, "an upgrade must not invent a DSN for an install that does not use one"


def test_an_upgrade_stamps_the_historical_backend_when_it_is_implicit(tmp_path):
    """A .env predating the explicit key relies on the compose fallback. Stamp
    it so the choice survives any future default change — and stamp `file`,
    never `postgres`."""
    env_path = tmp_path / ".env"
    env_path.write_text("ADMIN_USERNAME=admin\nDB_USER=netops\n")
    install.write_env(env_path, 8000, force=False)
    assert parse_env(env_path)["STORE_BACKEND"] == "file"


def test_an_upgrade_leaves_an_explicit_postgres_install_alone(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "STORE_BACKEND=postgres\n"
        "DATABASE_URL=postgres://netops_app:existing@postgres:5432/netops?sslmode=disable\n")
    install.write_env(env_path, 8000, force=False)
    env = parse_env(env_path)
    assert env["STORE_BACKEND"] == "postgres"
    assert "netops_app:existing@" in env["DATABASE_URL"], "an operator's DSN must survive an upgrade"


# ── deployment artifacts agree ──────────────────────────────────────────────

def test_compose_keeps_the_file_fallback_for_configuration_less_installs():
    """The compose default is NOT the product default: it is the safety net for
    an .env that predates the explicit key. It must stay `file` — a fallback of
    `postgres` would silently repoint such an install at an empty database."""
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    assert "STORE_BACKEND: ${STORE_BACKEND:-file}" in compose
    assert "STORE_BACKEND: ${STORE_BACKEND:-postgres}" not in compose


def test_no_shipped_artifact_defaults_a_new_install_to_file():
    """Guards against a stale conflicting default: the installer template is the
    only thing that decides a NEW install's backend."""
    template = (SCRIPTS / "install.py").read_text()
    assert "\nSTORE_BACKEND=postgres\n" in template
    assert "\nSTORE_BACKEND=file\n" not in template, \
        "the fresh-install template must not carry the compatibility backend"


# ── app-state role provisioning ─────────────────────────────────────────────

class FakeRunner:
    """Records what would run in the postgres container. `roles` is the fake
    catalog: name → (password, bypasses_rls)."""

    def __init__(self, roles=None, fail_provision=False):
        self.roles = dict(roles or {})
        self.fail_provision = fail_provision
        self.calls: list[tuple[str, list[str], str]] = []

    def exec(self, service, argv, stdin="", timeout=60):
        self.calls.append((service, argv, stdin))
        joined = " ".join(argv)
        if "sh" in argv and "-s" in argv:            # _pg_verify
            for name, (pw, _) in self.roles.items():
                if f"'{name}'" in stdin and f"'{pw}'" in stdin:
                    return sr.ExecResult(0, "1", "")
            return sr.ExecResult(2, "", "FATAL: password authentication failed")
        if "-tAc" in argv:                            # the rolsuper probe
            for name, (_, bypass) in self.roles.items():
                if f"'{name}'" in joined:
                    return sr.ExecResult(0, "t" if bypass else "f", "")
            return sr.ExecResult(0, "", "")
        if self.fail_provision:
            return sr.ExecResult(1, "", "ERROR: permission denied")
        # the DO $do$ / ALTER ROLE / GRANT script
        import re
        m = re.search(r"PASSWORD '([^']*)'", stdin)
        if m:
            self.roles["netops_app"] = (m.group(1), False)
        return sr.ExecResult(0, "", "")

    def recreate(self, service, timeout=300):
        return sr.ExecResult(0, "", "")


def test_provisioning_creates_a_non_superuser_role_and_verifies_it():
    r = FakeRunner()
    done, msg = sr.provision_app_state_role(
        r, db_user="netops", db_name="netops", app_user="netops_app", app_password="pw123456789012345678")
    assert done, msg
    assert r.roles["netops_app"][0] == "pw123456789012345678"
    script = "\n".join(stdin for _, _, stdin in r.calls)
    assert "NOSUPERUSER" in script and "NOBYPASSRLS" in script, \
        "a superuser or BYPASSRLS role would silently disable RLS tenant isolation"


def test_provisioning_is_idempotent():
    r = FakeRunner(roles={"netops_app": ("pw123456789012345678", False)})
    done, msg = sr.provision_app_state_role(
        r, db_user="netops", db_name="netops", app_user="netops_app", app_password="pw123456789012345678")
    assert done and "already provisioned" in msg
    assert not any("ALTER ROLE" in stdin for _, _, stdin in r.calls), \
        "a working credential must not be re-written"


def test_provisioning_refuses_a_role_that_bypasses_rls():
    r = FakeRunner(roles={"netops_app": ("pw123456789012345678", True)})
    done, msg = sr.provision_app_state_role(
        r, db_user="netops", db_name="netops", app_user="netops_app", app_password="pw123456789012345678")
    assert not done and "BYPASS" in msg.upper()


def test_provisioning_never_puts_the_password_in_argv():
    r = FakeRunner()
    sr.provision_app_state_role(
        r, db_user="netops", db_name="netops", app_user="netops_app", app_password="s3cr3t-not-in-argv")
    for _, argv, _ in r.calls:
        assert not any("s3cr3t-not-in-argv" in a for a in argv), \
            "a credential in argv is visible in the host process table"


def test_provisioning_failure_text_carries_no_credential():
    r = FakeRunner(fail_provision=True)
    done, msg = sr.provision_app_state_role(
        r, db_user="netops", db_name="netops", app_user="netops_app", app_password="s3cr3t-not-in-logs")
    assert not done and "s3cr3t-not-in-logs" not in msg


# ── the installer step around it ────────────────────────────────────────────

def test_bootstrap_is_a_noop_on_the_file_backend(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(install.subprocess, "run", lambda *a, **k: called.append(a))
    install.bootstrap_app_state_role(tmp_path, {"STORE_BACKEND": "file"})
    assert not called, "the file backend needs no database role"


def test_bootstrap_skips_an_external_database(tmp_path, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(install.subprocess, "run", lambda *a, **k: called.append(a))
    install.bootstrap_app_state_role(tmp_path, {
        "STORE_BACKEND": "postgres",
        "DATABASE_URL": "postgres://netops_app:pw@db.example.net:5432/netops",
    })
    assert not called
    assert "external database" in capsys.readouterr().out


def test_bootstrap_refuses_postgres_without_a_dsn(tmp_path):
    with pytest.raises(SystemExit):
        install.bootstrap_app_state_role(tmp_path, {"STORE_BACKEND": "postgres", "DATABASE_URL": ""})


def test_app_state_backend_normalizes_aliases():
    assert install.app_state_backend({"STORE_BACKEND": "PostgreSQL"}) == "postgres"
    assert install.app_state_backend({"STORE_BACKEND": "pg"}) == "postgres"
    assert install.app_state_backend({}) == "file"
    assert install.app_state_backend({"STORE_BACKEND": "memory"}) == "memory"


# ── TLS phase B ─────────────────────────────────────────────────────────────

def test_tls_phase_b_switches_the_dsn_to_verify_full(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "STORE_BACKEND=postgres\n"
        "DATABASE_URL=postgres://netops_app:pw@postgres:5432/netops?sslmode=disable\n")
    install.enable_tls_database_url(env_path)
    dsn = parse_env(env_path)["DATABASE_URL"]
    assert "sslmode=verify-full" in dsn
    # urlencode percent-encodes the path; libpq accepts either form.
    assert "sslrootcert=" in dsn and "ca.pem" in dsn
    assert "sslmode=disable" not in dsn
    assert "netops_app:pw@postgres:5432/netops" in dsn


def test_tls_phase_b_leaves_a_file_backend_alone(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("STORE_BACKEND=file\nDATABASE_URL=postgres://x:y@postgres:5432/netops?sslmode=disable\n")
    install.enable_tls_database_url(env_path)
    assert "sslmode=disable" in parse_env(env_path)["DATABASE_URL"]


def test_phase_a_normalization_and_phase_b_are_inverses(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "STORE_BACKEND=postgres\n"
        "DATABASE_URL=postgres://netops_app:pw@postgres:5432/netops?sslmode=disable\n")
    install.enable_tls_database_url(env_path)
    install.normalize_database_url_for_bootstrap(env_path)
    dsn = parse_env(env_path)["DATABASE_URL"]
    assert "sslmode=disable" in dsn and "sslrootcert" not in dsn, \
        "phase A must always be able to return the DSN to the plaintext bootstrap form"
