# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`install.py --migrate-env`: an upgraded install gains the .env keys a newer
release introduced, with no manual step (2026-11-11, seen on the lab).

update.sh carried its own partial copy of the installer's migration list and
deploy.sh ran none, so keys added to install.py's migration
(CX_PLATFORM_ADDRESSES, the per-lane ingest tokens, …) never reached an
upgraded .env and features silently ran on the compose fallback. Both paths now
call this entry point, which IS the installer's migration (write_env's
existing-.env branch between the same completeness gates).

Pinned here, against temp install trees with copies of the real compose files
and fake values only:
  * only missing keys are added; every existing line stays byte-identical;
  * idempotent: a second run changes nothing and leaves no backup behind;
  * .env is backed up owner-only BEFORE any write, the backups are bounded;
  * key NAMES are printed, never a value;
  * a truncated .env is refused, not filled with freshly minted credentials;
  * any error is loud: exit 1, .env unchanged (unwritable directory,
    unreadable file);
  * the CLI entry point itself: exit codes, the install lock, flag conflicts.
The ordering inside update.sh / deploy.sh is pinned in
tests/test_deploy_mounted_config.py (real scripts, fake docker, recording
install.py stub).

Run:  python3 -m pytest tests/test_upgrade_env_migration.py -v
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
COMPOSE_DIR = ROOT / "deployment" / "docker"
sys.path.insert(0, str(SCRIPTS))

import install

# Keys install.py's migration seeds that a pre-2026-11 .env might lack.
DROPPED = ("CX_PLATFORM_ADDRESSES", "INGEST_TOKEN_BUS", "OPENSEARCH_SNAPSHOT_KEEP",
           "VMALERT_WEBHOOK_COOLDOWN")
OPERATOR_TAIL = ("\n# operator edits — must survive byte for byte\n"
                 "SNMP_CIDR_RANGES=10.70.0.0/16 , 192.168.172.0/24\n"
                 "FEATURE_SECURITY_LANE=true\n"
                 "WEIRD_SPACING   =  kept as is  \n")
NOT_ROOT = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")


@pytest.fixture(autouse=True)
def no_docker(monkeypatch):
    """Nothing here may reach the host's docker (compose's project name is fixed)."""
    def guard(real):
        def call(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]) == "docker":
                raise AssertionError(f"docker reached from a unit test: {list(argv)[:4]}")
            return real(argv, *args, **kwargs)
        return call
    monkeypatch.setattr(install.subprocess, "run", guard(install.subprocess.run))


def _make_tree(root: Path) -> Path:
    cd = root / "deployment" / "docker"
    cd.mkdir(parents=True)
    for name in ("docker-compose.yml", "compose.tls.yml"):
        shutil.copy2(COMPOSE_DIR / name, cd / name)
    return cd


def _older_env(env_path: Path) -> str:
    """A fresh .env, then made 'older': the DROPPED keys removed, operator
    edits appended. Returns the text written."""
    install.write_env(env_path, 8000, force=True)
    text = "".join(line for line in env_path.read_text().splitlines(keepends=True)
                   if line.split("=", 1)[0] not in DROPPED) + OPERATOR_TAIL
    env_path.write_text(text)
    for snap in env_path.parent.glob(".env.snapshot"):
        snap.unlink()
    return text


@pytest.fixture
def tree(tmp_path, monkeypatch):
    for k in ("CORRELIX_STORE_BACKEND", "CORRELIX_ADMIN_USERNAME", "CX_PLATFORM_ADDRESSES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(install, "_ip_addr_json", list)
    monkeypatch.setattr(install, "_route_source_address", lambda: "192.0.2.10")
    cd = _make_tree(tmp_path)
    env_path = cd / ".env"
    return cd, env_path, _older_env(env_path)


def _backups(cd: Path) -> list[Path]:
    return sorted(cd.glob(".env" + install.ENV_MIGRATE_BACKUP_PREFIX + "*"))


def test_adds_only_the_missing_keys_and_keeps_every_line(tree):
    _, env_path, before = tree
    added = install.migrate_env_for_upgrade(env_path)
    after = env_path.read_text()
    assert added == sorted(DROPPED)
    assert after.startswith(before), "an existing line changed — the migration must only append"
    env = install._parse_env(env_path)
    assert env["CX_PLATFORM_ADDRESSES"] == "192.0.2.10"
    assert env["VMALERT_WEBHOOK_COOLDOWN"] == "30m"
    assert env["FEATURE_SECURITY_LANE"] == "true"


def test_is_idempotent_and_leaves_no_backup_when_nothing_changes(tree):
    cd, env_path, _ = tree
    install.migrate_env_for_upgrade(env_path)
    once = env_path.read_bytes()
    assert len(_backups(cd)) == 1
    assert install.migrate_env_for_upgrade(env_path) == []
    assert env_path.read_bytes() == once
    assert len(_backups(cd)) == 1, "a no-op run must not leave a backup behind"


def test_backs_up_the_previous_env_owner_only(tree):
    cd, env_path, before = tree
    install.migrate_env_for_upgrade(env_path)
    (backup,) = _backups(cd)
    assert backup.read_text() == before
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_old_backups_are_bounded(tree):
    cd, env_path, before = tree
    old = [cd / f".env{install.ENV_MIGRATE_BACKUP_PREFIX}202601{d:02d}T000000Z" for d in range(1, 13)]
    for p in old:
        install._write_private(p, "OLD=1\n")
    keep_me = cd / ".env.pre-migrate-notastamp"
    keep_me.write_text("unrelated\n")
    install.migrate_env_for_upgrade(env_path)
    left = _backups(cd)
    assert keep_me in left, "a file that is not a migration backup was pruned"
    stamped = [p for p in left if p != keep_me]
    assert len(stamped) == install.ENV_MIGRATE_BACKUP_KEEP
    (this_run,) = [p for p in stamped if p not in old]
    assert this_run.read_text() == before, "this run's backup must be kept"
    assert set(stamped) - {this_run} == set(old[-(install.ENV_MIGRATE_BACKUP_KEEP - 1):]), \
        "the OLDEST backups are the ones removed"


def test_prints_key_names_never_values(tree, capsys):
    _, env_path, _ = tree
    install.migrate_env_for_upgrade(env_path)
    out = capsys.readouterr()
    text = out.out + out.err
    env = install._parse_env(env_path)
    for key in DROPPED:
        assert key in text
    for key, value in env.items():
        if len(value) >= 8:          # short values ("true", "30m") are not secrets
            assert value not in text, f"the value of {key} was printed"


def test_a_truncated_env_is_refused_not_refilled(tree, capsys):
    _, env_path, before = tree
    damaged = "".join(line for line in before.splitlines(keepends=True)
                      if not line.startswith(("JWT_SECRET=", "REDIS_PASSWORD=")))
    env_path.write_text(damaged)
    with pytest.raises(SystemExit) as e:
        install.migrate_env_for_upgrade(env_path)
    assert e.value.code == 1
    assert "JWT_SECRET" in capsys.readouterr().err
    assert env_path.read_text() == damaged, "a refused migration must not write"


@NOT_ROOT
def test_an_unwritable_directory_fails_loud_and_changes_nothing(tree, capsys):
    cd, env_path, before = tree
    cd.chmod(0o500)
    try:
        with pytest.raises(SystemExit) as e:
            install.migrate_env_for_upgrade(env_path)
    finally:
        cd.chmod(0o700)
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "cannot back up" in err and "Nothing was changed" in err
    assert env_path.read_text() == before
    assert not _backups(cd)


@NOT_ROOT
def test_an_unreadable_env_fails_loud(tree, capsys):
    _, env_path, _ = tree
    env_path.chmod(0)
    try:
        with pytest.raises(SystemExit) as e:
            install.migrate_env_for_upgrade(env_path)
    finally:
        env_path.chmod(0o600)
    assert e.value.code == 1
    assert "cannot read" in capsys.readouterr().err


def test_no_env_is_an_error_not_a_fresh_install(tmp_path, capsys):
    cd = _make_tree(tmp_path)
    with pytest.raises(SystemExit) as e:
        install.migrate_env_for_upgrade(cd / ".env")
    assert e.value.code == 1
    assert not (cd / ".env").exists()


def test_an_old_database_url_password_is_moved_and_named(tree, capsys):
    """migrate_env_credentials runs inside the migration (tracker 384): the
    rewritten key is reported by NAME, and the password is not printed."""
    _, env_path, before = tree
    pw = "Fake-Db-Pw-0a1b2c3d4e"
    lines = [ln for ln in before.splitlines(keepends=True)
             if not ln.startswith(("DATABASE_URL=", "APP_DB_PASSWORD="))]
    env_path.write_text("".join(lines)
                        + f"DATABASE_URL=postgres://netops_app:{pw}@postgres:5432/netops\n")
    install.migrate_env_for_upgrade(env_path)
    out = capsys.readouterr()
    env = install._parse_env(env_path)
    assert env["APP_DB_PASSWORD"] == pw
    assert pw not in env["DATABASE_URL"]
    assert pw not in out.out + out.err
    assert "DATABASE_URL" in out.out


# ── the CLI entry point update.sh and deploy.sh call ─────────────────────────

@pytest.fixture
def cli_tree(tmp_path, monkeypatch):
    """A real-shaped tree with a COPY of install.py (it resolves the install
    root from its own path), its rotation helper, and an older .env."""
    for k in ("CORRELIX_STORE_BACKEND", "CORRELIX_ADMIN_USERNAME", "CX_PLATFORM_ADDRESSES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(install, "_ip_addr_json", list)
    monkeypatch.setattr(install, "_route_source_address", lambda: "192.0.2.10")
    (tmp_path / "scripts").mkdir()
    for name in ("install.py", "secret_rotation.py"):
        shutil.copy2(SCRIPTS / name, tmp_path / "scripts" / name)
    cd = _make_tree(tmp_path)
    before = _older_env(cd / ".env")
    return tmp_path, cd, before


def _cli(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "CORRELIX_INSTALL_LOCK_FD"}
    # The explicit override keeps the result independent of this host's interfaces.
    env["CX_PLATFORM_ADDRESSES"] = "192.0.2.10,2001:db8::10"
    return subprocess.run([sys.executable, str(root / "scripts" / "install.py"), *args],
                          capture_output=True, text=True, timeout=120, check=False, env=env,
                          cwd=root)


def test_cli_migrates_then_is_a_no_op(cli_tree):
    root, cd, before = cli_tree
    r = _cli(root, "--migrate-env")
    assert r.returncode == 0, r.stdout + r.stderr
    after = (cd / ".env").read_text()
    assert after.startswith(before)
    assert install._parse_env(cd / ".env")["CX_PLATFORM_ADDRESSES"] == "192.0.2.10,2001:db8::10"
    assert "CX_PLATFORM_ADDRESSES" in r.stdout and "192.0.2.10" not in r.stdout + r.stderr
    assert len(_backups(cd)) == 1
    # The install lock is taken and released (an empty record after a clean exit).
    assert (cd / ".install.lock").read_text() == ""
    r2 = _cli(root, "--migrate-env")
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert (cd / ".env").read_text() == after
    assert "no new keys" in r2.stdout
    assert len(_backups(cd)) == 1


@NOT_ROOT
def test_cli_exits_non_zero_on_an_unwritable_env_directory(cli_tree):
    root, cd, before = cli_tree
    (cd / ".install.lock").touch(mode=0o600)   # the lock file exists on any real install
    cd.chmod(0o500)
    try:
        r = _cli(root, "--migrate-env")
    finally:
        cd.chmod(0o700)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "[fail ]" in r.stderr and "cannot back up" in r.stderr
    assert (cd / ".env").read_text() == before


def test_cli_refuses_to_combine_with_another_mode(cli_tree):
    root, cd, before = cli_tree
    r = _cli(root, "--migrate-env", "--reset-env")
    assert r.returncode == 2
    assert "--migrate-env runs on its own" in r.stderr
    assert (cd / ".env").read_text() == before
