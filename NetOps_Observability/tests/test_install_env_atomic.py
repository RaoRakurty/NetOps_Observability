# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

""".env integrity: one atomic writer, a snapshot, a completeness gate (FMEA row 13, E1).

The FMEA counted nine .env mutation sites using a plain write_text or append.
A kill or ENOSPC during any of them left a truncated .env, and a re-run KEPT
it, migrating fresh secrets into the gap (a new KAFKA_CLUSTER_ID, REDIS or
OpenSearch password) that no store had ever agreed to.

Pinned here:
  * every .env write goes through write_env_text: temp file in the same dir,
    every byte, fsync, owner kept, os.replace, mode 0600 — ENOSPC injected
    part-way through leaves .env byte-identical, no temp file, a named error;
  * a snapshot of the last COMPLETE .env is kept before each change, and a
    damaged file never overwrites it;
  * validate_env_complete: every `${VAR:?}` key in docker-compose.yml +
    compose.tls.yml and every generated secret present and non-empty; a
    truncated file is restored from a complete snapshot (damaged copy kept),
    otherwise refused naming the KEY NAMES, never a value;
  * a re-run tells a legitimately older .env (missing only migratable keys)
    from a truncated one, and never re-mints KAFKA_CLUSTER_ID over a formatted
    broker volume.

No docker — enforced: any `docker` invocation from this module fails the test.
Temp install trees carry copies of the real compose files.
Run:  python3 -m pytest tests/test_install_env_atomic.py -v
"""

from __future__ import annotations

import ast
import errno
import os
import re
import shutil
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
COMPOSE_DIR = ROOT / "deployment" / "docker"
sys.path.insert(0, str(SCRIPTS))

import install

# _write_private's temp names: "." + the destination name + ".<pid>.<hex8>.tmp".
ENV_TMP = re.compile(r"\.\.env\.\d+\.[0-9a-f]{8}\.tmp")
SNAP_TMP = re.compile(r"\.\.env\.snapshot\.\d+\.[0-9a-f]{8}\.tmp")


@pytest.fixture(autouse=True)
def no_docker(monkeypatch):
    """A unit test that reaches docker would act on whatever stack runs on this
    host (compose's project name is fixed). Make that a loud test failure."""
    def guard(real):
        def call(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]) == "docker":
                raise AssertionError(f"docker reached from a unit test: {list(argv)[:4]}")
            return real(argv, *args, **kwargs)
        return call
    monkeypatch.setattr(install.subprocess, "run", guard(install.subprocess.run))
    monkeypatch.setattr(install.subprocess, "Popen", guard(install.subprocess.Popen))


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A real-shaped install tree: <root>/deployment/docker/{compose files,.env}."""
    monkeypatch.delenv("CORRELIX_STORE_BACKEND", raising=False)
    monkeypatch.delenv("CORRELIX_ADMIN_USERNAME", raising=False)
    cd = tmp_path / "deployment" / "docker"
    cd.mkdir(parents=True)
    for name in ("docker-compose.yml", "compose.tls.yml"):
        shutil.copy2(COMPOSE_DIR / name, cd / name)
    env_path = cd / ".env"
    install.write_env(env_path, 8000, force=True)
    return cd, env_path


def secret_values(env_path: Path) -> list[str]:
    return [v for k, v in install._parse_env(env_path).items()
            if len(v) >= 12 and re.search(r"PASSWORD|TOKEN|SECRET|KEY", k)]


def set_key(env_path: Path, key: str, value: str | None) -> None:
    """Replace (or with None, delete) KEY's line — a test-side edit."""
    out = []
    for line in env_path.read_text().splitlines(keepends=True):
        if line.startswith(f"{key}="):
            if value is not None:
                out.append(f"{key}={value}\n")
        else:
            out.append(line)
    env_path.write_text("".join(out))


def fail_writes_to(monkeypatch, pattern: re.Pattern) -> list[str]:
    """Inject ENOSPC half-way through the write of a temp file matching `pattern`."""
    real = install._raw_write
    hits: list[str] = []

    def fake(fd, data):
        name = os.path.basename(os.readlink(f"/proc/self/fd/{fd}"))
        if pattern.fullmatch(name):
            hits.append(name)
            if len(data) > 1:
                real(fd, data[: len(data) // 2])
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return real(fd, data)

    monkeypatch.setattr(install, "_raw_write", fake)
    return hits


# ── every write site: ENOSPC part-way leaves .env byte-identical ─────────────

def _db_url_verify_full(cd, ep):
    set_key(ep, "DATABASE_URL", "postgres://netops_app:pw@postgres:5432/netops"
                                "?sslmode=verify-full&sslrootcert=/data/tls/ca.pem")


SITES = {
    "splice_env_values (snmp)": (None, lambda cd, ep: install.enable_snmp_discovery_env(ep, "10.70.0.0/16")),
    "augment_profiles_for_tls": (None, lambda cd, ep: install.augment_profiles_for_tls(ep)),
    "activate_tls_compose_file": (None, lambda cd, ep: install.activate_tls_compose_file(cd, ep)),
    "write_offline_override": (None, lambda cd, ep: install.write_offline_override(cd, ep)),
    "enable_tls_database_url": (None, lambda cd, ep: install.enable_tls_database_url(ep)),
    "normalize_database_url_for_bootstrap": (
        _db_url_verify_full, lambda cd, ep: install.normalize_database_url_for_bootstrap(ep)),
    "write_env migration": (
        lambda cd, ep: set_key(ep, "REDIS_PASSWORD", None),
        lambda cd, ep: install.write_env(ep, 8000, force=False)),
    "write_env heal": (
        lambda cd, ep: set_key(ep, "OS_DASHBOARDS_PASSWORD", "-legacyBadValue0123456789"),
        lambda cd, ep: install.write_env(ep, 8000, force=False)),
    "write_env fresh template": (None, lambda cd, ep: install.write_env(ep, 8000, force=True)),
    "bootstrap_grafana append": (
        lambda cd, ep: set_key(ep, "GRAFANA_CH_PASSWORD", None),
        lambda cd, ep: install.bootstrap_grafana(cd.parent.parent, {})),
    "run_resource_plan": (None, lambda cd, ep: install.run_resource_plan(ep, "demo", None)),
}


@pytest.mark.parametrize("site", sorted(SITES))
def test_enospc_mid_write_leaves_env_byte_identical(tree, monkeypatch, capsys, site):
    cd, env_path = tree
    prep, mutate = SITES[site]
    if prep:
        prep(cd, env_path)
    before = env_path.read_bytes()
    secrets_before = secret_values(env_path)
    capsys.readouterr()
    hits = fail_writes_to(monkeypatch, ENV_TMP)
    with pytest.raises(SystemExit) as exc:
        mutate(cd, env_path)
    assert exc.value.code == 1
    assert hits, f"{site}: the .env write itself was never reached"
    assert env_path.read_bytes() == before, f"{site}: .env changed after a failed write"
    assert not [p.name for p in cd.iterdir() if p.name.endswith(".tmp")], "temp file left behind"
    err = capsys.readouterr().err
    assert "No space left on device" in err and "unchanged" in err
    assert not [s for s in secrets_before if s in err], "a secret value reached the error"


def test_a_failed_snapshot_write_also_leaves_env_untouched(tree, monkeypatch):
    _, env_path = tree
    before = env_path.read_bytes()
    hits = fail_writes_to(monkeypatch, SNAP_TMP)
    with pytest.raises(SystemExit):
        install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    assert hits and env_path.read_bytes() == before
    assert not install.env_snapshot_path(env_path).exists()


def test_no_env_write_bypasses_the_atomic_writer():
    """Structural: nothing outside the writer/restorer touches env_path directly."""
    tree = ast.parse((SCRIPTS / "install.py").read_text())
    allowed = {"write_env_text", "validate_env_complete"}
    offenders: list[str] = []
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            f = call.func
            if (isinstance(f, ast.Attribute) and f.attr in ("write_text", "write_bytes", "open")
                    and isinstance(f.value, ast.Name) and f.value.id == "env_path"):
                offenders.append(f"{fn.name}:{call.lineno} env_path.{f.attr}()")
            if (isinstance(f, ast.Name) and f.id == "_write_private" and call.args
                    and isinstance(call.args[0], ast.Name) and call.args[0].id == "env_path"
                    and fn.name not in allowed):
                offenders.append(f"{fn.name}:{call.lineno} _write_private(env_path)")
    assert not offenders, offenders


# ── the writer itself ────────────────────────────────────────────────────────

def test_written_env_is_owner_only(tree):
    _, env_path = tree
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_the_destination_owner_is_kept_across_the_replace(tmp_path, monkeypatch):
    target = tmp_path / ".env"
    target.write_text("A=1\n")
    real_uid, real_gid = os.geteuid(), os.getegid()
    calls: list[tuple[int, int]] = []
    real_fchown = os.fchown
    monkeypatch.setattr(install.os, "geteuid", lambda: real_uid + 1)   # "we are someone else"
    monkeypatch.setattr(install.os, "fchown",
                        lambda fd, u, g: calls.append((u, g)) or real_fchown(fd, u, g))
    install._write_private(target, "A=2\n")
    assert calls == [(real_uid, real_gid)]
    assert target.read_text() == "A=2\n"
    calls.clear()
    install._write_private(tmp_path / "new.env", "B=1\n")
    assert calls == [], "a new file has no owner to preserve"


# ── snapshot ─────────────────────────────────────────────────────────────────

def test_a_change_snapshots_the_complete_file_first(tree):
    _, env_path = tree
    before = env_path.read_text()
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    snap = install.env_snapshot_path(env_path)
    assert snap.read_text() == before
    assert stat.S_IMODE(snap.stat().st_mode) == 0o600


def test_a_damaged_file_never_replaces_a_good_snapshot(tree):
    _, env_path = tree
    good = env_path.read_text()
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")       # snapshot = good
    env_path.write_text(env_path.read_text()[: len(good) // 2])      # truncate
    set_key(env_path, "BASE_PORT", "8001")
    install.splice_env_values(env_path, {"SNMP_CIDR_RANGES": "10.0.0.0/8"}, ["# t"], "t")
    assert install.env_snapshot_path(env_path).read_text() == good


# ── completeness gate ────────────────────────────────────────────────────────

def test_the_fresh_template_is_complete(tree, capsys):
    _, env_path = tree
    install.validate_env_complete(env_path)
    assert "incomplete" not in capsys.readouterr().err


def test_required_keys_come_from_both_compose_files_and_the_generator(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "x: ${BASE_REQ?need}\ny: ${OPTIONAL:-d}\nz: $${ESCAPED:?literal}\n")
    (tmp_path / "compose.tls.yml").write_text("t: ${ONLY_TLS:?need it}\n")
    assert install.compose_required_env_keys(tmp_path) == {"BASE_REQ", "ONLY_TLS"}
    real = install.compose_required_env_keys(COMPOSE_DIR)
    assert {"DB_PASSWORD", "KAFKA_CLUSTER_ID", "NETBOX_TOKEN", "INGEST_TOKEN_BUS"} <= real
    assert set(install.generate_secrets()) <= install.required_env_keys(tmp_path)


def test_migrated_keys_are_derived_from_the_migration_code():
    migrated = install.migrated_env_keys()
    assert {"REDIS_PASSWORD", "KAFKA_CLUSTER_ID", "GRAFANA_CH_PASSWORD",
            "OS_API_PASSWORD", "VMAUTH_API_PASSWORD"} <= migrated
    assert not {"DB_PASSWORD", "JWT_SECRET", "ENCRYPTION_KEY", "NETBOX_TOKEN"} & migrated


def _snapshot_then_truncate(env_path: Path, fraction: float = 0.55) -> tuple[str, str]:
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")
    snapshot = install.env_snapshot_path(env_path).read_text()
    full = env_path.read_text()
    env_path.write_text(full[: int(len(full) * fraction)])
    return snapshot, env_path.read_text()


@pytest.mark.parametrize("before_migration", [False, True])
def test_a_truncated_env_is_restored_from_a_complete_snapshot(tree, capsys, before_migration):
    cd, env_path = tree
    secrets_ = secret_values(env_path)
    snapshot, truncated = _snapshot_then_truncate(env_path)
    install.validate_env_complete(env_path, before_migration=before_migration)
    assert env_path.read_text() == snapshot
    assert (cd / ".env.damaged").read_text() == truncated
    assert stat.S_IMODE((cd / ".env.damaged").stat().st_mode) == 0o600
    err = capsys.readouterr().err
    assert "Restored it from .env.snapshot" in err and "OS_API_PASSWORD" in err
    assert not [s for s in secrets_ if s in err]


def test_a_truncated_env_with_no_snapshot_on_a_fresh_host_names_keys_and_reset_env(tree, capsys):
    _, env_path = tree
    secrets_ = secret_values(env_path)
    full = env_path.read_text()
    env_path.write_text(full[: int(len(full) * 0.55)])      # loses the file's tail
    before = env_path.read_bytes()
    with pytest.raises(SystemExit) as exc:
        install.validate_env_complete(env_path)
    assert exc.value.code == 1 and env_path.read_bytes() == before
    err = capsys.readouterr().err
    assert "missing or empty" in err and "KAFKA_CLUSTER_ID" in err and "OS_API_PASSWORD" in err
    assert "no snapshot" in err and "--reset-env" in err
    assert not [s for s in secrets_ if s in err]


def test_a_started_install_is_never_told_to_regenerate(tree, capsys):
    cd, env_path = tree
    marker = cd.parent.parent / "data" / "postgres" / "PG_VERSION"
    marker.parent.mkdir(parents=True)
    marker.write_text("16\n")
    set_key(env_path, "DB_PASSWORD", None)
    with pytest.raises(SystemExit):
        install.validate_env_complete(env_path)
    err = capsys.readouterr().err
    assert "DB_PASSWORD" in err and "Restore .env from a backup" in err
    assert "--reset-env" not in err


def test_an_empty_value_counts_as_missing(tree, capsys):
    _, env_path = tree
    set_key(env_path, "JWT_SECRET", "")
    with pytest.raises(SystemExit):
        install.validate_env_complete(env_path)
    assert "JWT_SECRET" in capsys.readouterr().err


def test_an_incomplete_snapshot_is_not_restored(tree, capsys):
    _, env_path = tree
    install.env_snapshot_path(env_path).write_text("BASE_PORT=8000\n")
    set_key(env_path, "ENCRYPTION_KEY", None)
    with pytest.raises(SystemExit):
        install.validate_env_complete(env_path)
    assert "snapshot .env.snapshot is incomplete too" in capsys.readouterr().err
    assert "ENCRYPTION_KEY" not in env_path.read_text()


def test_an_older_env_missing_only_migratable_keys_is_not_damage(tree, capsys):
    _, env_path = tree
    for key in ("REDIS_PASSWORD", "OS_API_PASSWORD", "GRAFANA_CH_PASSWORD"):
        set_key(env_path, key, None)
    install.validate_env_complete(env_path, before_migration=True)     # no exit
    install.write_env(env_path, 8000, force=False)                     # migrates
    install.validate_env_complete(env_path)                            # now complete
    assert "incomplete" not in capsys.readouterr().err


def test_keys_the_snapshot_had_are_damage_even_if_migratable(tree, capsys):
    _, env_path = tree
    install.enable_snmp_discovery_env(env_path, "10.70.0.0/16")        # snapshot exists
    set_key(env_path, "REDIS_PASSWORD", None)
    snapshot = install.env_snapshot_path(env_path).read_text()
    install.validate_env_complete(env_path, before_migration=True)
    assert env_path.read_text() == snapshot, "restored instead of re-minting REDIS_PASSWORD"
    assert "REDIS_PASSWORD" in capsys.readouterr().err


def test_kafka_cluster_id_is_never_reminted_over_a_formatted_broker(tree, capsys):
    cd, env_path = tree
    meta = cd.parent.parent / "data" / "kafka" / "meta.properties"
    meta.parent.mkdir(parents=True)
    meta.write_text("cluster.id=abc\n")
    set_key(env_path, "KAFKA_CLUSTER_ID", None)
    before = env_path.read_bytes()
    with pytest.raises(SystemExit):
        install.write_env(env_path, 8000, force=False)
    assert env_path.read_bytes() == before
    assert "refuse its own data" in capsys.readouterr().err


def test_a_pre_kafka_install_still_gets_a_cluster_id(tree):
    _, env_path = tree
    set_key(env_path, "KAFKA_CLUSTER_ID", None)
    env = install.write_env(env_path, 8000, force=False)
    assert len(env["KAFKA_CLUSTER_ID"]) == 22


def test_main_gates_before_migration_and_before_the_first_start():
    src = (SCRIPTS / "install.py").read_text()
    main_src = src[src.index("def main("):]
    pre = main_src.index("validate_env_complete(env_path, before_migration=True)\n    if args.reset_env")
    migrate = main_src.index("secrets_map = write_env(env_path")
    post = main_src.index("validate_env_complete(env_path)\n", migrate)
    first_up = main_src.index("compose_up(compose_dir")
    assert pre < migrate < post < first_up
    assert main_src.rindex("validate_env_complete(env_path)", 0, first_up) > post
