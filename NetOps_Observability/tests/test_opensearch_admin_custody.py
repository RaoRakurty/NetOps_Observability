# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Custody of the OpenSearch admin key (docs/design/OPENSEARCH_ACCESS_2026-11-09.md).

The admin DN bypasses every role and index check. The owner's decision is that
the certificate stays on disk at 0600 under CORRELIX_UID, in a 0700 directory,
readable only by the one job that needs it. These tests pin the parts that do
not need a container; the Go tests pin the mint, and the real securityadmin run
as a non-1000 uid is the docker proof and the install-boot CI leg.

Run:  python3 -m pytest tests/test_opensearch_admin_custody.py -v
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = ROOT / "deployment" / "docker"
APPLY_SECURITY = COMPOSE_DIR / "opensearch" / "security" / "apply-security.sh"
sys.path.insert(0, str(ROOT / "scripts"))

import install


def _security_init() -> dict:
    return yaml.safe_load((COMPOSE_DIR / "docker-compose.yml").read_text())[
        "services"]["opensearch-security-init"]


def test_compose_file_is_yaml_parseable():
    assert _security_init()["profiles"] == ["security"]


# ── the job's shape ──────────────────────────────────────────────────────────

def test_security_init_runs_as_the_key_owner_uid():
    uid, _, gid = _security_init()["user"].rpartition(":")
    assert uid == "${CORRELIX_UID:-65532}", (
        "the admin key is 0600 under CORRELIX_UID, so the job that reads it "
        "must run as CORRELIX_UID on every host, not the image's uid 1000")
    assert gid == "1000", (
        "gid 1000 is what lets a non-1000 uid into the image's 0750 home")


def test_security_init_mounts_only_the_admin_dir():
    vols = _security_init()["volumes"]
    tls = [v for v in vols if "data/tls" in v]
    assert tls == ["../../data/tls/admin:/certs:ro"], (
        "this job must see the admin directory and nothing else of data/tls")


def test_security_init_paths_match_the_narrow_mount():
    env = _security_init()["environment"]
    assert env["OS_ADMIN_CA"] == "/certs/ca.pem"
    assert env["OS_ADMIN_CERT"] == "/certs/admin.crt"
    assert env["OS_ADMIN_KEY"] == "/certs/admin.key"


def test_image_opens_its_home_to_the_group_before_flattening():
    text = (COMPOSE_DIR / "opensearch" / "Dockerfile").read_text()
    chmod = text.find("RUN chmod 0750 /usr/share/opensearch")
    flatten = text.find("FROM scratch")
    assert chmod != -1, (
        "the stock image's home is 0700, so a non-1000 uid cannot run "
        "securityadmin without this line")
    assert chmod < flatten, "the chmod must land in the stage that is copied"


def test_no_compose_file_mounts_the_admin_dir_for_anyone_else():
    """Line-based: compose.tls.yml uses compose's `!override` tag, and exactly one
    mount line may name the directory across every compose file."""
    hits = []
    for f in sorted(COMPOSE_DIR.glob("*.yml")):
        for line in f.read_text().splitlines():
            if re.search(r"\.\./data/tls/admin\b", line) and not line.lstrip().startswith("#"):
                hits.append(f"{f.name}: {line.strip()}")
    assert hits == ["docker-compose.yml: - ../../data/tls/admin:/certs:ro"], hits


# ── the installer ────────────────────────────────────────────────────────────

def test_admin_dir_is_precreated_owner_only(tmp_path, monkeypatch):
    """A missing bind source becomes ROOT's directory the moment the job starts,
    and the api could then never mint the admin identity: phase A deadlocks."""
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    (compose_dir / ".env").write_text(
        f"CORRELIX_UID={os.getuid()}\nCORRELIX_GID={os.getgid()}\n")
    router = compose_dir / "vector-router"
    router.mkdir()
    (router / "processors-default.yaml").write_text("transforms: {}\n")
    seen: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, u, g, name: seen.__setitem__(name, (u, g)))
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    install.ensure_data_dirs(tmp_path)

    admin = tmp_path / "data" / "tls" / "admin"
    assert seen["data/tls/admin"] == (os.getuid(), os.getgid())
    assert stat.S_IMODE(admin.stat().st_mode) == 0o700


def test_a_dir_that_cannot_be_secured_fails_the_install(tmp_path, monkeypatch, capsys):
    d = tmp_path / "admin"
    d.mkdir(mode=0o755)
    d.chmod(0o755)

    def refuse(self, mode):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(Path, "chmod", refuse)
    with pytest.raises(SystemExit):
        install.set_custody_dir_mode(d, 0o700)
    assert "sudo chmod 0700" in capsys.readouterr().err


# ── backup.sh still reaches the key ──────────────────────────────────────────

def test_backup_curl_container_runs_as_the_key_owner():
    """The curl image's own uid is 100. Until PR C moves backup to its own
    identity, it must not lose the snapshot call when the key goes 0600."""
    text = (ROOT / "scripts" / "backup.sh").read_text()
    call = next(line for line in text.splitlines()
                if "docker run --rm" in line and "$OS_ADMIN_DIR:/certs:ro" in line)
    assert '--user "$owner"' in call


# ── apply-security.sh's named failures (§16.1) ───────────────────────────────

def _harness(tmp_path: Path, *, until: str | None, keytool_rc: int = 0,
             key: bool = True) -> dict[str, str]:
    """A fake image tree and admin dir; keytool is a stub printing `until`."""
    home = tmp_path / "os-home"
    jdk_bin = home / "jdk" / "bin"
    jdk_bin.mkdir(parents=True)
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "ca.pem").write_text("public\n")
    (certs / "admin.crt").write_text("public\n")
    if key:
        (certs / "admin.key").write_text("test-only\n")
        (certs / "admin.key").chmod(0o600)
    line = f'echo "Valid from: Mon Nov 09 13:43:05 UTC 2026 until: {until}"' if until else "echo nothing"
    keytool = jdk_bin / "keytool"
    keytool.write_text(f"#!/bin/sh\n{line}\nexit {keytool_rc}\n")
    keytool.chmod(0o755)
    env = {k: "x" for k in ("OS_API_PASSWORD", "OS_ROUTER_PASSWORD",
                            "OS_CORRELATION_PASSWORD", "OS_BOOTSTRAP_PASSWORD",
                            "OS_DASHBOARDS_PASSWORD", "OS_AGGREGATOR_PASSWORD")}
    env.update(PATH=os.environ["PATH"], OS_HOME=str(home),
               OS_ADMIN_CA=str(certs / "ca.pem"),
               OS_ADMIN_CERT=str(certs / "admin.crt"),
               OS_ADMIN_KEY=str(certs / "admin.key"))
    return env


def _run(env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(APPLY_SECURITY)], env=env, capture_output=True,
                          text=True, timeout=60, check=False)


def test_expired_admin_cert_is_a_named_failure(tmp_path):
    r = _run(_harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2026"))
    assert r.returncode == 78, r.stderr
    assert "expired" in r.stderr
    assert "docker compose up -d api" in r.stderr, "the remedy names the order"


def test_cert_about_to_expire_is_refused_too(tmp_path):
    soon = subprocess.run(["date", "-u", "-d", "+30 seconds", "+%a %b %d %H:%M:%S UTC %Y"],
                          capture_output=True, text=True, check=True).stdout.strip()
    r = _run(_harness(tmp_path, until=soon))
    assert r.returncode == 78, r.stderr
    assert "expired or expires within" in r.stderr


def test_valid_cert_passes_the_check(tmp_path):
    """Past the check the fake home has no default config, so the next named
    failure is the proof that the check itself let it through."""
    r = _run(_harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2099"))
    assert r.returncode == 78, r.stderr
    assert "cannot seed the config set" in r.stderr, r.stderr
    assert "expired" not in r.stderr


def test_missing_admin_material_names_the_api(tmp_path):
    r = _run(_harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2099", key=False))
    assert r.returncode == 78
    assert "admin.key is missing" in r.stderr
    assert "docker compose up -d api" in r.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a 0000 file")
def test_unreadable_key_names_the_uid_contract(tmp_path):
    env = _harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2099")
    Path(env["OS_ADMIN_KEY"]).chmod(0o000)
    r = _run(env)
    assert r.returncode == 78
    assert "not readable by uid" in r.stderr
    assert "CORRELIX_UID" in r.stderr


def test_keytool_failure_is_named_with_its_exit_code(tmp_path):
    r = _run(_harness(tmp_path, until=None, keytool_rc=3))
    assert r.returncode == 78
    assert re.search(r"keytool could not read .*\(exit 3\)", r.stderr), r.stderr


def test_unparseable_output_fails_closed(tmp_path):
    r = _run(_harness(tmp_path, until=None))
    assert r.returncode == 78
    assert "could not find the validity line" in r.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root enters a 0000 directory")
def test_stale_image_home_names_the_rebuild(tmp_path):
    env = _harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2099")
    home = Path(env["OS_HOME"])
    home.chmod(0o000)
    try:
        r = _run(env)
    finally:
        home.chmod(0o755)
    assert r.returncode == 78
    assert "docker compose build opensearch" in r.stderr


def test_the_script_never_prints_the_key_path_contents(tmp_path):
    """Failure output carries paths and dates, never certificate fields."""
    r = _run(_harness(tmp_path, until="Mon Jan 05 00:00:00 UTC 2026"))
    assert "test-only" not in r.stderr and "test-only" not in r.stdout
