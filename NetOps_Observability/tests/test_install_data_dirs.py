"""Installer data-dir ownership (2026-08 scale-test defects).

`ensure_data_dirs` used to mkdir and, when a non-root installer could not
chown to the required container uid, print `[info] Fix: sudo chown -R ...`
and CONTINUE — the §16.1 accept-and-ignore defect, and it shipped two broken
deployments in one week:

  * data/correlation/deadletter not owned 10001:999 → every dead-letter write
    failed at runtime → 238k payloads silently lost while offsets advanced;
  * a stale root-owned data/tls/services → the api could not mint its SVIDs
    (mkdir permission denied, crash-loop) → TLS phase-A bootstrap deadlock.

These tests pin the contract that replaced it (`chown_tree`):

  (a) direct chown works → done, no helper container;
  (b) direct chown cannot finish (installer not root, or stale root-owned
      children from a previous run) → fall back to a chown in a helper
      container using the SAME pinned image the stack already pulls;
  (c) BOTH fail → the install FAILS (exit 1) with the sudo remedy — never a
      warn-and-continue into a broken deployment;
  (d) ensure_data_dirs routes every owned dir through that contract,
      including data/tls (recursive) and data/correlation/deadletter.

Everything runs against temp dirs with chown/subprocess monkeypatched — no
docker, no real chown, no root needed.

Run:  python3 -m pytest tests/test_install_data_dirs.py -v
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

import install

# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def fake_root(tmp_path: Path) -> Path:
    """A throwaway project root with the files ensure_data_dirs reads."""
    compose_dir = tmp_path / "deployment" / "docker"
    compose_dir.mkdir(parents=True)
    (compose_dir / ".env").write_text(
        f"CORRELIX_UID={os.getuid()}\nCORRELIX_GID={os.getgid()}\n")
    router = compose_dir / "vector-router"
    router.mkdir()
    (router / "processors-default.yaml").write_text("transforms: {}\n")
    return tmp_path


class DockerRecorder:
    """Stands in for subprocess.run; records the helper-container command."""

    def __init__(self, returncode: int = 0, stderr: str = "",
                 exc: BaseException | None = None):
        self.returncode = returncode
        self.stderr = stderr
        self.exc = exc
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.returncode,
                                           stdout="", stderr=self.stderr)


# ── (a) direct chown works → no helper container ─────────────────────────────

def test_direct_chown_success_never_touches_docker(tmp_path, monkeypatch):
    d = tmp_path / "clickhouse"
    d.mkdir()
    (d / "store").mkdir()
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "chown",
                        lambda p, uid, gid, **kw: chowned.append((str(p), uid, gid)))
    docker = DockerRecorder()
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.chown_tree(d, 101, 101, "clickhouse")

    assert docker.calls == []
    assert (str(d), 101, 101) in chowned
    assert (str(d / "store"), 101, 101) in chowned     # recursive


# ── (b) not-root → docker helper fallback ────────────────────────────────────

def test_permission_error_falls_back_to_pinned_helper_container(tmp_path, monkeypatch):
    d = tmp_path / "correlation" / "deadletter"
    d.mkdir(parents=True)

    def deny(path, uid, gid, **kw):
        raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chown", deny)
    docker = DockerRecorder(returncode=0)
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.chown_tree(d, 10001, 999, "correlation/deadletter")

    assert len(docker.calls) == 1
    cmd = docker.calls[0]
    assert cmd[:3] == ["docker", "run", "--rm"]
    # Reuses the exact pinned image the stack already pulls — no new image,
    # no unpinned pull (§6-style supply-chain hygiene applies to helpers too).
    assert install.CHOWN_HELPER_IMAGE in cmd
    assert "@sha256:" in install.CHOWN_HELPER_IMAGE
    assert f"{d}:/target" in cmd
    assert "10001:999" in cmd
    assert "-R" in cmd                                  # recursive repair


def test_stale_root_owned_child_triggers_fallback(tmp_path, monkeypatch):
    """The data/tls case: the TOP dir chowns fine, but a subtree left behind
    by a previous run (docker-created, root-owned) cannot be — the old code
    swallowed that per-child (`except OSError: pass`); now it must repair via
    the helper container instead."""
    d = tmp_path / "tls"
    stale = d / "services" / "api"
    stale.mkdir(parents=True)

    def chown_only_top(path, uid, gid, **kw):
        if Path(path) != d:
            raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chown", chown_only_top)
    docker = DockerRecorder(returncode=0)
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.chown_tree(d, 1000, 1000, "tls")

    assert len(docker.calls) == 1
    assert f"{d}:/target" in docker.calls[0]


# ── (c) both fail → install FAILS with the sudo remedy ───────────────────────

def deny_chown(path, uid, gid, **kw):
    raise PermissionError(1, "Operation not permitted", str(path))


def test_both_paths_failing_fails_the_install(tmp_path, monkeypatch, capsys):
    d = tmp_path / "clickhouse"
    d.mkdir()
    monkeypatch.setattr(os, "chown", deny_chown)
    docker = DockerRecorder(returncode=125, stderr="docker: pull denied")
    monkeypatch.setattr(install.subprocess, "run", docker)

    with pytest.raises(SystemExit) as excinfo:
        install.chown_tree(d, 101, 101, "clickhouse")

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert f"sudo chown -R 101:101 {d}" in err          # exact remedy
    assert "docker: pull denied" in err                  # §16.1: real stderr shown


def test_docker_binary_missing_counts_as_fallback_failure(tmp_path, monkeypatch, capsys):
    d = tmp_path / "victoria"
    d.mkdir()
    monkeypatch.setattr(os, "chown", deny_chown)
    docker = DockerRecorder(exc=FileNotFoundError("docker"))
    monkeypatch.setattr(install.subprocess, "run", docker)

    with pytest.raises(SystemExit):
        install.chown_tree(d, 1000, 1000, "victoria")
    assert "sudo chown -R 1000:1000" in capsys.readouterr().err


def test_wedged_docker_daemon_is_bounded_and_fails(tmp_path, monkeypatch, capsys):
    d = tmp_path / "kafka"
    d.mkdir()
    monkeypatch.setattr(os, "chown", deny_chown)
    docker = DockerRecorder(exc=subprocess.TimeoutExpired(cmd="docker", timeout=180))
    monkeypatch.setattr(install.subprocess, "run", docker)

    with pytest.raises(SystemExit):
        install.chown_tree(d, 1000, 1000, "kafka")
    assert "sudo chown -R 1000:1000" in capsys.readouterr().err


# ── (d) ensure_data_dirs routes the critical dirs through the contract ───────

def test_ensure_data_dirs_covers_tls_and_deadletter(fake_root, monkeypatch):
    seen: dict[str, tuple[int, int]] = {}

    def record(d: Path, uid: int, gid: int, name: str) -> None:
        seen[name] = (uid, gid)

    monkeypatch.setattr(install, "chown_tree", record)
    install.ensure_data_dirs(fake_root)

    # The two dirs whose wrong ownership shipped broken deployments:
    assert seen["correlation/deadletter"] == (10001, 999)
    assert seen["tls"] == (os.getuid(), os.getgid())     # api runtime uid (.env)
    # ...and both directories exist afterwards.
    assert (fake_root / "data" / "tls").is_dir()
    assert (fake_root / "data" / "correlation" / "deadletter").is_dir()
