# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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

import ast
import os
import re
import stat
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
                 exc: BaseException | None = None,
                 inspect_ok: dict[str, bool] | None = None):
        self.returncode = returncode
        self.stderr = stderr
        self.exc = exc
        self.calls: list[list[str]] = []
        self.inspect_calls: list[list[str]] = []
        # Which refs `docker image inspect` finds locally. Default: the
        # digest-pinned one, i.e. an online host that already pulled it.
        self.inspect_ok = (inspect_ok if inspect_ok is not None
                           else {install.CHOWN_HELPER_IMAGE: True})

    def __call__(self, cmd, **kwargs):
        cmd = list(cmd)
        # `docker image inspect <ref>` is the helper-ref probe (_image_present),
        # not the chown itself. Answer it from `inspect_ok` and keep it out of
        # `calls`, so every assertion below still reads "the helper container
        # ran once, with this command".
        if cmd[:3] == ["docker", "image", "inspect"]:
            self.inspect_calls.append(cmd)
            return subprocess.CompletedProcess(
                cmd, 0 if self.inspect_ok.get(cmd[3], False) else 1,
                stdout="", stderr="")
        self.calls.append(cmd)
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
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    install.ensure_data_dirs(fake_root)

    # The two dirs whose wrong ownership shipped broken deployments:
    assert seen["data/correlation/deadletter"] == (10001, 999)
    assert seen["data/tls"] == (os.getuid(), os.getgid())     # api runtime uid (.env)
    # ...and both directories exist afterwards.
    assert (fake_root / "data" / "tls").is_dir()
    assert (fake_root / "data" / "correlation" / "deadletter").is_dir()
    # 2026-08-16 §16.1 findings: the api-written seed trees and the
    # operator-written feed dirs go through the SAME repair-or-refuse
    # contract — their chowns used to be `except OSError: pass`.
    api_ug = (os.getuid(), os.getgid())
    assert seen["data/api/enrichment"] == api_ug          # api re-exports the CSV
    assert seen["data/api/processors"] == api_ug          # api rewrites processors.yaml
    assert seen["data/api/appid-feeds"] == api_ug         # operator drops feeds
    assert seen["data/api/cloud-fixtures"] == api_ug      # operator drops fixtures
    # No SUDO_UID → the operator-owned vuln dir is not chowned at all.
    assert not any("vuln" in name for name in seen)


def test_ensure_data_dirs_creates_sealed_blob_dirs_0700_api_owned(fake_root, monkeypatch):
    """The two sealed-blob bind sources (device configurations, packet
    captures). Docker auto-creates a MISSING bind source as root, and the api
    is user-mapped with cap_drop:ALL — so a dir the installer does not
    pre-create is one the module can never write, failing its first capture
    and every one after it. The MODE is part of the contract too: the blobs
    are sealed, but the listing (device ids, capture times) and any payload
    bytes are owner-only."""
    seen: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, uid, gid, name: seen.update({name: (uid, gid)}))
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    install.ensure_data_dirs(fake_root)

    api_ug = (os.getuid(), os.getgid())          # api runtime uid from .env
    for name in ("config-backups", "pcap"):
        d = fake_root / "data" / name
        assert d.is_dir(), f"data/{name} was not created"
        assert seen[f"data/{name}"] == api_ug, (
            f"data/{name} must be owned by the api's RUNTIME uid")
        assert stat.S_IMODE(d.stat().st_mode) == 0o700, (
            f"data/{name} must be 0700 — it holds sealed device data")


def test_ensure_data_dirs_reports_an_unsettable_private_mode(fake_root, monkeypatch, capsys):
    """§16.1: a blob dir left group/world-readable is a real posture
    regression, so a failing chmod FAILS the install with the remedy — it is
    never warned past."""
    monkeypatch.setattr(install, "chown_tree", lambda d, uid, gid, name: None)
    monkeypatch.delenv("SUDO_UID", raising=False)
    real_chmod = Path.chmod

    def boom(self, mode, **kw):
        if self.name in ("config-backups", "pcap"):
            raise PermissionError(1, "Operation not permitted", str(self))
        return real_chmod(self, mode, **kw)

    monkeypatch.setattr(Path, "chmod", boom)
    with pytest.raises(SystemExit):
        install.ensure_data_dirs(fake_root)
    assert "sudo chmod 0700" in capsys.readouterr().err


def test_ensure_data_dirs_hands_vuln_dir_to_the_sudo_invoker(fake_root, monkeypatch):
    """Under sudo, data/vuln goes to the INVOKING user (they run
    vuln-feed-prepare.py without root afterwards) — through chown_tree, not
    the old silently-swallowed chown."""
    seen: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, uid, gid, name: seen.update({name: (uid, gid)}))
    monkeypatch.setenv("SUDO_UID", "1234")
    monkeypatch.setenv("SUDO_GID", "5678")
    install.ensure_data_dirs(fake_root)
    assert seen["data/vuln (operator-owned)"] == (1234, 5678)


def test_ensure_data_dirs_reports_malformed_sudo_ids_and_skips_vuln_chown(
        fake_root, monkeypatch, capsys):
    """A mangled SUDO_UID must not be guessed around: no chown for data/vuln,
    and the degraded state is REPORTED (§16.1), never silent."""
    seen: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, uid, gid, name: seen.update({name: (uid, gid)}))
    monkeypatch.setenv("SUDO_UID", "not-a-uid")
    monkeypatch.delenv("SUDO_GID", raising=False)
    install.ensure_data_dirs(fake_root)
    assert not any("vuln" in name for name in seen)
    err = capsys.readouterr().err
    assert "SUDO_UID/SUDO_GID malformed" in err
    assert "vuln-feed-prepare.py" in err


# ── nginx ingress TLS key: same §16.1 class, same contract ───────────────────
#
# ensure_ingress_cert used to warn "Fix: sudo chown 101 ..." and continue when
# a non-root installer could not hand the 0600 privkey.pem to nginx (uid 101,
# cap_drop:ALL, no DAC_OVERRIDE) — shipping an ingress that crash-loops on
# "cannot load certificate key ... Permission denied".

def _stat_owned_by(uid: int, gid: int):
    class _St:
        st_uid = uid
        st_gid = gid
    return lambda _p: _St()


def test_ingress_key_already_owned_by_nginx_is_left_alone(tmp_path, monkeypatch):
    key = tmp_path / "privkey.pem"
    key.write_text("key")
    monkeypatch.setattr(os, "chown", deny_chown)      # would blow up if called
    docker = DockerRecorder()
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.ensure_ingress_key_owner(key, statfn=_stat_owned_by(101, 101))

    assert docker.calls == []                          # no helper spawned on re-runs


def test_ingress_key_nonroot_falls_back_to_helper_container(tmp_path, monkeypatch):
    key = tmp_path / "privkey.pem"
    key.write_text("key")
    monkeypatch.setattr(os, "chown", deny_chown)
    docker = DockerRecorder(returncode=0)
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.ensure_ingress_key_owner(key, statfn=_stat_owned_by(1000, 1000))

    assert len(docker.calls) == 1
    cmd = docker.calls[0]
    assert install.CHOWN_HELPER_IMAGE in cmd
    assert f"{key}:/target" in cmd                     # the key file itself is mounted
    assert "101:101" in cmd


def test_ingress_key_both_paths_failing_fails_the_install(tmp_path, monkeypatch, capsys):
    key = tmp_path / "privkey.pem"
    key.write_text("key")
    monkeypatch.setattr(os, "chown", deny_chown)
    docker = DockerRecorder(returncode=125, stderr="docker: daemon down")
    monkeypatch.setattr(install.subprocess, "run", docker)

    with pytest.raises(SystemExit) as excinfo:
        install.ensure_ingress_key_owner(key, statfn=_stat_owned_by(1000, 1000))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert f"sudo chown -R 101:101 {key}" in err       # exact remedy
    assert "docker: daemon down" in err                # §16.1: real stderr shown


def test_ingress_key_missing_fails_instead_of_chowning_nothing(tmp_path, monkeypatch, capsys):
    """A missing key must fail loudly, and must NOT reach the docker fallback:
    bind-mounting a nonexistent source would make docker CREATE it as a
    root-owned directory — manufacturing the exact broken state this exists
    to prevent."""
    docker = DockerRecorder()
    monkeypatch.setattr(install.subprocess, "run", docker)

    with pytest.raises(SystemExit):
        install.ensure_ingress_key_owner(tmp_path / "privkey.pem")

    assert docker.calls == []
    assert "ingress private key missing" in capsys.readouterr().err


# ── (e) air-gap: the helper ref must resolve on a docker-load'ed host ────────
# Fresh-install acceptance, 2026-09-06 (lab host 10.70.245.123). Every
# non-root install with the DEFAULT TLS posture died at the TLS stage:
# ensure_ingress_key_owner() could not chown privkey.pem to 101:101 directly,
# fell back to the helper container, and docker could not find
# `postgres:16-alpine@sha256:...` locally — because `docker load` restores an
# image by TAG and a registry digest is pull-time metadata the archive never
# carries. Docker then reached for registry-1.docker.io, which an air-gapped
# appliance must never do and which fails outright with no egress.

def test_helper_ref_prefers_digest_when_it_is_local(monkeypatch):
    docker = DockerRecorder(inspect_ok={install.CHOWN_HELPER_IMAGE: True})
    monkeypatch.setattr(install.subprocess, "run", docker)
    assert install._chown_helper_ref() == install.CHOWN_HELPER_IMAGE


def test_helper_ref_falls_back_to_tag_on_a_docker_loaded_host(monkeypatch):
    """The offline-bundle case: only the TAG exists locally."""
    docker = DockerRecorder(inspect_ok={install.CHOWN_HELPER_IMAGE_TAG: True})
    monkeypatch.setattr(install.subprocess, "run", docker)
    assert install._chown_helper_ref() == install.CHOWN_HELPER_IMAGE_TAG
    assert "@sha256:" not in install.CHOWN_HELPER_IMAGE_TAG


def test_helper_ref_stays_digest_pinned_when_nothing_is_local(monkeypatch):
    """Online install, image not pulled yet: pull a PINNED ref, never a
    floating tag (§6 supply-chain hygiene applies to helper images too)."""
    docker = DockerRecorder(inspect_ok={})
    monkeypatch.setattr(install.subprocess, "run", docker)
    assert install._chown_helper_ref() == install.CHOWN_HELPER_IMAGE
    assert "@sha256:" in install.CHOWN_HELPER_IMAGE


def test_tag_ref_is_the_digest_ref_without_its_digest():
    """The two refs must name the SAME image, or the fallback silently runs
    something else than the one the stack already ships."""
    assert install.CHOWN_HELPER_IMAGE.split("@")[0] == install.CHOWN_HELPER_IMAGE_TAG


def test_offline_chown_uses_the_loaded_tag_not_the_digest(tmp_path, monkeypatch):
    """End-to-end shape of the acceptance failure: not root, and only the
    docker-load'ed tag on the host → the helper container must still run."""
    d = tmp_path / "certs"
    d.mkdir()

    def deny(path, uid, gid, **kw):
        raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chown", deny)
    docker = DockerRecorder(returncode=0,
                            inspect_ok={install.CHOWN_HELPER_IMAGE_TAG: True})
    monkeypatch.setattr(install.subprocess, "run", docker)

    install.chown_tree(d, 101, 101, "nginx ingress TLS key (privkey.pem)")

    assert len(docker.calls) == 1
    cmd = docker.calls[0]
    assert install.CHOWN_HELPER_IMAGE_TAG in cmd
    assert install.CHOWN_HELPER_IMAGE not in cmd     # the un-pullable digest ref
    assert "101:101" in cmd


# ── (f) ordering: images must be loaded before the first chown fallback ─────

def test_bundle_load_precedes_the_chown_dependent_steps():
    """`ensure_ingress_cert` (uid 101) and `ensure_data_dirs` (service uids)
    both need the helper container on a non-root install, and the helper needs
    an image. On a virgin air-gapped host the ONLY thing that puts an image on
    the host is load_bundle() — so it must run first. Pinned by source order
    because the alternative is re-running a 10-minute install to find out."""
    src = (SCRIPTS / "install.py").read_text()
    main_src = src[src.index("def main("):]
    load = main_src.index("load_bundle(args.bundle)")
    cert = main_src.index("ensure_ingress_cert(root)")
    dirs = main_src.index("ensure_data_dirs(root)")
    assert load < cert, "load_bundle must precede ensure_ingress_cert"
    assert load < dirs, "load_bundle must precede ensure_data_dirs"


# ── (g) postgres first-boot race: readiness and provisioning must ride it ───
# Fresh-install acceptance, 2026-09-06. The official postgres entrypoint runs
# initdb, starts a TEMPORARY server on the unix socket for its init scripts,
# shuts that down, and only then starts the real one. `pg_isready` answers
# "ready" against the temporary server, so the very next psql landed in the
# shutdown window and the whole install died on
# "FATAL: the database system is shutting down".
#
# 2026-09-14, .123 lab box, GUI wizard, first Install attempt: it happened
# AGAIN, in its most common form —
#   psql: error: connection to server on socket
#   "/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory
# — and the retry loop spent ZERO retries on it, because the transient
# classifier spelled that case `No such file or directory.*PGSQL` while psql
# prints the socket path FIRST. Reproduced against a throwaway
# postgres:16-alpine container: every probe for the first ~16s of a first boot
# fails with exactly that text. The tests below pin both halves of the fix:
# the classifier, and a readiness signal that is a real query on the real
# server rather than pg_isready.

#: The verbatim first-boot error from the .123 lab install (2026-09-14) and
#: from the local postgres:16-alpine reproduction.
LAB_SOCKET_ERROR = (
    'psql: error: connection to server on socket '
    '"/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory\n'
    '\tIs the server running locally and accepting connections on that socket?')

#: A genuine error waiting cannot fix.
REAL_SQL_ERROR = (
    'psql: error: connection to server at "127.0.0.1", port 5432 failed: '
    'FATAL:  password authentication failed for user "netops_app"')


class FakeRotation:
    """Stands in for the secret_rotation module's provision_app_state_role."""

    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def provision_app_state_role(self, runner, **kw):
        self.calls += 1
        return self.results[min(self.calls - 1, len(self.results) - 1)]


class FakeRunner:
    """Stands in for `docker compose exec -T <service> …`.

    `script` is a list of (returncode, stdout, stderr); the last entry repeats,
    so "fails forever" and "fails N times then succeeds" are both one line.
    """

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[list[str]] = []

    def exec(self, service, argv, stdin="", timeout=60):
        self.calls.append(list(argv))
        rc, out, err = self.script[min(len(self.calls) - 1, len(self.script) - 1)]
        return install._rotation_module().ExecResult(rc, out, err)


SOCKET_FAIL = (2, "", LAB_SOCKET_ERROR)
QUERY_OK = (0, "1\n", "")


class FakeClock:
    """Monotonic time the test advances — only through sleep()."""

    def __init__(self) -> None:
        self.t = 0.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, d: float) -> None:
        self.slept.append(d)
        self.t += d


# -- the classifier itself ---------------------------------------------------

@pytest.mark.parametrize("transient", [
    LAB_SOCKET_ERROR,
    "psql: error: FATAL:  the database system is shutting down",
    "psql: error: FATAL:  the database system is starting up",
    ('connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" '
     "failed: Connection refused"),
    'connection to server at "127.0.0.1", port 5432 failed: Connection refused',
    "server closed the connection unexpectedly",
    'service "postgres" is not running',
])
def test_connection_class_errors_are_transient(transient):
    assert install._pg_transient(transient), (
        f"{transient!r} is a connection failure — it must be retried, not fatal")


@pytest.mark.parametrize("fatal", [
    REAL_SQL_ERROR,
    'ERROR:  syntax error at or near "CREAT"',
    'FATAL:  database "netops" does not exist',
    'ERROR:  permission denied for schema public',
])
def test_real_errors_are_never_classified_transient(fatal):
    assert not install._pg_transient(fatal), (
        f"{fatal!r} cannot be fixed by waiting — it must surface immediately")


# -- wait_for_postgres: a real query on the real server ----------------------

def test_readiness_waits_through_the_socket_window_then_succeeds():
    """(a) the lab failure: N socket errors, then the real server answers."""
    clock = FakeClock()
    runner = FakeRunner([SOCKET_FAIL] * 5 + [QUERY_OK])
    ready, msg = install.wait_for_postgres(
        runner, user="netops", db="netops", budget_s=180.0,
        sleep=clock.sleep, now=clock.now)
    assert ready, msg
    assert "ready after" in msg
    probes = [c for c in runner.calls if c[0] == "psql"]
    assert len(probes) >= 7, "must probe past the window and confirm stability"
    assert probes[0][-1] == "select 1", "readiness must be a REAL query"
    assert clock.slept, "the waits must be logged/bounded, not a busy loop"


def test_readiness_requires_two_successes_a_stable_interval_apart():
    """The init server answers too — one success must never be enough."""
    clock = FakeClock()
    runner = FakeRunner([QUERY_OK] * 20)
    ready, _msg = install.wait_for_postgres(
        runner, user="netops", db="netops", budget_s=180.0, stable_s=2.0,
        sleep=clock.sleep, now=clock.now)
    assert ready
    assert len(runner.calls) >= 2, "one answer is the init server's answer too"
    assert clock.t >= 2.0, f"must observe the server for >= 2s, waited {clock.t}"


def test_an_init_server_that_goes_away_does_not_count_as_ready():
    """Answer, vanish (the init→real handover), answer twice → only then ready."""
    clock = FakeClock()
    runner = FakeRunner([QUERY_OK, SOCKET_FAIL, SOCKET_FAIL, QUERY_OK, QUERY_OK])
    ready, msg = install.wait_for_postgres(
        runner, user="netops", db="netops", budget_s=180.0, stable_s=2.0,
        sleep=clock.sleep, now=clock.now)
    assert ready, msg
    assert len(runner.calls) >= 5, (
        "the stability window must restart after the server drops, not carry "
        "the init server's success forward")


def test_readiness_surfaces_a_real_error_immediately():
    """(b) a genuine SQL/auth error is never masked as 'not ready yet'."""
    clock = FakeClock()
    runner = FakeRunner([(2, "", REAL_SQL_ERROR)])
    ready, msg = install.wait_for_postgres(
        runner, user="netops", db="netops", budget_s=180.0,
        sleep=clock.sleep, now=clock.now)
    assert not ready
    assert len(runner.calls) == 1, "a real error must not be retried"
    assert "password authentication failed" in msg
    assert clock.slept == []


def test_readiness_is_bounded_and_reports_the_elapsed_time():
    """(c) a postgres that never boots fails after the budget, loudly."""
    clock = FakeClock()
    runner = FakeRunner([SOCKET_FAIL])
    ready, msg = install.wait_for_postgres(
        runner, user="netops", db="netops", budget_s=30.0,
        sleep=clock.sleep, now=clock.now)
    assert not ready
    assert "did not become ready within 30s" in msg
    assert "elapsed" in msg and "No such file or directory" in msg
    assert clock.t >= 30.0 and len(runner.calls) < 200, "bounded, not a spin"


def test_readiness_backoff_is_jittered_and_capped():
    clock = FakeClock()
    runner = FakeRunner([SOCKET_FAIL])
    install.wait_for_postgres(runner, user="netops", db="netops", budget_s=120.0,
                              sleep=clock.sleep, now=clock.now)
    assert max(clock.slept) <= 10.0 * 1.25 + 0.01, "backoff must be capped"
    assert len(set(clock.slept)) > 1, "backoff must carry jitter (§9)"


def test_readiness_budget_is_env_tunable(monkeypatch):
    monkeypatch.setenv(install.PG_READY_BUDGET_ENV, "42")
    assert install._pg_ready_budget_s() == 42.0
    monkeypatch.setenv(install.PG_READY_BUDGET_ENV, "not-a-number")
    assert install._pg_ready_budget_s() == install.PG_READY_BUDGET_S
    monkeypatch.setenv(install.PG_READY_BUDGET_ENV, "-5")
    assert install._pg_ready_budget_s() == install.PG_READY_BUDGET_S
    monkeypatch.delenv(install.PG_READY_BUDGET_ENV)
    assert install._pg_ready_budget_s() == install.PG_READY_BUDGET_S


# -- provisioning retry ------------------------------------------------------

def _provision(sr, tmp_path, ready=None, clock=None, **kw):
    clock = clock or FakeClock()
    ready = ready or (lambda budget_s: (True, "ready after 0s"))
    ok, msg = install._provision_app_state_role_with_retry(
        sr, tmp_path, db_user="netops", db_name="netops",
        app_user="netops_app", app_password="pw",
        runner=FakeRunner([QUERY_OK]), ready=ready,
        sleep=clock.sleep, now=clock.now, **kw)
    return ok, msg, clock.slept


@pytest.mark.parametrize("transient", [
    LAB_SOCKET_ERROR,
    "psql: error: FATAL:  the database system is shutting down",
    "psql: error: FATAL:  the database system is starting up",
    ('connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" '
     "failed: Connection refused"),
    "server closed the connection unexpectedly",
])
def test_first_boot_states_are_retried_not_fatal(transient, tmp_path):
    sr = FakeRotation([(False, transient), (False, transient), (True, "created")])
    ok, _msg, slept = _provision(sr, tmp_path)
    assert ok, f"{transient!r} must be retried, not treated as a hard failure"
    assert sr.calls == 3
    assert slept and slept == sorted(slept), "retries must back off"


def test_the_lab_failure_is_survived_and_reported(tmp_path, capsys):
    """(a) end to end: the exact 2026-09-14 message, then success."""
    sr = FakeRotation([(False, f"provisioning failed: {LAB_SOCKET_ERROR}")] * 3
                      + [(True, "app-state role provisioned and verified")])
    ok, msg, _slept = _provision(sr, tmp_path)
    assert ok and sr.calls == 4
    out = capsys.readouterr().out
    assert "provisioned on attempt 4" in out, out
    assert "budget" in out, "every wait must name the elapsed time (§16.1)"
    assert "provisioned and verified" in msg


def test_readiness_is_re_proved_before_every_retry(tmp_path):
    """A retry must not be thrown at a socket that is still gone."""
    seen: list[float] = []

    def ready(budget_s):
        seen.append(budget_s)
        return (True, "ready after 1s")

    sr = FakeRotation([(False, LAB_SOCKET_ERROR), (False, LAB_SOCKET_ERROR),
                       (True, "created")])
    ok, _msg, _slept = _provision(sr, tmp_path, ready=ready)
    assert ok
    assert len(seen) == 2, "readiness must be re-proved before each retry"
    assert all(b > 0 for b in seen), "the re-check must get the REMAINING budget"


def test_a_readiness_failure_during_retries_is_final(tmp_path):
    """The readiness helper is itself bounded — its verdict is the last word."""
    sr = FakeRotation([(False, LAB_SOCKET_ERROR)])
    verdict = (False, "postgres did not become ready within 180s (40 probes)")
    ok, msg, _slept = _provision(sr, tmp_path, ready=lambda budget_s: verdict)
    assert not ok
    assert "did not become ready" in msg
    assert sr.calls == 1


def test_a_real_error_is_not_retried(tmp_path):
    """A genuine failure must surface immediately — three minutes of retries
    on a bad password only delays the message the operator needs."""
    sr = FakeRotation([(False, f"provisioning failed: {REAL_SQL_ERROR}")])
    ok, msg, slept = _provision(sr, tmp_path)
    assert not ok
    assert sr.calls == 1, "a non-transient error must not be retried"
    assert slept == []
    assert "password authentication failed" in msg


def test_retry_is_bounded(tmp_path):
    """(c) a postgres that never finishes booting must not hang the install."""
    sr = FakeRotation([(False, "FATAL:  the database system is starting up")])
    clock = FakeClock()
    ok, msg, _slept = _provision(sr, tmp_path, clock=clock, deadline_s=30.0)
    assert not ok
    assert "still transient after" in msg
    assert clock.t >= 30.0, "the budget must actually be spent waiting"
    assert sr.calls < 100, "the retry loop must terminate, not spin"


def test_first_attempt_success_does_not_sleep(tmp_path):
    sr = FakeRotation([(True, "already present")])
    ok, _msg, slept = _provision(sr, tmp_path)
    assert ok and sr.calls == 1 and slept == []


def test_no_call_site_judges_postgres_by_pg_isready():
    """The regression guard: pg_isready answers for the entrypoint's temporary
    init server, so it must never again be the signal a step keys on. Checked
    over the AST, so the prose explaining that cannot satisfy the test."""
    tree = ast.parse((SCRIPTS / "install.py").read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and node.body:
            first = node.body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and "pg_isready" in node.value and id(node) not in docstrings):
            raise AssertionError(
                f"install.py line {node.lineno} runs pg_isready as a readiness "
                f"signal — use wait_for_postgres()")


def test_the_postgres_bootstraps_use_the_shared_readiness_helper():
    src = (SCRIPTS / "install.py").read_text()
    for func in ("def bootstrap_app_state_role(", "def bootstrap_keycloak_db("):
        start = src.index(func)
        body = src[start:src.index("\ndef ", start + 1)]
        assert "wait_for_postgres(" in body, (
            f"{func} talks to postgres right after a compose up — it must wait "
            f"for it through the shared helper")


# ── (h) data/tls/services must be the api's tree, never Docker's ────────────
# Fresh-install acceptance, 2026-09-06. data/tls IS chowned recursively — but
# on a FRESH install it is empty at that moment, so there is nothing under it
# to repair. Docker then created data/tls/services (and services/vmauth, a
# bind-mount source) as ROOT when the first TLS-fronted service started, and
# the api's internal CA could no longer mint into it:
#   "internal CA: tls ca: svid registry: api: mkdir /data/tls/services/api:
#    permission denied"
# TLS phase A then deadlocked and the install failed at 83%.
# preflight-install.py had flagged exactly this as a WARNING whose comment
# reads "docker auto-creates a missing bind-mount dir (as root), so this
# doesn't hard-break a fresh install" — for data/tls/services it does.

def test_tls_service_mount_dirs_are_derived_from_compose():
    compose_dir = ROOT / "deployment" / "docker"
    dirs = install.tls_service_mount_dirs(compose_dir)
    assert dirs, "no data/tls/services/<name> bind mounts parsed out of compose"
    assert all(d.startswith("tls/services/") for d in dirs)
    # vmauth is the one that actually broke the install: it joined the default
    # profile set (TLS_EXTRA_PROFILES) and mounts an SVID dir.
    assert "tls/services/vmauth" in dirs, (
        "the vmauth SVID mount is no longer parsed — the dir Docker would "
        "create as root is exactly the one that deadlocked TLS phase A")


def test_ensure_data_dirs_pre_creates_the_tls_service_root_and_children(
        fake_root, monkeypatch):
    """Every per-service SVID dir must exist, owned by the api uid, BEFORE
    compose runs — otherwise Docker gets there first, as root."""
    seen: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(install, "chown_tree",
                        lambda d, uid, gid, name: seen.__setitem__(name, (uid, gid)))
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    # give the fake root the real compose files so the derivation has input
    compose_dir = fake_root / "deployment" / "docker"
    for name in ("docker-compose.yml", "compose.tls.yml"):
        src = ROOT / "deployment" / "docker" / name
        if src.exists():
            (compose_dir / name).write_text(src.read_text())

    install.ensure_data_dirs(fake_root)

    api_ug = (os.getuid(), os.getgid())
    assert seen["data/tls/services"] == api_ug, (
        "data/tls/services must be pre-created and owned by the api runtime "
        "uid, or Docker creates it as root and the api can never mint")
    assert (fake_root / "data" / "tls" / "services").is_dir()
    for rel in install.tls_service_mount_dirs(compose_dir):
        assert seen[f"data/{rel}"] == api_ug, f"data/{rel} not owned by the api uid"
        assert (fake_root / "data" / rel).is_dir(), f"data/{rel} was not created"


def test_tls_services_is_created_before_any_compose_up():
    """Source-order guard: ensure_data_dirs must run before compose_up, or the
    pre-creation is pointless — Docker would already have won the race."""
    src = (SCRIPTS / "install.py").read_text()
    main_src = src[src.index("def main("):]
    dirs = main_src.index("ensure_data_dirs(root)")
    up = main_src.index("compose_up(compose_dir")
    assert dirs < up, "ensure_data_dirs must precede the first compose_up"


# ── (i) the installer's own preflight must be clean on an INSTALLED host ────
# Fresh-install acceptance, 2026-09-06. preflight-install.py ships inside the
# customer bundle, but it hard-failed on every installed appliance:
#   ✗ docs/security/transport-inventory.yaml missing (SEC-001.1 as-built inventory)
# make-installer.sh deliberately leaves the security-design docs out of the
# customer tree, so the gate was failing on the absence of a file the customer
# was never sent — and telling them so in language about an internal invariant.

def _run_preflight(cwd: Path):
    return subprocess.run([sys.executable, str(SCRIPTS / "preflight-install.py")],
                          cwd=str(cwd), capture_output=True, text=True, check=False)


def test_preflight_is_clean_in_the_repo():
    """The gate must still do its job where drift actually happens."""
    r = _run_preflight(ROOT)
    assert r.returncode == 0, (
        f"preflight-install.py fails in the repo:\n{r.stdout}\n{r.stderr}")


def test_preflight_reports_the_real_migration_count():
    """The migrations line pointed at src/backend/migrations, which has not
    existed for a long time, so it reported '0 present' on every single run."""
    r = _run_preflight(ROOT)
    m = re.search(r"\[migrations\] (\d+) present", r.stdout)
    assert m, f"no migrations line in the output:\n{r.stdout}"
    counted = int(m.group(1))
    actual = len(list((ROOT / "src" / "backend" / "internal" / "platformdb"
                       / "migrations").glob("*.sql")))
    assert counted == actual and counted > 0, (
        f"preflight reports {counted} migrations, the tree has {actual} — "
        "the path is stale again")


def test_transport_inventory_gate_is_repo_only():
    """Absent inventory + no git (an extracted customer tree) must SKIP, not
    fail; absent inventory inside a git checkout must still fail."""
    src = (SCRIPTS / "preflight-install.py").read_text()
    block = src[src.index('inv_path = ROOT / "docs"'):]
    block = block[:block.index("# 6)")] if "# 6)" in block else block[:4000]
    assert "if tracked is None:" in block, (
        "the transport-inventory check no longer distinguishes an extracted "
        "customer tree from a git checkout — it will fail on every install")
    head = block[:block.index("else:")]
    assert "warn(" in head and "bad(" not in head, (
        "a shipped tree without the repo-only inventory must warn, not fail")
    assert "bad(" in block[block.index("else:"):], (
        "a GIT checkout missing the inventory must still fail — that is the drift "
        "this gate exists to catch")
