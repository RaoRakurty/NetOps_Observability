# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`install-correlix.sh upgrade` and `cleanup-old-images` (FMEA 2026-09-15).

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md rows pinned here:

  U1 / row 7 — upgrade from a NEW bundle folder over the existing install:
      preflight + the single-writer lock (both folders) → a VERIFIED backup
      before anything is touched (refuse when it cannot be verified, or when
      there is not the disk to take it) → the previous image tags protected →
      old stack stopped → data/ moved into the new folder → the existing .env
      carried forward (never regenerated; .env.snapshot/.env.damaged are NOT
      carried) → the new bundle's install.py, invoked the way cmd_install
      invokes it → the stability gate.
      Any failure after the first change rolls back: stop the new stack, data
      back, previous image tags back, old stack up, stability gate — and the
      report names both the failure and the rollback result. A rollback that
      fails too says so loudly with the backup path and the manual restore.
  S13 — old images go only through an explicit `cleanup-old-images --confirm`,
      which removes ONLY named refs of the previous bundle (its MANIFEST and the
      rollback tags) that no container uses and the current bundle does not
      name. No prune of any kind, ever.
  T7  — the Kafka ACL script is run by install.py (not this script); pinned
      here only so this script never starts executing a bind-mounted copy.

Every run uses the REAL script with a stateful fake docker, a fake install.py
and a fake backup.sh inside tmp_path. The host's docker is unreachable: the
PATH-prepend line is neutralised (asserted), DOCKER_HOST points at a socket
that does not exist, and each harness first proves `command -v docker` is the
fake (exit 99 otherwise).

Run:  python3 -m pytest tests/test_install_upgrade.py -v
"""

from __future__ import annotations

import fcntl
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install-correlix.sh"

SENTINEL_PW = "Sentinel-Upgrade-Pw-9c2d"
SENTINEL_DB = "Sentinel-Db-Secret-51aa"
_PATH_LINE = 'export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"'


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _fakes_win(src: str) -> str:
    assert src.count(_PATH_LINE) == 1, "install-correlix.sh PATH line changed — update the harness"
    return src.replace(_PATH_LINE, 'export PATH="${PATH:?test harness sets PATH}"')


def _without_dispatch() -> str:
    src = _fakes_win(_src())
    return src[:src.rindex('\ncase "$CMD" in\n')] + "\n"


def _write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ── fakes ───────────────────────────────────────────────────────────────────

# Images db: "ref id" lines. Containers: "container_id|image_id" lines.
FAKE_DOCKER = r"""#!/bin/bash
printf 'docker %s | cwd=%s\n' "$*" "$PWD" >> "$EVENTS"
case "$1" in
  ps)
    if [ "${2:-}" = "-aq" ]; then
      [ -f "$CONTAINERS" ] && awk -F'|' '{print $1}' "$CONTAINERS"
      exit 0
    fi
    case "$*" in
      *working_dir*) [ -n "${FAKE_WORKDIRS:-}" ] && printf '%s\n' $FAKE_WORKDIRS ;;
      *'{{.Image}}'*) [ -f "$PROJECT_IMAGES" ] && cat "$PROJECT_IMAGES" ;;
      *' -q '*) [ -n "${FAKE_RUNNING:-}" ] && printf '%s\n' "$FAKE_RUNNING" ;;
    esac
    exit 0 ;;
  inspect)
    shift
    [ "$1" = "--format" ] && shift 2
    for c in "$@"; do awk -F'|' -v c="$c" '$1 == c {print $2}' "$CONTAINERS"; done
    exit 0 ;;
  image)
    [ "$2" = inspect ] || exit 0
    ref="$5"
    id=$(awk -v r="$ref" '$1 == r {print $2}' "$IMAGES_DB")
    [ -n "$id" ] || { echo "Error: No such image: $ref" >&2; exit 1; }
    printf '%s\n' "$id"
    exit 0 ;;
  tag)
    src="$2"; dst="$3"
    case "$src" in
      sha256:*) awk -v i="$src" '$2 == i {f=1} END {exit !f}' "$IMAGES_DB" || { echo "Error: No such image: $src" >&2; exit 1; }; id="$src" ;;
      *) id=$(awk -v r="$src" '$1 == r {print $2}' "$IMAGES_DB") ;;
    esac
    awk -v r="$dst" '$1 != r' "$IMAGES_DB" > "$IMAGES_DB.tmp"; mv "$IMAGES_DB.tmp" "$IMAGES_DB"
    printf '%s %s\n' "$dst" "$id" >> "$IMAGES_DB"
    exit 0 ;;
  rmi)
    awk -v r="$2" '$1 != r' "$IMAGES_DB" > "$IMAGES_DB.tmp"; mv "$IMAGES_DB.tmp" "$IMAGES_DB"
    exit 0 ;;
  compose)
    if [ "${2:-}" = up ] && [ -n "${FAIL_UP_IN:-}" ] && [ "$PWD" = "$FAIL_UP_IN" ]; then
      echo "Error response from daemon: simulated up failure" >&2; exit 1
    fi
    exit 0 ;;
esac
exit 0
"""

FAKE_BACKUP = r"""#!/bin/bash
if [ "$1" = --verify ]; then
  printf 'backup-verify %s\n' "$2" >> "$EVENTS"
  [ "${FAKE_VERIFY_RC:-0}" = 0 ] || echo "VERIFY FAILED: the manifest records at least one failed component." >&2
  exit "${FAKE_VERIFY_RC:-0}"
fi
printf 'backup %s\n' "$1" >> "$EVENTS"
{ echo "--new-lock"; cat "$NEW_LOCK"; echo "--old-lock"; cat "$OLD_LOCK"; } >> "$LOCKS_SEEN" 2>&1
if [ "${FAKE_BACKUP_RC:-0}" != 0 ]; then echo "backup: postgres dump FAILED" >&2; exit 1; fi
printf 'fake backup artifact\n' > "$1"
echo "  postgres: pass"
"""

FAKE_INSTALL_PY = r"""
import fcntl, json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
dc = root / "deployment" / "docker"
events = os.environ["EVENTS"]
with open(events, "a") as f:
    f.write("install.py " + " ".join(sys.argv[1:]) + "\n")
report = {
    "env_equal": (dc / ".env").read_text() == os.environ["OLD_ENV_TEXT"],
    "env_mode": oct((dc / ".env").stat().st_mode & 0o777),
    "data_here": (root / "data" / "postgres" / "PG_VERSION").is_file(),
    "fd_env": os.environ.get("CORRELIX_INSTALL_LOCK_FD"),
}
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
    report["inherited_flock_ok"] = os.fstat(9).st_ino == os.stat(dc / ".install.lock").st_ino
except OSError as e:
    report["inherited_flock_ok"] = False
Path(os.environ["ENGINE_REPORT"]).write_text(json.dumps(report))
# `docker load` of the new bundle moves the tag onto the new image.
db = Path(os.environ["IMAGES_DB"])
lines = [ln for ln in db.read_text().splitlines() if not ln.startswith("netops-api:latest ")]
lines.append("netops-api:latest sha256:newapi")
db.write_text("\n".join(lines) + "\n")
print("engine: ADMIN_INITIAL_PASSWORD is in .env (value not printed)")
sys.exit(1 if os.environ.get("FAIL_INSTALL") else 0)
"""

OLD_MANIFEST = """product:  Correlix (NetOps Observability)
version:  2026.09.01-gaaaaaaa
profile:  core
images:
  - netops-api:latest
  - postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229
  - netops-opensearch:2.16.0-slim
  - netops-old-only:1.0
"""

NEW_MANIFEST = """product:  Correlix (NetOps Observability)
version:  2026.09.15-gbbbbbbb
profile:  core
images:
  - netops-api:latest
  - postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229
"""

OLD_ENV = (
    "ADMIN_USERNAME=admin\n"
    f"ADMIN_INITIAL_PASSWORD={SENTINEL_PW}\n"
    f"DB_PASSWORD={SENTINEL_DB}\n"
    "BASE_PORT=8000\n"
    "COMPOSE_FILE=docker-compose.yml:compose.tls.yml\n"
    "COMPOSE_PROFILES=embedded-bus,prober\n"
)

GUARD = """
if [ "$(command -v docker)" != "$FAKE_DOCKER" ]; then
  echo "HARNESS: the host's real docker is reachable ($(command -v docker))" >&2
  exit 99
fi
"""

STUBS = """
preflight() { printf 'preflight\\n' >> "$EVENTS"; ok "preflight stubbed by the test harness"; }
wait_healthy() {
  printf 'gate %s\\n' "$COMPOSE_DIR" >> "$EVENTS"
  [ "${FAIL_GATE_IN:-}" != "$COMPOSE_DIR" ]
}
verify_admin_login() { :; }
"""


@dataclass
class Rig:
    tmp: Path
    old: Path          # old bundle dir
    new: Path          # new bundle dir
    env: dict

    @property
    def old_root(self) -> Path:
        return self.old / "NetOps_Observability"

    @property
    def new_root(self) -> Path:
        return self.new / "NetOps_Observability"

    @property
    def old_dc(self) -> Path:
        return self.old_root / "deployment" / "docker"

    @property
    def new_dc(self) -> Path:
        return self.new_root / "deployment" / "docker"

    def events(self) -> list[str]:
        p = Path(self.env["EVENTS"])
        return p.read_text().splitlines() if p.exists() else []

    def images(self) -> dict[str, str]:
        out = {}
        for ln in Path(self.env["IMAGES_DB"]).read_text().splitlines():
            if ln.strip():
                ref, iid = ln.split()
                out[ref] = iid
        return out

    def run(self, args: list[str], tail: str = "", **extra: str):
        env = {**self.env, **extra}
        h = self.new / "harness.sh"
        h.write_text(_without_dispatch() + GUARD + STUBS + tail)
        return subprocess.run(["bash", str(h), *args], capture_output=True, text=True,
                              timeout=180, env=env, stdin=subprocess.DEVNULL, check=False)

    def upgrade(self, *args: str, **extra: str):
        return self.run(["upgrade", *args], "cmd_upgrade\n", **extra)

    def cleanup(self, *args: str, **extra: str):
        return self.run(["cleanup-old-images", *args], "cmd_cleanup_old_images\n", **extra)

    def logs(self) -> str:
        return "".join(p.read_text() for p in self.new.glob("correlix-install-*.log"))


@pytest.fixture()
def rig(tmp_path: Path) -> Rig:
    tmp = tmp_path.resolve()
    old, new = tmp / "old-bundle", tmp / "new-bundle"
    # old install
    (old / "MANIFEST").parent.mkdir(parents=True)
    (old / "MANIFEST").write_text(OLD_MANIFEST)
    odc = old / "NetOps_Observability" / "deployment" / "docker"
    odc.mkdir(parents=True)
    (odc / "docker-compose.yml").write_text("name: netops\nservices: {}\n")
    (odc / "compose.tls.yml").write_text("services: {}\n")
    (odc / "docker-compose.override.yml").write_text("services: {}\n")
    (odc / ".env").write_text(OLD_ENV)
    (odc / ".env").chmod(0o600)
    (odc / ".env.snapshot").write_text(OLD_ENV)
    (odc / ".env.damaged").write_text("ADMIN_INITIAL_PASSWORD=trunc")
    _write_exec(old / "NetOps_Observability" / "scripts" / "backup.sh", FAKE_BACKUP)
    pg = old / "NetOps_Observability" / "data" / "postgres"
    pg.mkdir(parents=True)
    (pg / "PG_VERSION").write_text("16\n")
    # new bundle
    new.mkdir()
    (new / "MANIFEST").write_text(NEW_MANIFEST)
    (new / "correlix-images-core-2026.09.15-gbbbbbbb.tar.zst").write_bytes(b"not really zstd")
    ndc = new / "NetOps_Observability" / "deployment" / "docker"
    ndc.mkdir(parents=True)
    (ndc / "docker-compose.yml").write_text("name: netops\nservices: {}\n")
    (ndc / "compose.tls.yml").write_text("services: {}\n")
    (new / "NetOps_Observability" / "scripts").mkdir()
    (new / "NetOps_Observability" / "scripts" / "install.py").write_text(FAKE_INSTALL_PY)
    inst = new / "install-correlix.sh"
    inst.write_text(_fakes_win(_src()))
    inst.chmod(0o755)
    # docker state
    b = tmp / "bin"
    _write_exec(b / "docker", FAKE_DOCKER)
    _write_exec(b / "curl", "#!/bin/sh\nexit 0\n")
    (tmp / "images.db").write_text(
        "netops-api:latest sha256:oldapi\n"
        "postgres:16-alpine sha256:pg16\n"
        "netops-opensearch:2.16.0-slim sha256:oldos\n"
        "netops-old-only:1.0 sha256:oldonly\n")
    (tmp / "containers.txt").write_text("c1|sha256:oldapi\nc2|sha256:pg16\nc3|sha256:oldos\n")
    (tmp / "project-images.txt").write_text(
        "netops-api:latest\npostgres:16-alpine\nnetops-opensearch:2.16.0-slim\n")
    env = {
        "PATH": f"{b}:/usr/bin:/bin",
        "HOME": str(tmp),
        "TMPDIR": str(tmp),
        "DOCKER_HOST": "unix:///nonexistent/correlix-test/docker.sock",
        "FAKE_DOCKER": str(b / "docker"),
        "EVENTS": str(tmp / "events.txt"),
        "IMAGES_DB": str(tmp / "images.db"),
        "CONTAINERS": str(tmp / "containers.txt"),
        "PROJECT_IMAGES": str(tmp / "project-images.txt"),
        "FAKE_WORKDIRS": str(odc),
        "ENGINE_REPORT": str(tmp / "engine.json"),
        "OLD_ENV_TEXT": OLD_ENV,
        "NEW_LOCK": str(ndc / ".install.lock"),
        "OLD_LOCK": str(odc / ".install.lock"),
        "LOCKS_SEEN": str(tmp / "locks-seen.txt"),
        "CORRELIX_NO_SIZING": "1",
    }
    return Rig(tmp, old, new, env)


def _idx(events: list[str], pred) -> int:
    for i, e in enumerate(events):
        if pred(e):
            return i
    raise AssertionError("event not found:\n" + "\n".join(events))


def _no_secret(*texts: str) -> None:
    for t in texts:
        assert SENTINEL_PW not in t and SENTINEL_DB not in t, "a secret value was printed"


def _backup_dirs(rig: Rig) -> list[Path]:
    return sorted(rig.tmp.glob("correlix-upgrade-backup-*"))


# ── the harness cannot reach the host's docker ──────────────────────────────

def test_the_harness_resolves_docker_to_the_fake(rig: Rig) -> None:
    r = rig.run(["status"], 'echo "DOCKER_IS=$(command -v docker)"\n')
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"DOCKER_IS={rig.env['FAKE_DOCKER']}" in r.stdout


# ── happy path ──────────────────────────────────────────────────────────────

def test_upgrade_happy_path_runs_in_the_safe_order(rig: Rig) -> None:
    r = rig.upgrade()
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    ev = rig.events()
    i_pre = _idx(ev, lambda e: e == "preflight")
    i_bk = _idx(ev, lambda e: e.startswith("backup ") and not e.startswith("backup-verify"))
    i_ver = _idx(ev, lambda e: e.startswith("backup-verify "))
    i_tag = _idx(ev, lambda e: e.startswith("docker tag sha256:") and "correlix-rollback:" in e)
    i_down = _idx(ev, lambda e: e.startswith("docker compose down") and f"cwd={rig.old_dc}" in e)
    i_inst = _idx(ev, lambda e: e.startswith("install.py "))
    i_gate = _idx(ev, lambda e: e == f"gate {rig.new_dc}")
    assert i_pre < i_bk < i_ver < i_tag < i_down < i_inst < i_gate, "\n".join(ev)

    # the lock covered both folders while the backup ran
    seen = Path(rig.env["LOCKS_SEEN"]).read_text()
    assert seen.count("command=upgrade") == 2, seen

    # install.py saw the carried .env (byte-identical, 0600), the data, the lock
    import json
    rep = json.loads(Path(rig.env["ENGINE_REPORT"]).read_text())
    assert rep == {"env_equal": True, "env_mode": "0o600", "data_here": True,
                   "fd_env": "9", "inherited_flock_ok": True}, rep
    argv = ev[i_inst]
    for want in ("--bundle", "--port 8000", "--tls yes", "--bootstrap-docker no"):
        assert want in argv, argv
    assert (rig.new_root / "data" / "postgres" / "PG_VERSION").is_file()
    assert not (rig.old_root / "data").exists()

    # never regenerated, never the damaged/snapshot siblings
    assert (rig.new_dc / ".env").read_text() == OLD_ENV
    assert not (rig.new_dc / ".env.snapshot").exists()
    assert not (rig.new_dc / ".env.damaged").exists()
    # an operator overlay the new bundle does not ship travels (compose.tls.yml does not need to)
    # the old folder can no longer operate the (shared-name) project
    assert not (rig.old_dc / ".env").exists()
    assert list(rig.old_dc.glob(".env.upgraded-*"))

    # no image was removed during the upgrade
    assert not [e for e in ev if e.startswith("docker rmi") or "prune" in e], "\n".join(ev)
    assert "cleanup-old-images --confirm" in out

    [bk] = _backup_dirs(rig)
    assert stat.S_IMODE(bk.stat().st_mode) == 0o700
    assert (bk / "config" / ".env").read_text() == OLD_ENV
    assert (bk / "config" / "MANIFEST").read_text() == OLD_MANIFEST
    assert (bk / "config" / "docker-compose.override.yml").is_file()
    assert not (bk / "config" / ".env.damaged").exists()
    assert str(bk) in out
    _no_secret(r.stdout, r.stderr, rig.logs())


def test_explicit_from_accepts_the_bundle_folder(rig: Rig) -> None:
    r = rig.upgrade("--from", str(rig.old), FAKE_WORKDIRS="")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (rig.new_root / "data" / "postgres" / "PG_VERSION").is_file()


# ── refusals before anything is touched ─────────────────────────────────────

def _untouched(rig: Rig) -> None:
    ev = rig.events()
    assert not [e for e in ev if e.startswith("docker compose")], "\n".join(ev)
    assert not [e for e in ev if e.startswith("install.py")], "\n".join(ev)
    assert (rig.old_root / "data" / "postgres" / "PG_VERSION").is_file()
    assert (rig.old_dc / ".env").read_text() == OLD_ENV
    assert not (rig.new_dc / ".env").exists()
    assert not (rig.new_root / "data").exists()


@pytest.mark.parametrize("knob", ["FAKE_BACKUP_RC", "FAKE_VERIFY_RC"])
def test_an_unverifiable_backup_refuses_the_upgrade(rig: Rig, knob: str) -> None:
    r = rig.upgrade(**{knob: "1"})
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert re.search(r"(?i)backup.*(not be verified|could not be verified|failed)", out), out
    _untouched(rig)
    _no_secret(r.stdout, r.stderr, rig.logs())


def test_too_little_disk_for_the_backup_refuses_before_taking_it(rig: Rig) -> None:
    _write_exec(rig.tmp / "bin" / "df",
                "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
                "/dev/fake 1000 1000 12 100%% /\\n'\n")
    r = rig.upgrade()
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert re.search(r"(?i)free|space", out), out
    assert not [e for e in rig.events() if e.startswith("backup ")]
    _untouched(rig)


def test_no_previous_install_is_a_named_refusal(rig: Rig) -> None:
    r = rig.upgrade(FAKE_WORKDIRS="")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "install" in out and "--from" in out, out
    _untouched(rig)


def test_a_downgrade_is_refused(rig: Rig) -> None:
    (rig.new / "MANIFEST").write_text(NEW_MANIFEST.replace("2026.09.15-gbbbbbbb", "2026.08.01-gccccccc"))
    r = rig.upgrade()
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "2026.08.01" in out and "2026.09.01" in out, out
    _untouched(rig)


def test_upgrade_is_covered_by_the_single_writer_lock(rig: Rig) -> None:
    lock = rig.new_dc / ".install.lock"
    fh = open(lock, "a+")  # noqa: SIM115 — held for the duration of the refused run
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fh.write(f"pid={os.getpid()}\ncommand=install\nstarted_utc=2026-09-15T01:00:00Z\n")
    fh.flush()
    try:
        r = rig.upgrade()
    finally:
        fh.close()
    assert r.returncode == 3, r.stdout + r.stderr
    assert not [e for e in rig.events() if e.startswith("backup")]
    _untouched(rig)


def test_the_previous_install_folder_is_locked_too(rig: Rig) -> None:
    lock = rig.old_dc / ".install.lock"
    fh = open(lock, "a+")  # noqa: SIM115 — held for the duration of the refused run
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        r = rig.upgrade()
    finally:
        fh.close()
    assert r.returncode == 3, r.stdout + r.stderr
    _untouched(rig)


def test_an_interrupted_earlier_upgrade_is_not_blindly_repeated(rig: Rig) -> None:
    (rig.new_dc / ".correlix-upgrade.state").write_text(
        f"status=applying\nprevious_compose_dir={rig.old_dc}\nbackup_dir=/somewhere\n")
    r = rig.upgrade()
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "applying" in out and "/somewhere" in out, out
    assert not [e for e in rig.events() if e.startswith("backup")]


# ── failure → rollback ──────────────────────────────────────────────────────

def _assert_rolled_back(rig: Rig, r) -> None:
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    ev = rig.events()
    i_fail = _idx(ev, lambda e: e.startswith("install.py ") or e == f"gate {rig.new_dc}")
    i_down_new = _idx(ev, lambda e: e.startswith("docker compose down") and f"cwd={rig.new_dc}" in e)
    i_retag = _idx(ev, lambda e: e.startswith("docker tag sha256:oldapi netops-api:latest"))
    i_up_old = _idx(ev, lambda e: e.startswith("docker compose up -d") and f"cwd={rig.old_dc}" in e)
    i_gate_old = _idx(ev, lambda e: e == f"gate {rig.old_dc}")
    assert i_fail < i_down_new < i_retag < i_up_old < i_gate_old, "\n".join(ev)
    assert rig.images()["netops-api:latest"] == "sha256:oldapi", "previous image tag not restored"
    assert (rig.old_root / "data" / "postgres" / "PG_VERSION").is_file(), "data not moved back"
    assert not (rig.new_root / "data").exists()
    assert (rig.old_dc / ".env").read_text() == OLD_ENV, "the previous .env must be untouched"
    assert not (rig.new_dc / ".env").exists(), "the new folder must not look installed"
    assert list(rig.new_dc.glob(".env.upgrade-failed-*"))
    assert re.search(r"(?i)rolled back", out), out
    assert "stable" in out.lower() or "stability" in out.lower(), out
    state = (rig.new_dc / ".correlix-upgrade.state").read_text()
    assert "status=rolled-back" in state, state
    assert not [e for e in ev if e.startswith("docker rmi") or "prune" in e]
    _no_secret(r.stdout, r.stderr, rig.logs())


def test_a_failed_install_rolls_back_to_the_previous_bundle(rig: Rig) -> None:
    r = rig.upgrade(FAIL_INSTALL="1")
    _assert_rolled_back(rig, r)
    assert "install.py" in (r.stdout + r.stderr) or "installer" in (r.stdout + r.stderr)


def test_an_unstable_new_stack_rolls_back(rig: Rig) -> None:
    r = rig.upgrade(FAIL_GATE_IN=str(rig.new_dc))
    _assert_rolled_back(rig, r)
    assert re.search(r"(?i)stab", r.stdout + r.stderr)


def test_a_failed_rollback_is_loud_and_hands_over_the_backup(rig: Rig) -> None:
    r = rig.upgrade(FAIL_INSTALL="1", FAIL_GATE_IN=str(rig.old_dc))
    out = r.stdout + r.stderr
    assert r.returncode == 5, out
    assert "ROLLBACK ALSO FAILED" in out, out
    [bk] = _backup_dirs(rig)
    assert str(bk) in out
    assert "restore.sh" in out and "docker compose up -d" in out, out
    assert "status=rollback-failed" in (rig.new_dc / ".correlix-upgrade.state").read_text()
    _no_secret(r.stdout, r.stderr, rig.logs())


def test_a_rollback_that_cannot_start_the_old_stack_is_loud(rig: Rig) -> None:
    r = rig.upgrade(FAIL_INSTALL="1", FAIL_UP_IN=str(rig.old_dc))
    out = r.stdout + r.stderr
    assert r.returncode == 5, out
    assert "ROLLBACK ALSO FAILED" in out and "simulated up failure" in out, out


# ── cleanup-old-images ──────────────────────────────────────────────────────

def test_cleanup_without_confirm_only_lists(rig: Rig) -> None:
    assert rig.upgrade().returncode == 0
    before = rig.images()
    r = rig.cleanup()
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert rig.images() == before
    assert "netops-old-only:1.0" in out and "--confirm" in out, out
    assert not [e for e in rig.events() if e.startswith("docker rmi")]


def test_cleanup_removes_only_unused_named_refs_of_the_previous_bundle(rig: Rig) -> None:
    assert rig.upgrade().returncode == 0
    # the new stack replaced the api container; opensearch + postgres still run
    (rig.tmp / "containers.txt").write_text("n1|sha256:newapi\nc2|sha256:pg16\nc3|sha256:oldos\n")
    keep_tags = {ref: iid for ref, iid in rig.images().items() if ref.startswith("correlix-rollback:")}
    r = rig.cleanup("--confirm")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    removed = {e.split()[2] for e in rig.events() if e.startswith("docker rmi ")}
    expect = {"netops-old-only:1.0"} | {t for t, i in keep_tags.items() if i in ("sha256:oldapi", "sha256:oldonly")}
    assert removed == expect, (removed, expect, out)
    imgs = rig.images()
    assert imgs["netops-api:latest"] == "sha256:newapi", "the current version's tag was removed"
    assert "postgres:16-alpine" in imgs and "netops-opensearch:2.16.0-slim" in imgs
    assert not [e for e in rig.events() if "prune" in e]


def test_cleanup_refuses_without_a_recorded_upgrade(rig: Rig) -> None:
    rig.new_dc.joinpath(".env").write_text(OLD_ENV)
    r = rig.cleanup("--confirm")
    assert r.returncode == 1, r.stdout + r.stderr
    assert not [e for e in rig.events() if e.startswith("docker rmi")]


def test_cleanup_refuses_after_a_rolled_back_upgrade(rig: Rig) -> None:
    assert rig.upgrade(FAIL_INSTALL="1").returncode == 4
    r = rig.cleanup("--confirm")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "rolled-back" in out
    assert not [e for e in rig.events() if e.startswith("docker rmi")]


# ── the .env copies an upgrade leaves behind ────────────────────────────────
#
# Every upgrade sets the .env it replaced aside under a timestamped name, and
# each of those files holds the whole stack's secrets. Retention has to be
# explicit and bounded (scripts/CLAUDE.md 16.4): the third upgrade on a host
# otherwise leaves three of them, forever, each one 0600 at best.

OLD_STAMPS = ("20250101T000000Z", "20250601T120000Z", "20250901T235959Z")


def _seed_set_asides(dirpath: Path, klass: str, stamps=OLD_STAMPS) -> list[Path]:
    out = []
    for st in stamps:
        f = dirpath / f".env.{klass}-{st}"
        f.write_text(OLD_ENV)
        f.chmod(0o644)
        out.append(f)
    return out


def _prune(rig: Rig, dirpath: Path):
    return rig.run(["status"], f'prune_env_set_asides "{dirpath}/.env"\n')


def test_only_the_newest_copy_of_each_class_survives(rig: Rig, tmp_path: Path) -> None:
    d = tmp_path / "keep"
    d.mkdir()
    (d / ".env").write_text(OLD_ENV)
    _seed_set_asides(d, "upgraded")
    _seed_set_asides(d, "upgrade-failed")
    r = _prune(rig, d)
    assert r.returncode == 0, r.stdout + r.stderr
    left = sorted(p.name for p in d.glob(".env.*"))
    assert left == [f".env.upgrade-failed-{OLD_STAMPS[-1]}", f".env.upgraded-{OLD_STAMPS[-1]}"], left
    assert (d / ".env").is_file(), "the live .env is not a set-aside copy"
    _no_secret(r.stdout, r.stderr)


def test_the_copy_that_is_kept_is_owner_only(rig: Rig, tmp_path: Path) -> None:
    """A copy of .env is as sensitive as .env; one restored from a backup
    archive can arrive 0644."""
    d = tmp_path / "mode"
    d.mkdir()
    kept = _seed_set_asides(d, "upgraded")[-1]
    r = _prune(rig, d)
    assert r.returncode == 0, r.stdout + r.stderr
    assert oct(kept.stat().st_mode & 0o777) == "0o600", oct(kept.stat().st_mode)


def test_a_lone_copy_and_no_copy_at_all_are_both_fine(rig: Rig, tmp_path: Path) -> None:
    """Idempotent (16.3): the prune runs after every upgrade, including the
    first one on a host."""
    d = tmp_path / "lone"
    d.mkdir()
    only = _seed_set_asides(d, "upgraded", stamps=OLD_STAMPS[:1])[0]
    assert _prune(rig, d).returncode == 0
    assert only.is_file()
    assert _prune(rig, d).returncode == 0, "a second run must be a no-op, not a failure"
    empty = tmp_path / "none"
    empty.mkdir()
    r = _prune(rig, empty)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_copy_that_cannot_be_removed_is_named_and_not_fatal(rig: Rig, tmp_path: Path) -> None:
    """16.1: never silent. But an upgrade that worked must not be reported as
    failed because a stale copy could not be deleted."""
    d = tmp_path / "stuck"
    d.mkdir()
    _seed_set_asides(d, "upgraded")
    d.chmod(0o500)
    try:
        r = _prune(rig, d)
    finally:
        d.chmod(0o700)
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "remove it by hand" in out and ".env.upgraded-" in out, \
        "the copy left behind must be named, with the command to remove it: " + out
    assert len(list(d.glob(".env.upgraded-*"))) == 3, "nothing was removed, so nothing may be claimed"
    _no_secret(r.stdout, r.stderr)


def test_a_finished_upgrade_leaves_exactly_one_copy_of_the_old_env(rig: Rig) -> None:
    odc = rig.old / "NetOps_Observability" / "deployment" / "docker"
    _seed_set_asides(odc, "upgraded")
    r = rig.upgrade()
    assert r.returncode == 0, r.stdout + r.stderr
    left = sorted(p.name for p in odc.glob(".env.upgraded-*"))
    assert len(left) == 1, left
    assert left[0] > f".env.upgraded-{OLD_STAMPS[-1]}", (
        "the copy kept must be the one this upgrade just set aside: " + str(left))
    assert oct((odc / left[0]).stat().st_mode & 0o777) == "0o600"


def test_both_set_aside_sites_prune(rig: Rig) -> None:
    """The rollback path sets one aside too — an uncovered sibling accumulates
    forever (16.4)."""
    code = _code()
    sites = [m for m in re.finditer(r'mv -f -- "\$(?:PREV_)?ENV(?:_FILE)?" '
                                    r'"\$(?:PREV_)?ENV(?:_FILE)?\.upgrade', code)]
    assert len(sites) == 2, [code[m.start():m.end()] for m in sites]
    for m in sites:
        after = code[m.end():m.end() + 1200]
        assert "prune_env_set_asides" in after, \
            "a set-aside with no prune after it accumulates: " + code[m.start():m.end()]


# ── static contracts ────────────────────────────────────────────────────────

def _code() -> str:
    return re.sub(r"^\s*#.*$", "", _src(), flags=re.MULTILINE)


def test_no_image_prune_of_any_kind() -> None:
    code = _code()
    for bad in ("image prune", "system prune", "rmi -f", "rmi --force"):
        assert bad not in code, f"install-correlix.sh must never run `docker {bad}` (owner rule)"


def test_the_acl_script_is_never_executed_from_a_bind_mount() -> None:
    """T7: if install-correlix.sh ever runs the ACL matrix itself it must pipe
    the bundle's copy on stdin — a single-file bind mount can be stale."""
    code = _code()
    assert "/acls/apply-acls.sh" not in code
    for m in re.finditer(r"apply-acls\.sh", code):
        line = code[code.rfind("\n", 0, m.start()) + 1:code.find("\n", m.end())]
        assert "sh -s" in line and "<" in line, line


def test_upgrade_invokes_install_py_like_cmd_install() -> None:
    src = _src()
    body = src[src.index("upgrade_apply() {"):]
    body = body[:body.index("\n}\n")]
    assert 'PYTHONUNBUFFERED=1 python3 -u "$ROOT/scripts/install.py" "${INSTALL_ARGS[@]}" 5>&- 6>&-' in body
    assert "wait_healthy" in body
