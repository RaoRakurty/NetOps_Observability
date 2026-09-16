# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""An install from a NEW folder must not adopt another folder's stack.

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md rows pinned here:

  S7 / row 7 — the compose project name is fixed (`name: netops`), so an
               `install` from a second bundle folder takes over the first
               folder's containers while that folder's data and settings stay
               behind. Preflight reads the compose labels of every container
               of project `netops` and refuses when one belongs to a DIFFERENT
               working directory, naming it and the two supported ways forward
               (`upgrade` from the new bundle, or `uninstall` the old one).
               The same folder is a normal idempotent re-run.
  X3 (2026-09-15 addendum) — `uninstall --purge` removes every .env sibling
               that carries secrets: .env.snapshot, .env.damaged,
               .env.rotate.bak (+ .env.plan.bak and a failed upgrade's
               set-aside .env).
  Q4         — uninstall leaves host hardening in place BY DESIGN; the help
               text says so and there is no --purge-host.

The REAL script runs with docker faked on PATH. The host's docker cannot be
reached: the script's PATH-prepend line is neutralised (asserted), DOCKER_HOST
points at a socket that does not exist, and every harness run first proves
`command -v docker` is the fake.

Run:  python3 -m pytest tests/test_install_existing_detection.py -v
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install-correlix.sh"

SENTINEL_PW = "Sentinel-Pw-Detect-4b1e"
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
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


FAKE_DOCKER = r"""#!/bin/bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
if [ "$1" = ps ]; then
  [ -n "${FAKE_PS_FAIL:-}" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
  case "$*" in
    *com.docker.compose.project.working_dir*) [ -n "${FAKE_WORKDIRS:-}" ] && printf '%s\n' $FAKE_WORKDIRS ;;
  esac
fi
exit 0
"""

GUARD = """
if [ "$(command -v docker)" != "$FAKE_DOCKER" ]; then
  echo "HARNESS: the host's real docker is reachable ($(command -v docker))" >&2
  exit 99
fi
"""


def _tree(tmp_path: Path, name: str = "root") -> Path:
    root = tmp_path / name
    (root / "scripts").mkdir(parents=True)
    dc = root / "deployment" / "docker"
    dc.mkdir(parents=True)
    (dc / "docker-compose.yml").write_text("name: netops\nservices: {}\n")
    dst = root / "scripts" / "install-correlix.sh"
    dst.write_text(_fakes_win(_src()))
    dst.chmod(0o755)
    return root


def _env(tmp_path: Path, **extra: str) -> dict:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    _write_exec(b / "docker", FAKE_DOCKER)
    _write_exec(b / "curl", "#!/bin/sh\nexit 0\n")
    env = {
        "PATH": f"{b}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "DOCKER_LOG": str(tmp_path / "docker.log"),
        "DOCKER_HOST": "unix:///nonexistent/correlix-test/docker.sock",
        "FAKE_DOCKER": str(b / "docker"),
        "CORRELIX_NO_SIZING": "1",
    }
    env.update(extra)
    return env


def _harness(root: Path, tail: str, args: list[str], env: dict):
    h = root / "scripts" / "harness.sh"
    h.write_text(_without_dispatch() + GUARD + tail)
    return subprocess.run(["bash", str(h), *args], capture_output=True, text=True,
                          timeout=120, env=env, stdin=subprocess.DEVNULL, check=False)


# ── the harness itself cannot reach the host's docker ───────────────────────

def test_the_harness_resolves_docker_to_the_fake(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    env = _env(tmp_path)
    r = _harness(root, 'echo "DOCKER_IS=$(command -v docker)"\n', ["status"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"DOCKER_IS={env['FAKE_DOCKER']}" in r.stdout
    assert env["DOCKER_HOST"].startswith("unix:///nonexistent/")


# ── S7: existing install in another folder ──────────────────────────────────

def test_a_stack_owned_by_another_folder_is_refused_by_name(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    other = _tree(tmp_path, "old-bundle/NetOps_Observability")
    other_dc = other / "deployment" / "docker"
    env = _env(tmp_path, FAKE_WORKDIRS=str(other_dc))
    r = _harness(root, "check_existing_install\necho REACHED\n", ["install"], env)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "REACHED" not in out
    assert str(other_dc) in out, "the refusal must name the other install's folder"
    assert "upgrade" in out and "uninstall" in out, (
        "the refusal must give the two supported ways forward")
    assert "label=com.docker.compose.project=netops" in (tmp_path / "docker.log").read_text()


def test_the_same_folder_is_a_normal_rerun(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    dc = root / "deployment" / "docker"
    env = _env(tmp_path, FAKE_WORKDIRS=str(dc))
    r = _harness(root, "check_existing_install\necho REACHED\n", ["install"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHED" in r.stdout


def test_the_same_folder_through_a_symlink_is_still_the_same_folder(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    link = tmp_path / "link-to-root"
    link.symlink_to(root)
    env = _env(tmp_path, FAKE_WORKDIRS=str(link / "deployment" / "docker"))
    r = _harness(root, "check_existing_install\necho REACHED\n", ["install"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHED" in r.stdout


def test_no_existing_containers_is_a_fresh_install(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    r = _harness(root, "check_existing_install\necho REACHED\n", ["install"], _env(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHED" in r.stdout


def test_a_failed_label_query_is_named_not_skipped(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    env = _env(tmp_path, FAKE_PS_FAIL="1")
    r = _harness(root, "check_existing_install\necho REACHED\n", ["install"], env)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "REACHED" not in out
    assert "Cannot connect to the Docker daemon" in out


def test_install_never_starts_over_a_foreign_stack(tmp_path: Path) -> None:
    """Wired end to end through cmd_install: the refusal comes before install.py
    and before any compose call."""
    root = _tree(tmp_path)
    (root / "scripts" / "install.py").write_text(
        "import pathlib, os\npathlib.Path(os.environ['ENGINE_RAN']).write_text('ran')\n")
    other = _tree(tmp_path, "old/NetOps_Observability") / "deployment" / "docker"
    env = _env(tmp_path, FAKE_WORKDIRS=str(other), ENGINE_RAN=str(tmp_path / "engine-ran"))
    tail = "preflight() { check_existing_install; }\nwait_healthy() { return 0; }\ncmd_install\n"
    r = _harness(root, tail, ["install"], env)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert not (tmp_path / "engine-ran").exists(), "install.py ran over another folder's stack"
    assert " compose " not in " " + (tmp_path / "docker.log").read_text()
    assert not (root / "deployment" / "docker" / ".env").exists()


def test_preflight_checks_for_an_existing_install_before_the_ui_port() -> None:
    """A busy UI port held by the OTHER folder's stack used to be reported as a
    foreign process (S7). The ownership check must come first."""
    body = _src()[_src().index("preflight() {"):_src().index("\n# Release-signature check")]
    assert "check_existing_install" in body
    assert body.index("docker compose version") < body.index("check_existing_install") \
        < body.index('port_in_use "$UI_PORT"')


# ── purge: every .env sibling that holds secrets ────────────────────────────

ENV_SIBLINGS = [".env.snapshot", ".env.damaged", ".env.rotate.bak", ".env.plan.bak",
                ".env.upgrade-failed-20260915T101500Z"]


def test_purge_removes_every_env_sibling_that_holds_secrets(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    dc = root / "deployment" / "docker"
    (dc / ".env").write_text(f"ADMIN_INITIAL_PASSWORD={SENTINEL_PW}\n")
    for name in ENV_SIBLINGS:
        (dc / name).write_text(f"ADMIN_INITIAL_PASSWORD={SENTINEL_PW}\n")
    env = _env(tmp_path)
    r = subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"), "uninstall", "--purge"],
                       capture_output=True, text=True, timeout=120, env=env,
                       stdin=subprocess.DEVNULL, check=False)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    for name in ENV_SIBLINGS:
        assert not (dc / name).exists(), f"{name} (holds secrets) survived uninstall --purge"
    assert not (dc / ".env").exists()
    assert SENTINEL_PW not in out


def test_a_plain_uninstall_keeps_the_env_siblings(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    dc = root / "deployment" / "docker"
    (dc / ".env").write_text("BASE_PORT=8000\n")
    (dc / ".env.snapshot").write_text("BASE_PORT=8000\n")
    r = subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"), "uninstall"],
                       capture_output=True, text=True, timeout=120, env=_env(tmp_path),
                       stdin=subprocess.DEVNULL, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (dc / ".env.snapshot").exists() and (dc / ".env").exists()


# ── Q4: host hardening stays by design ──────────────────────────────────────

def test_uninstall_help_says_host_hardening_is_kept_by_design(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    r = subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"), "--help"],
                       capture_output=True, text=True, timeout=60, env=_env(tmp_path),
                       stdin=subprocess.DEVNULL, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    text = r.stdout
    assert re.search(r"(?is)uninstall.*host (preparation|hardening).*(kept|left in place).*by design", text), text
    assert "upgrade" in text and "cleanup-old-images" in text
    code = re.sub(r"^\s*#.*$", "", _src(), flags=re.MULTILINE)
    assert "--purge-host" not in code, "owner Q4: no --purge-host"
