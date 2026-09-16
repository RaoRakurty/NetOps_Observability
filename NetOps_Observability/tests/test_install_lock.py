# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Single-writer install lock, install.py side (FMEA §2 #12, §4.2).

Two installs at once (GUI + CLI, two wizard processes, a cron update.sh) race
on .env surgery and on compose. install.py now takes an exclusive flock on
deployment/docker/.install.lock for every mutating mode:

  * a second run refuses with exit 3 and NAMES the holder (pid, command, start);
  * a stale record whose pid is dead is taken over with a warning;
  * under install-correlix.sh (which holds `flock -n 9` and exports
    CORRELIX_INSTALL_LOCK_FD=9) install.py re-flocks THAT descriptor instead of
    opening the file — and never releases the shell's lock;
  * --help and argument errors take no lock; a finished run empties the record.

Real flock(2) on temp files; the subprocess cases run a COPY of install.py in a
temp tree (no docker, nothing in the repository is touched).
Run:  python3 -m pytest tests/test_install_lock.py -v
"""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install

SHELL_RECORD = "pid=4242\ncmd=install-correlix.sh install\nstarted_utc=2026-09-15T03:00:00Z\n"


def compose_dir(tmp_path: Path) -> Path:
    d = tmp_path / "deployment" / "docker"
    d.mkdir(parents=True)
    return d


def hold(path: Path, record: str = SHELL_RECORD) -> int:
    """Hold the lock the way install-correlix.sh does: an fd with LOCK_EX."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.ftruncate(fd, 0)
    os.pwrite(fd, record.encode(), 0)
    return fd


def lock_is_free(path: Path) -> bool:
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


# ── in-process ───────────────────────────────────────────────────────────────

def test_the_holder_records_itself_owner_only_and_clears_on_release(tmp_path):
    cd = compose_dir(tmp_path)
    lock = install.acquire_install_lock(cd, ["/opt/x/install.py", "--bundle", "secret?"],
                                        environ={})
    path = cd / ".install.lock"
    text = path.read_text()
    assert f"pid={os.getpid()}\n" in text
    assert "cmd=install.py --bundle\n" in text, "argv[0] basename + argv[1] only"
    assert "started_utc=20" in text and text.rstrip().endswith("Z")
    assert (path.stat().st_mode & 0o777) == 0o600
    assert not lock_is_free(path)
    lock.release()
    assert path.read_text() == "" and lock_is_free(path)


def test_a_second_install_refuses_with_exit_3_naming_the_holder(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    fd = hold(cd / ".install.lock")
    try:
        with pytest.raises(SystemExit) as exc:
            install.acquire_install_lock(cd, ["install.py"], environ={})
    finally:
        os.close(fd)
    assert exc.value.code == install.INSTALL_LOCK_BUSY_EXIT == 3
    err = capsys.readouterr().err
    assert "already running" in err and "pid 4242" in err
    assert "install-correlix.sh install" in err and "2026-09-15T03:00:00Z" in err


def test_a_stale_record_from_a_dead_pid_is_taken_over_with_a_warning(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    (cd / ".install.lock").write_text("pid=999999\ncmd=install.py\nstarted_utc=2026-09-14T01:00:00Z\n")
    lock = install.acquire_install_lock(cd, ["install.py"], environ={},
                                        pid_alive=lambda pid: False)
    err = capsys.readouterr().err
    assert "took over a stale install lock" in err and "pid 999999" in err
    assert f"pid={os.getpid()}" in (cd / ".install.lock").read_text()
    lock.release()


def test_a_live_but_unlocked_pid_is_called_a_reused_pid(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    (cd / ".install.lock").write_text("pid=1\ncmd=init\n")
    install.acquire_install_lock(cd, ["install.py"], environ={},
                                 pid_alive=lambda pid: True).release()
    assert "reused pid" in capsys.readouterr().err


def test_a_hostile_record_is_bounded_and_printable(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    fd = hold(cd / ".install.lock", "pid=7\ncmd=\x1b[2Jevil" + "A" * 5000 + "\n")
    try:
        with pytest.raises(SystemExit):
            install.acquire_install_lock(cd, ["install.py"], environ={})
    finally:
        os.close(fd)
    err = capsys.readouterr().err
    assert "\x1b" not in err and "A" * 201 not in err


def test_the_shells_inherited_descriptor_is_reflocked_not_reopened(tmp_path):
    cd = compose_dir(tmp_path)
    path = cd / ".install.lock"
    shell_fd = hold(path)
    try:
        lock = install.acquire_install_lock(
            cd, ["install.py"], environ={install.INSTALL_LOCK_FD_ENV: str(shell_fd)})
        assert lock.owned is False
        assert path.read_text() == SHELL_RECORD, "the shell's record is the shell's"
        lock.release()
        assert not lock_is_free(path), "install.py must never release the shell's lock"
    finally:
        os.close(shell_fd)
    assert lock_is_free(path)


@pytest.mark.parametrize("value", ["abc", "2", "-1", "99999999"])
def test_an_unusable_descriptor_number_falls_back_to_a_direct_lock(tmp_path, capsys, value):
    cd = compose_dir(tmp_path)
    lock = install.acquire_install_lock(cd, ["install.py"],
                                        environ={install.INSTALL_LOCK_FD_ENV: value})
    assert lock.owned is True
    assert f"ignoring {install.INSTALL_LOCK_FD_ENV}" in capsys.readouterr().err
    lock.release()


def test_a_descriptor_on_another_file_is_not_trusted_as_the_lock(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    (cd / ".install.lock").write_text("")
    other = os.open(tmp_path / "unrelated", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        lock = install.acquire_install_lock(
            cd, ["install.py"], environ={install.INSTALL_LOCK_FD_ENV: str(other)})
        assert lock.owned is True
        assert "is not" in capsys.readouterr().err
        lock.release()
    finally:
        os.close(other)


def test_a_closed_descriptor_is_not_trusted_as_the_lock(tmp_path, capsys):
    cd = compose_dir(tmp_path)
    fd = os.open(tmp_path / "gone", os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)
    lock = install.acquire_install_lock(cd, ["install.py"],
                                        environ={install.INSTALL_LOCK_FD_ENV: str(fd)})
    assert lock.owned is True and "not open in this process" in capsys.readouterr().err
    lock.release()


# ── the real script, in a temp tree ──────────────────────────────────────────

@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    shutil.copy2(SCRIPTS / "install.py", tmp_path / "scripts" / "install.py")
    compose_dir(tmp_path)
    return tmp_path


def run_install(tree: Path, *args: str, env: dict | None = None, pass_fds=()):
    full_env = {k: v for k, v in os.environ.items()
                if k not in (install.INSTALL_LOCK_FD_ENV, "CORRELIX_PROGRESS_JSON")}
    full_env.update(env or {})
    return subprocess.run([sys.executable, str(tree / "scripts" / "install.py"), *args],
                          capture_output=True, text=True, timeout=60, env=full_env,
                          pass_fds=pass_fds, check=False)


def test_help_takes_no_lock(tree):
    r = run_install(tree, "--help")
    assert r.returncode == 0
    assert not (tree / "deployment" / "docker" / ".install.lock").exists()


def test_a_mutating_mode_locks_and_releases_on_every_exit_path(tree):
    r = run_install(tree, "--replan")              # fails: no .env yet
    assert r.returncode == 1 and ".env not found" in r.stderr
    lock = tree / "deployment" / "docker" / ".install.lock"
    assert lock.exists() and lock.read_text() == "", "released and emptied on the fail path"
    assert lock_is_free(lock)


def test_a_concurrent_run_of_the_real_script_exits_3(tree):
    lock = tree / "deployment" / "docker" / ".install.lock"
    fd = hold(lock)
    try:
        r = run_install(tree, "--replan")
    finally:
        os.close(fd)
    assert r.returncode == 3, r.stderr
    assert "already running" in r.stderr and "pid 4242" in r.stderr
    assert lock.read_text() == SHELL_RECORD, "a refused run changes nothing"


def test_under_the_shells_lock_the_real_script_proceeds(tree):
    lock = tree / "deployment" / "docker" / ".install.lock"
    fd = hold(lock)
    try:
        os.set_inheritable(fd, True)
        r = run_install(tree, "--replan", env={install.INSTALL_LOCK_FD_ENV: str(fd)},
                        pass_fds=(fd,))
        still_held = not lock_is_free(lock)
    finally:
        os.close(fd)
    assert r.returncode == 1 and ".env not found" in r.stderr, "past the lock, not refused"
    assert still_held, "the child must not have released the shell's lock"
    assert lock.read_text() == SHELL_RECORD
