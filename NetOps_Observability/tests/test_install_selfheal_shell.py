# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""install-correlix.sh self-healing, shell side (FMEA 2026-09-15).

docs/design/INSTALLER_SELF_HEALING_FMEA_2026-09-15.md rows pinned here:

  row 14 / S3  — the install log is trustworthy: install.py runs unbuffered so
                 lines keep their real order, and every log line carries a UTC
                 timestamp, except the `@CX@ {json}` markers, which stay
                 byte-identical at line start (the wizard parses them).
  row 6 / S2   — the generated admin password never reaches the tee'd log. The
                 operator still gets it: on a terminal only (never the log),
                 plus a 0600 credential file whose path is printed.
                 `uninstall --purge` removes the logs and that file (X3).
  row 5 / §4.7 — `wait_healthy` means STABLE, not sampled: a RestartCount
                 delta, a StartedAt inside the window, an unhealthy end state,
                 or a one-shot `*-init` that did not exit 0 fails the gate and
                 names the service with its (redacted) last log lines.
  row 12 / §4.2 — single-writer lock: `flock -n` on
                 deployment/docker/.install.lock for every state-changing
                 command. A refusal names the holder; a record left by a dead
                 holder is taken over with a warning; install.py inherits the
                 locked fd as CORRELIX_INSTALL_LOCK_FD=9.
  S9 / S11     — the split-archive join and the source extract go through a
                 `.partial` and a rename; a leftover `.partial` is redone,
                 never trusted, and a truncated joined archive is rebuilt once.

Everything runs the REAL script with docker/curl/sleep faked on PATH inside
tmp_path. Nothing touches the host, docker, or the network.

Run:  python3 -m pytest tests/test_install_selfheal_shell.py -v
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pty
import re
import select
import stat
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install-correlix.sh"

SENTINEL_PW = "Sentinel-Pw-7f3a9QZ"
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ")


# ── harness ─────────────────────────────────────────────────────────────────

def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


# The script PREPENDS the system directories to PATH (cron-safety, §16.2), which
# would let the real /usr/bin/docker beat the fake one. The copy under test gets
# exactly that one line neutralised — asserted, so the swap cannot silently
# no-op and let a test reach the host's docker.
_PATH_LINE = 'export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"'


def _fakes_win(src: str) -> str:
    assert src.count(_PATH_LINE) == 1, "install-correlix.sh PATH line changed — update the harness"
    return src.replace(_PATH_LINE, 'export PATH="${PATH:?test harness sets PATH}"')


def _script_without_dispatch() -> str:
    """The shipped script with its final `case "$CMD"` dispatch removed, so a
    harness can override a stage (preflight, wait_healthy) and call one
    command function directly. Every definition stays verbatim."""
    src = _fakes_win(_src())
    cut = src.rindex('\ncase "$CMD" in\n')
    return src[:cut] + "\n"


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _tree(tmp_path: Path, *, env: bool = True) -> Path:
    """A fake SOURCE checkout: scripts/ + deployment/docker/docker-compose.yml."""
    root = tmp_path / "root"
    (root / "scripts").mkdir(parents=True)
    dc = root / "deployment" / "docker"
    dc.mkdir(parents=True)
    (dc / "docker-compose.yml").write_text("services: {}\n")
    if env:
        (dc / ".env").write_text(
            "ADMIN_USERNAME=admin\n"
            f"ADMIN_INITIAL_PASSWORD={SENTINEL_PW}\n"
            "BASE_PORT=8000\n"
            "COMPOSE_PROFILES=embedded-bus,prober\n")
    dst = root / "scripts" / "install-correlix.sh"
    dst.write_text(_fakes_win(_src()))
    dst.chmod(0o755)
    return root


FAKE_DOCKER_RECORDING = """#!/bin/bash
printf '%s\\n' "$*" >> "$DOCKER_LOG"
if [ -n "${LOCK_SNAPSHOT:-}" ] && [ "$1" = compose ]; then
  cat "$LOCK_FILE" >> "$LOCK_SNAPSHOT" 2>/dev/null
fi
exit 0
"""


def _bin(tmp_path: Path) -> Path:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    _write_exec(b / "docker", FAKE_DOCKER_RECORDING)
    _write_exec(b / "curl", "#!/bin/sh\nexit 0\n")
    return b


def _env(tmp_path: Path, bindir: Path, **extra: str) -> dict:
    env = {
        "PATH": f"{bindir}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "DOCKER_LOG": str(tmp_path / "docker.log"),
        "CORRELIX_NO_SIZING": "1",
    }
    env.update(extra)
    return env


def _run_real(root: Path, args: list[str], env: dict, timeout: int = 120):
    return subprocess.run(["bash", str(root / "scripts" / "install-correlix.sh"), *args],
                          capture_output=True, text=True, timeout=timeout, env=env,
                          stdin=subprocess.DEVNULL, check=False)


def _run_harness(root: Path, tail: str, args: list[str], env: dict, timeout: int = 120):
    h = root / "scripts" / "harness.sh"
    h.write_text(_script_without_dispatch() + tail)
    return subprocess.run(["bash", str(h), *args], capture_output=True, text=True,
                          timeout=timeout, env=env, stdin=subprocess.DEVNULL, check=False)


def _logs(root: Path) -> list[Path]:
    return sorted((root / "scripts").glob("correlix-install-*.log"))


FAKE_INSTALL_PY = r"""
import fcntl, json, os, sys
print("engine: first stdout line")
sys.stderr.write("engine: stderr line\n")
sys.stderr.flush()
print("engine: second stdout line")
print('@CX@ {"kind":"stage","id":"env","title":"Environment generated","status":"ok"}')
report = {"fd_env": os.environ.get("CORRELIX_INSTALL_LOCK_FD")}
lock = os.environ.get("EXPECT_LOCK_FILE")
if lock:
    try:
        report["same_inode"] = os.fstat(9).st_ino == os.stat(lock).st_ino
        fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report["inherited_flock_ok"] = True
    except OSError as e:
        report["inherited_flock_ok"] = False
        report["err"] = str(e)
    other = open(lock, "a+")
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report["independent_open_locked"] = True
    except BlockingIOError:
        report["independent_open_locked"] = False
    other.close()
with open(os.environ["ENGINE_REPORT"], "w") as f:
    json.dump(report, f)
"""

INSTALL_TAIL = """
preflight() { ok "preflight stubbed by the test harness"; }
wait_healthy() { return 0; }
verify_admin_login() { :; }
cmd_install
"""


def _install_run(tmp_path: Path, **extra_env: str):
    root = _tree(tmp_path)
    (root / "scripts" / "install.py").write_text(FAKE_INSTALL_PY)
    bindir = _bin(tmp_path)
    env = _env(tmp_path, bindir, ENGINE_REPORT=str(tmp_path / "engine.json"),
               EXPECT_LOCK_FILE=str(root / "deployment" / "docker" / ".install.lock"),
               **extra_env)
    r = _run_harness(root, INSTALL_TAIL, ["install"], env)
    return root, r


# ── row 14: trustworthy log ─────────────────────────────────────────────────

def test_install_py_is_always_run_unbuffered() -> None:
    code = re.sub(r"^\s*#.*$", "", _src(), flags=re.MULTILINE)
    calls = re.findall(r"python3[^\n]*scripts/install\.py", code)
    assert calls, "no install.py invocation found"
    for c in calls:
        assert "python3 -u " in c, (
            f"install.py launched buffered: {c!r} — through tee its stdout is "
            "block-buffered and the log's line order is scrambled (FMEA row 14)")
    assert "PYTHONUNBUFFERED=1" in code


def test_log_lines_keep_their_real_order(tmp_path: Path) -> None:
    root, r = _install_run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    [log] = _logs(root)
    text = log.read_text()
    a = text.index("engine: first stdout line")
    b = text.index("engine: stderr line")
    c = text.index("engine: second stdout line")
    assert a < b < c, (
        "install.py's stdout arrived out of order relative to its stderr — "
        f"python is still block-buffered through tee:\n{text}")


def test_every_log_line_is_utc_timestamped_except_the_markers(tmp_path: Path) -> None:
    root, r = _install_run(tmp_path, CORRELIX_PROGRESS_JSON="1")
    assert r.returncode == 0, r.stdout + r.stderr
    [log] = _logs(root)
    lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
    assert lines
    markers = [ln for ln in lines if ln.startswith("@CX@ ")]
    assert markers, "the @CX@ markers must still be in the log"
    for ln in markers:
        json.loads(ln[len("@CX@ "):])  # byte-identical, still parseable
    stamped = [ln for ln in lines if not ln.startswith("@CX@ ")]
    bad = [ln for ln in stamped if not TS_RE.match(ln)]
    assert not bad, f"log lines without a UTC timestamp prefix: {bad[:5]}"


def test_stdout_markers_stay_byte_identical_for_the_wizard(tmp_path: Path) -> None:
    """The wizard reads the child's STDOUT, not the log: markers there must
    begin at column 0 exactly as `strings.CutPrefix(line, "@CX@ ")` expects,
    and nothing on stdout grows a timestamp the wizard would show."""
    _root, r = _install_run(tmp_path, CORRELIX_PROGRESS_JSON="1")
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout.splitlines()
    assert '@CX@ {"kind":"stage","id":"env","title":"Environment generated","status":"ok"}' in out
    assert any(ln.startswith('@CX@ {"kind":"result","status":"ok"') for ln in out), r.stdout
    assert not any(TS_RE.match(ln) for ln in out), "stdout must not be timestamped"


def test_the_install_log_is_private(tmp_path: Path) -> None:
    root, r = _install_run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    [log] = _logs(root)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600, oct(log.stat().st_mode)


# ── row 6: no admin password in the log ─────────────────────────────────────

@pytest.mark.parametrize("gui", [False, True])
def test_the_admin_password_never_reaches_the_log(tmp_path: Path, gui: bool) -> None:
    extra = {"CORRELIX_PROGRESS_JSON": "1"} if gui else {}
    root, r = _install_run(tmp_path, **extra)
    assert r.returncode == 0, r.stdout + r.stderr
    [log] = _logs(root)
    assert SENTINEL_PW not in log.read_text(), "admin password written to the install log"
    assert SENTINEL_PW not in r.stdout + r.stderr, (
        "not a terminal (pipe / wizard): the password must not be printed; the "
        "wizard reads it from .env and a human gets the credential file")
    cred = root / "data" / "initial-admin-credential.txt"
    assert cred.is_file(), "the operator must still receive the credential"
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
    assert SENTINEL_PW in cred.read_text()
    assert str(cred) in r.stdout, "the credential file's path must be printed"
    # The wizard's banner-scrape fallback (adminRE `^\s*Password:\s+(\S+)`)
    # must not capture a non-password word from the pointer line.
    assert not re.search(r"(?m)^\s*Password:\s+\S+", r.stdout)


def _run_on_pty(argv: list[str], env: dict, timeout: float = 120) -> str:
    master, slave = pty.openpty()
    p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                         close_fds=True)
    os.close(slave)
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        elif p.poll() is not None:
            # drain whatever is left, then stop
            try:
                while True:
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if not ready:
                        break
                    data = os.read(master, 65536)
                    if not data:
                        break
                    chunks.append(data)
            except OSError:
                pass
            break
    p.wait(timeout=10)
    os.close(master)
    return b"".join(chunks).decode(errors="replace")


def test_on_a_terminal_the_password_is_shown_but_not_logged(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "scripts" / "install.py").write_text(FAKE_INSTALL_PY)
    bindir = _bin(tmp_path)
    env = _env(tmp_path, bindir, ENGINE_REPORT=str(tmp_path / "engine.json"), TERM="dumb")
    h = root / "scripts" / "harness.sh"
    h.write_text(_script_without_dispatch() + INSTALL_TAIL)
    term = _run_on_pty(["bash", str(h), "install"], env)
    assert SENTINEL_PW in term, "an operator at a terminal must see the password:\n" + term
    [log] = _logs(root)
    assert SENTINEL_PW not in log.read_text()


# ── row 12: single-writer lock ──────────────────────────────────────────────

def _hold_lock(lock: Path, record: str):
    lock.parent.mkdir(parents=True, exist_ok=True)
    # Returned open on purpose: the flock lives exactly as long as the handle,
    # and the caller closes it in a finally once the refused run has exited.
    fh = open(lock, "a+")  # noqa: SIM115
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fh.seek(0)
    fh.truncate()
    fh.write(record)
    fh.flush()
    return fh


@pytest.mark.parametrize("args", [
    ["install"], ["uninstall"], ["enable", "sso"], ["disable", "sso"], ["reset-demo-data"],
])
def test_a_second_writer_is_refused_and_names_the_holder(tmp_path: Path, args) -> None:
    root = _tree(tmp_path)
    lock = root / "deployment" / "docker" / ".install.lock"
    started = "2026-09-15T03:11:07Z"
    fh = _hold_lock(lock, f"pid={os.getpid()}\ncommand=install\nstarted_utc={started}\n")
    try:
        bindir = _bin(tmp_path)
        r = _run_real(root, args, _env(tmp_path, bindir))
    finally:
        fh.close()
    out = r.stdout + r.stderr
    assert r.returncode == 3, f"rc={r.returncode}\n{out}"
    assert str(os.getpid()) in out and started in out and "install" in out, out
    assert not (tmp_path / "docker.log").exists(), (
        "the refused command touched docker anyway:\n"
        + (tmp_path / "docker.log").read_text())


def test_a_record_left_by_a_dead_holder_is_taken_over_with_a_warning(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    lock = root / "deployment" / "docker" / ".install.lock"
    dead = subprocess.Popen(["true"])
    dead.wait()
    lock.write_text(f"pid={dead.pid}\ncommand=install\nstarted_utc=2026-09-14T00:00:00Z\n")
    bindir = _bin(tmp_path)
    snap = tmp_path / "lock-during.txt"
    env = _env(tmp_path, bindir, LOCK_SNAPSHOT=str(snap), LOCK_FILE=str(lock))
    r = _run_real(root, ["uninstall"], env)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert str(dead.pid) in out and re.search(r"(?i)stale|no longer running", out), out
    during = snap.read_text()
    assert "command=uninstall" in during and "started_utc=" in during, during
    assert f"pid={dead.pid}" not in during
    # released on exit: an independent flock succeeds now
    with open(lock, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_install_py_inherits_the_held_lock_on_fd_9(tmp_path: Path) -> None:
    _root, r = _install_run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads((tmp_path / "engine.json").read_text())
    assert rep["fd_env"] == "9", rep
    assert rep["same_inode"] is True, rep
    assert rep["inherited_flock_ok"] is True, rep
    assert rep["independent_open_locked"] is False, (
        "the lock was not actually held while install.py ran")


# ── row 5 / §4.7: stability gate ────────────────────────────────────────────

# The fake docker answers from two snapshots: before the stability window's
# sleep (inspect0) and after it (inspect1). The fake `sleep` records its
# argument and advances the phase, so no real time passes.
FAKE_DOCKER_STATEFUL = r"""#!/bin/bash
S="$FAKE_STATE"
phase=0
[ -s "$S/sleeps" ] && phase=1
cur="$S/inspect$phase"
case "$1" in
  compose)
    shift
    case "$*" in
      *"ps -aq"*|*"ps -q"*) cut -d'|' -f1 "$cur" ;;
      *"{{.Service}}|{{.State}}|{{.Health}}"*)
          awk -F'|' '{h=$6; if (h=="none") h=""; print $2 "|" $5 "|" h}' "$cur" ;;
      *"{{.Service}}"*) cut -d'|' -f2 "$cur" ;;
      *) : ;;
    esac ;;
  inspect) cat "$cur" ;;
  logs)
    for a in "$@"; do last="$a"; done
    grep "^$last " "$S/logs" 2>/dev/null | cut -d' ' -f2- ;;
esac
exit 0
"""

FAKE_SLEEP = "#!/bin/sh\necho \"$1\" >> \"$FAKE_STATE/sleeps\"\nexit 0\n"

STABLE = [
    "c-api|api|0|2026-09-15T03:00:00Z|running|none|0",
    "c-pg|postgres|0|2026-09-15T03:00:00Z|running|healthy|0",
    "c-kc|keycloak|2|2026-09-15T03:00:00Z|running|none|0",
    "c-kinit|kafka-init|0|2026-09-15T03:00:00Z|exited|none|0",
]


def _gate(tmp_path: Path, before: list[str], after: list[str], logs: str = "",
          **extra_env: str):
    root = _tree(tmp_path)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER_STATEFUL)
    _write_exec(bindir / "sleep", FAKE_SLEEP)
    _write_exec(bindir / "curl", "#!/bin/sh\nexit 0\n")
    state = tmp_path / "state"
    state.mkdir()
    (state / "inspect0").write_text("\n".join(before) + "\n")
    (state / "inspect1").write_text("\n".join(after) + "\n")
    (state / "logs").write_text(logs)
    env = _env(tmp_path, bindir, FAKE_STATE=str(state), **extra_env)
    tail = "\nif wait_healthy; then echo GATE=PASS; else echo GATE=FAIL; fi\n"
    r = _run_harness(root, tail, [], env, timeout=60)
    sleeps = (state / "sleeps").read_text().split() if (state / "sleeps").exists() else []
    return r, sleeps


def test_a_stable_stack_passes_the_gate(tmp_path: Path) -> None:
    r, sleeps = _gate(tmp_path, STABLE, STABLE)
    assert "GATE=PASS" in r.stdout, r.stdout + r.stderr
    assert "60" in sleeps, f"default window is 60 s, slept {sleeps}"


def test_a_crash_looping_service_fails_the_gate_and_is_named(tmp_path: Path) -> None:
    after = list(STABLE)
    after[2] = "c-kc|keycloak|5|2026-09-15T03:00:50Z|running|none|0"
    logs = ("c-kc FATAL: database \"keycloak\" does not exist\n"
            "c-kc connecting with password=hunter2-secret-value\n"
            "c-kc Authorization: Bearer abc.def.ghi\n")
    r, _ = _gate(tmp_path, STABLE, after, logs)
    out = r.stdout + r.stderr
    assert "GATE=FAIL" in out, out
    assert "keycloak" in out and re.search(r"restart", out, re.IGNORECASE), out
    assert 'database "keycloak" does not exist' in out, "last log lines must be shown"
    assert "hunter2-secret-value" not in out and "abc.def.ghi" not in out, (
        "log lines that look like credentials must be redacted")


def test_a_restart_that_reset_the_counter_is_still_caught(tmp_path: Path) -> None:
    """A recreated container keeps RestartCount 0 but its StartedAt moves
    inside the window — sampled State would read `running` both times."""
    after = list(STABLE)
    after[0] = "c-api|api|0|2026-09-15T03:00:59Z|running|none|0"
    r, _ = _gate(tmp_path, STABLE, after)
    out = r.stdout + r.stderr
    assert "GATE=FAIL" in out and "api" in out, out


def test_unhealthy_at_the_end_of_the_window_fails(tmp_path: Path) -> None:
    after = list(STABLE)
    after[1] = "c-pg|postgres|0|2026-09-15T03:00:00Z|running|unhealthy|0"
    r, _ = _gate(tmp_path, STABLE, after)
    out = r.stdout + r.stderr
    assert "GATE=FAIL" in out and "postgres" in out and "unhealthy" in out, out


def test_a_one_shot_that_failed_fails_the_gate(tmp_path: Path) -> None:
    bad = list(STABLE)
    bad[3] = "c-kinit|kafka-init|0|2026-09-15T03:00:00Z|exited|none|1"
    r, _ = _gate(tmp_path, bad, bad)
    out = r.stdout + r.stderr
    assert "GATE=FAIL" in out and "kafka-init" in out, out


@pytest.mark.parametrize("value,expected", [("15", "15"), ("100000", "900"),
                                             ("3", "10"), ("soon", "60")])
def test_the_window_is_env_tunable_and_bounded(tmp_path: Path, value, expected) -> None:
    r, sleeps = _gate(tmp_path, STABLE, STABLE, CORRELIX_STABILITY_WINDOW_S=value)
    assert "GATE=PASS" in r.stdout, r.stdout + r.stderr
    assert expected in sleeps, f"window {value!r} → slept {sleeps}, want {expected}"


# ── S9 / S11: atomic join and extract ───────────────────────────────────────

def _bundle(tmp_path: Path, *, parts: bool = True) -> tuple[Path, bytes]:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    payload = os.urandom(300_000)
    name = "correlix-images-core-9.9.9.tar.zst"
    if parts:
        (bundle / f"{name}.part00").write_bytes(payload[:150_000])
        (bundle / f"{name}.part01").write_bytes(payload[150_000:])
    src = tmp_path / "srctree" / "NetOps_Observability" / "deployment" / "docker"
    src.mkdir(parents=True)
    (src / "docker-compose.yml").write_text("services: {}\n")
    (src.parent.parent / "MARKER").write_text("complete\n")
    tgz = bundle / "correlix-source-9.9.9.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(tmp_path / "srctree" / "NetOps_Observability", arcname="NetOps_Observability")
    sums = (f"{hashlib.sha256(payload).hexdigest()}  ./{name}\n"
            f"{hashlib.sha256(tgz.read_bytes()).hexdigest()}  ./{tgz.name}\n")
    (bundle / "SHA256SUMS").write_text(sums)
    return bundle, payload


def _verify(tmp_path: Path, bundle: Path, fake: dict[str, str] | None = None):
    tree = tmp_path / "harness-tree"
    if not tree.exists():
        tree.mkdir()
        (tree / "scripts").mkdir()
        (tree / "deployment" / "docker").mkdir(parents=True)
        (tree / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    bindir = tmp_path / "vbin"
    if bindir.exists():
        for f in bindir.iterdir():
            f.unlink()
    else:
        bindir.mkdir()
    for name, body in (fake or {}).items():
        _write_exec(bindir / name, body)
    tail = (f'\nBUNDLE_DIR="{bundle}"\nROOT="{bundle}/NetOps_Observability"\n'
            'verify_bundle\necho VERIFY=DONE\n')
    env = {"PATH": f"{bindir}:/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path)}
    return _run_harness(tree, tail, [], env, timeout=60)


JOINED = "correlix-images-core-9.9.9.tar.zst"


def test_a_leftover_partial_join_is_redone_not_trusted(tmp_path: Path) -> None:
    bundle, payload = _bundle(tmp_path)
    (bundle / f"{JOINED}.partial").write_bytes(b"garbage from an interrupted run")
    r = _verify(tmp_path, bundle)
    assert "VERIFY=DONE" in r.stdout, r.stdout + r.stderr
    assert (bundle / JOINED).read_bytes() == payload
    assert not (bundle / f"{JOINED}.partial").exists()


def test_an_interrupted_join_leaves_no_joined_archive_and_a_rerun_heals(tmp_path: Path) -> None:
    bundle, payload = _bundle(tmp_path)
    # A `cat` that dies half-way (disk full, SIGKILL): writes some bytes, fails.
    half_cat = "#!/bin/sh\nhead -c 1000 \"$1\"\nexit 1\n"
    r1 = _verify(tmp_path, bundle, {"cat": half_cat})
    assert "VERIFY=DONE" not in r1.stdout, r1.stdout + r1.stderr
    assert not (bundle / JOINED).exists(), (
        "a truncated joined archive under the final name is trusted by every re-run")
    r2 = _verify(tmp_path, bundle)
    assert "VERIFY=DONE" in r2.stdout, r2.stdout + r2.stderr
    assert (bundle / JOINED).read_bytes() == payload


def test_a_truncated_joined_archive_from_an_older_run_is_rebuilt_once(tmp_path: Path) -> None:
    bundle, payload = _bundle(tmp_path)
    (bundle / JOINED).write_bytes(payload[:1000])
    r = _verify(tmp_path, bundle)
    assert "VERIFY=DONE" in r.stdout, r.stdout + r.stderr
    assert (bundle / JOINED).read_bytes() == payload


def test_a_leftover_partial_extract_is_redone(tmp_path: Path) -> None:
    bundle, _ = _bundle(tmp_path, parts=False)
    stale = bundle / "NetOps_Observability.partial" / "NetOps_Observability"
    stale.mkdir(parents=True)
    (stale / "half-written").write_text("x")
    r = _verify(tmp_path, bundle)
    assert "VERIFY=DONE" in r.stdout, r.stdout + r.stderr
    root = bundle / "NetOps_Observability"
    assert (root / "MARKER").read_text() == "complete\n"
    assert (root / "deployment" / "docker" / "docker-compose.yml").is_file()
    assert not (root / "half-written").exists()
    assert not (bundle / "NetOps_Observability.partial").exists()


def test_an_interrupted_extract_is_not_mistaken_for_a_tree(tmp_path: Path) -> None:
    bundle, _ = _bundle(tmp_path, parts=False)
    # A tar that creates part of the tree and then fails (ENOSPC, SIGKILL).
    broken_tar = """#!/bin/bash
dest=.
while [ $# -gt 0 ]; do case "$1" in -C) dest="$2"; shift 2 ;; *) shift ;; esac; done
mkdir -p "$dest/NetOps_Observability/deployment"
echo "tar: write error: No space left on device" >&2
exit 2
"""
    r1 = _verify(tmp_path, bundle, {"tar": broken_tar})
    assert "VERIFY=DONE" not in r1.stdout, r1.stdout + r1.stderr
    assert not (bundle / "NetOps_Observability").exists(), (
        "a half-extracted tree under the final name makes every re-run skip extraction")
    r2 = _verify(tmp_path, bundle)
    assert "VERIFY=DONE" in r2.stdout, r2.stdout + r2.stderr
    assert (bundle / "NetOps_Observability" / "MARKER").is_file()


# ── X3: purge removes the logs and the credential file ─────────────────────

WIZARD_FILES = ["correlix-setup-install-20260915-025100.log",
                "correlix-setup-install.job.json",
                "correlix-setup-install.lock"]


def test_purge_removes_install_logs_and_the_credential_file(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    logs = [root / "scripts" / "correlix-install-20260915-025100.log",
            root / "scripts" / "correlix-install-20260915-031500.log"]
    logs += [root / "scripts" / name for name in WIZARD_FILES]
    for p in logs:
        p.write_text(f"Password: {SENTINEL_PW}\n")
    cred = root / "data" / "initial-admin-credential.txt"
    cred.parent.mkdir(parents=True)
    cred.write_text(f"password={SENTINEL_PW}\n")
    bindir = _bin(tmp_path)
    r = _run_real(root, ["uninstall", "--purge"], _env(tmp_path, bindir))
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    for p in logs:
        assert not p.exists(), f"{p.name} survived the purge"
    assert not cred.exists()
    assert "correlix-install-" in out, "the purge must say it removed the install logs"


def test_purge_leaves_a_running_wizards_lock_and_job_file_and_names_them(tmp_path: Path) -> None:
    """Unlinking a lock file someone still holds lets the next opener lock a
    fresh inode — two wizards each believing they are alone. The transcript
    still goes; the held lock and the job state stay, named with the command."""
    root = _tree(tmp_path)
    scripts = root / "scripts"
    for name in WIZARD_FILES:
        (scripts / name).write_text("x\n")
    fh = open(scripts / "correlix-setup-install.lock", "a+")  # noqa: SIM115 — held across the run
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        bindir = _bin(tmp_path)
        r = _run_real(root, ["uninstall", "--purge"], _env(tmp_path, bindir))
    finally:
        fh.close()
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert not (scripts / WIZARD_FILES[0]).exists(), "the wizard transcript must still be purged"
    assert (scripts / "correlix-setup-install.lock").exists()
    assert (scripts / "correlix-setup-install.job.json").exists()
    assert "still running" in out and "correlix-setup-install.lock" in out, out


def test_a_plain_uninstall_keeps_the_logs(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    log = root / "scripts" / "correlix-install-20260915-025100.log"
    log.write_text("kept\n")
    bindir = _bin(tmp_path)
    r = _run_real(root, ["uninstall"], _env(tmp_path, bindir))
    assert r.returncode == 0, r.stdout + r.stderr
    assert log.exists()
