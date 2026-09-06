# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""rotate-tls-services.sh qualification-guard liveness check (ultra #21,
2026-09-01).

The defect this pins: the guard was a bare `pgrep -f 'scale-miniladder\\.py'`,
which matches ANY command line carrying the string — a `tail -f` on the
harness log, an editor, a grep, an agent shell quoting the name (the exact
false-match class scale-ab-driver.py's HARNESS_PROC_RE documents). Every
daily act sweep then "deferred" the restart class for a run that did not
exist — indefinitely, until a held cert crossed the WIRE_MIN_LEFT_H floor.

The fix ports the ab-driver's check: candidates from `pgrep -af`, narrowed
to "a python interpreter executing the harness file". pgrep rc>1 (pgrep
itself broken) refuses to guess: restart class deferred AND the sweep is
flagged DEGRADED.

Watchdog-suite style: the FULL script runs from a sandboxed copy (fake-tool
bindir prepended to its own explicit PATH line) against a fake `docker` that
plays a healthy hot-reload mesh, real minted certs on disk, and a scripted
`pgrep` whose output the tests drive.
"""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "rotate-tls-services.sh"

FAKE_DOCKER = r'''#!/bin/sh
# A healthy stack: every hot-reload leg succeeds, every wire endpoint serves
# the disk mint ($FAKE_WIRE_NOTAFTER, set to the minted cert's notAfter), the
# pdf profile (gotenberg) is not running, restarts succeed and come up healthy.
printf 'DOCKER %s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
  inspect) echo healthy; exit 0 ;;
  compose) ;;
  *) exit 0 ;;
esac
case "$*" in
  *"ps -q --status running gotenberg"*) exit 0 ;;
  *s_client*) printf 'notAfter=%s\n' "$FAKE_WIRE_NOTAFTER"; exit 0 ;;
  *valkey-cli*) cat >/dev/null; echo OK; exit 0 ;;
  *" ps -q "*) echo cid-test; exit 0 ;;
  *" restart "*) exit 0 ;;
esac
exit 0
'''

FAKE_PGREP = r'''#!/bin/sh
# Scripted `pgrep -af`: prints $FAKE_PGREP_LINES (rc 0) when non-empty,
# rc 1 (no match) when empty/unset, or fails outright with $FAKE_PGREP_RC.
if [ -n "${FAKE_PGREP_RC:-}" ]; then
    echo "pgrep: simulated failure" >&2
    exit "$FAKE_PGREP_RC"
fi
if [ -n "${FAKE_PGREP_LINES:-}" ] && [ -s "$FAKE_PGREP_LINES" ]; then
    cat "$FAKE_PGREP_LINES"
    exit 0
fi
exit 1
'''

# Command lines that merely MENTION the harness file — every one of these
# made the old bare `pgrep -f` defer the restart class (the #21 defect).
DECOY_LINES = (
    "1234 tail -f /var/tmp/scale-runs/scale-miniladder.py\n"
    "2345 vim scripts/scale-miniladder.py\n"
    "3456 grep -n cleanup scripts/scale-miniladder.py\n"
    "4567 bash -c pgrep -af scale-miniladder.py\n"
)
# What a REAL run looks like after `setsid nohup` execs (cron's included).
HARNESS_LINE = ("5678 /usr/bin/python3 /home/rao/Projects/NetOps_Observability/"
                "NetOps_Observability/scripts/scale-miniladder.py "
                "--devices 1000 --profile t-nominal\n")


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _sandboxed_copy(dest: Path, bindir: Path) -> None:
    """Prepend the fake-tool bindir to the script's OWN explicit PATH line
    (the sanctioned test seam — see test_watchdog_transitions)."""
    content = SCRIPT.read_text()
    marker = "PATH=/usr/local/bin:"
    assert marker in content, "rotate-tls-services.sh lost its explicit PATH line"
    dest.write_text(content.replace(marker, f"PATH={bindir}:/usr/local/bin:", 1))
    dest.chmod(0o755)


def _layout(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "docker", FAKE_DOCKER)
    _write_exec(bindir / "pgrep", FAKE_PGREP)

    compose = tmp_path / "deploy"
    compose.mkdir()
    (compose / "docker-compose.yml").write_text("services: {}\n")
    (compose / ".env").write_text("REDIS_PASSWORD=test-redis-pw\n")

    tls = tmp_path / "tls"
    key = tmp_path / "mint.key"
    crt = tmp_path / "mint.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days",
         "30", "-subj", "/CN=rotate-tls-test", "-keyout", str(key),
         "-out", str(crt)],
        check=True, capture_output=True, timeout=60)
    for svc in ("kafka", "postgres", "clickhouse", "redis", "vmauth"):
        d = tls / "services" / svc
        d.mkdir(parents=True)
        (d / f"{svc}.crt").write_bytes(crt.read_bytes())
    enddate = subprocess.run(
        ["openssl", "x509", "-in", str(crt), "-noout", "-enddate"],
        check=True, capture_output=True, text=True, timeout=30).stdout
    not_after = enddate.strip().split("=", 1)[1]

    script = tmp_path / "rotate-tls-services.sh"
    _sandboxed_copy(script, bindir)
    return script, compose, tls, not_after


def _run(tmp_path: Path, script: Path, compose: Path, tls: Path,
         not_after: str, run_name: str, **knobs):
    docker_log = tmp_path / f"docker.{run_name}.log"
    docker_log.write_text("")
    hb = tmp_path / f"{run_name}.heartbeat"
    env = os.environ.copy()
    env.update({
        "COMPOSE_DIR": str(compose),
        "TLS_DIR": str(tls),
        "HEARTBEAT": str(hb),
        "ROTATE_STATE": str(tmp_path / f"{run_name}.loaded"),
        "DOCKER_LOG": str(docker_log),
        "FAKE_WIRE_NOTAFTER": not_after,
    })
    env.update({k: str(v) for k, v in knobs.items()})
    r = subprocess.run(["bash", str(script)], env=env,
                       stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=300)
    heartbeat = hb.read_text() if hb.exists() else ""
    return r, docker_log.read_text(), heartbeat


def test_decoy_mentions_do_not_defer_restart_class(tmp_path):
    """THE #21 regression: a tail -f / editor / grep / self-quoting shell
    carrying 'scale-miniladder.py' is NOT a live run — the act sweep must
    proceed to the restart class instead of deferring forever."""
    script, compose, tls, not_after = _layout(tmp_path)
    lines = tmp_path / "pgrep.decoys"
    lines.write_text(DECOY_LINES)
    r, dlog, hb = _run(tmp_path, script, compose, tls, not_after, "decoys",
                       FAKE_PGREP_LINES=lines)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert "DEFER: live qualification/soak run" not in r.stderr, (
        f"decoy command lines deferred the sweep — the #21 defect:\n{r.stderr}")
    assert "mode=act" in hb, hb
    assert " restart " in dlog, (
        f"the restart class must actually run under decoys:\n{dlog}")


def test_real_harness_process_still_defers(tmp_path):
    """A python interpreter executing the harness file OWNS the stack: the
    hot-reload legs run, the restart class defers."""
    script, compose, tls, not_after = _layout(tmp_path)
    lines = tmp_path / "pgrep.live"
    lines.write_text(DECOY_LINES + HARNESS_LINE)
    r, dlog, hb = _run(tmp_path, script, compose, tls, not_after, "live",
                       FAKE_PGREP_LINES=lines)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert "DEFER: live qualification/soak run" in r.stderr, r.stderr
    assert "mode=deferred" in hb, hb
    assert " restart " not in dlog, (
        f"a live run owns the stack — no restart may land:\n{dlog}")
    # The hot-reload legs are evidence-safe and must still have run.
    assert "valkey-cli" in dlog, dlog


def test_no_processes_at_all_runs_the_act_sweep(tmp_path):
    script, compose, tls, not_after = _layout(tmp_path)
    r, dlog, hb = _run(tmp_path, script, compose, tls, not_after, "idle")
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert "mode=act" in hb, hb
    assert " restart " in dlog


def test_pgrep_failure_refuses_to_guess_loudly(tmp_path):
    """pgrep rc>1: the sweep cannot prove the host is idle — restart class
    deferred AND the run is flagged DEGRADED (16.1: refusal must be loud)."""
    script, compose, tls, not_after = _layout(tmp_path)
    r, dlog, hb = _run(tmp_path, script, compose, tls, not_after, "broken",
                       FAKE_PGREP_RC=3)
    assert r.returncode == 1, (
        f"a blind guard must exit non-zero:\n{r.stderr}\nstdout:\n{r.stdout}")
    assert "cannot prove the host is idle" in r.stderr, r.stderr
    assert "mode=deferred" in hb and "status=DEGRADED" in hb, hb
    assert " restart " not in dlog, dlog
