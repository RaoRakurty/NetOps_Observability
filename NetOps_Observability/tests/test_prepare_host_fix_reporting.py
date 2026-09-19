# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""prepare-host.sh reports what a FIX actually did (FMEA 2026-09-15, P3).

`systemctl enable --now systemd-timesyncd 2>/dev/null || true; fixd "…"` printed
FIXED whether or not the clock was ever going to be disciplined — the §16.1
swallow, in the one step whose silent failure is hardest to see later: a host
whose clock drifts fails TLS handshakes, expires tokens early and correlates
events into the wrong window, long after the install said it was fine. The
unattended-upgrades sibling was fixed on 2026-09-15 (217e3ab4); this pins the
same shape for time sync, and a static guard so no third step reintroduces it.

The time-sync step runs FOR REAL with fake `timedatectl` / `systemctl` binaries
on PATH inside tmp_path. Nothing touches the host clock or systemd.

Run:  python3 -m pytest tests/test_prepare_host_fix_reporting.py -v
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PREP = ROOT / "scripts" / "prepare-host.sh"

STEP_BEGIN = "# ---------- 3) time sync"
STEP_END = "# ---------- 4) docker daemon"


def _step() -> str:
    src = PREP.read_text(encoding="utf-8")
    assert STEP_BEGIN in src and STEP_END in src, (
        "prepare-host.sh's time-sync step is no longer delimited by its section "
        "comments — update this harness rather than dropping the coverage")
    return src[src.index(STEP_BEGIN):src.index(STEP_END)]


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# The reporters prepare-host.sh gives every step, reduced to greppable markers
# plus the two counters the script's exit status is built from.
HARNESS_HEAD = """set -euo pipefail
FIXES=0
FAILED=0
pass(){ printf 'PASS|%s\\n' "$1"; }
fixd(){ printf 'FIXED|%s\\n' "$1"; }
need(){ printf 'FIX|%s\\n' "$1"; FIXES=$((FIXES+1)); }
fixfail(){ printf 'FIXFAILED|%s\\n' "$1"; FAILED=$((FAILED+1)); }
"""

HARNESS_TAIL = """
printf 'COUNTERS|%s|%s\\n' "$FIXES" "$FAILED"
"""


def _run_step(tmp_path: Path, *, synced: bool, check: int,
              systemctl_rc: int = 0, systemctl_err: str = "") -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "timedatectl",
                "#!/bin/sh\n"
                f'printf \'%s\\n\' "{"yes" if synced else "no"}"\n')
    _write_exec(bindir / "systemctl",
                "#!/bin/sh\n"
                f'printf \'%s\\n\' "$*" >> "{tmp_path}/systemctl.log"\n'
                f'printf \'%s\\n\' "{systemctl_err}" >&2\n'
                f"exit {systemctl_rc}\n")
    # The PATH has to carry /usr/bin for real coreutils, and that is also where
    # the developer's (and the CI runner's) live docker sits. The fakes go
    # FIRST and the probe below proves they won before the step runs:
    # prepare-host.sh's other steps install and start a container runtime, so a
    # harness that let a real binary through would be editing this host.
    _write_exec(bindir / "docker",
                "#!/bin/sh\n"
                "printf 'fake docker: a test must never reach a container runtime: "
                "%s\\n' \"$*\" >&2\n"
                "exit 97\n")
    script = tmp_path / "step.sh"
    script.write_text(HARNESS_HEAD + f"CHECK={check}\n" + _step() + HARNESS_TAIL)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    probe = subprocess.run(
        ["bash", "-c", "command -v timedatectl; command -v systemctl; command -v docker"],
        env=env, capture_output=True, text=True, timeout=10, check=False)
    assert probe.stdout.split() == [str(bindir / "timedatectl"), str(bindir / "systemctl"),
                                    str(bindir / "docker")], \
        ("a test could reach the host's real timedatectl/systemctl/docker — refusing to run:\n"
         + probe.stdout)
    return subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=60,
        env=env, stdin=subprocess.DEVNULL, check=False)


def _lines(r: subprocess.CompletedProcess) -> list[str]:
    return [ln for ln in r.stdout.splitlines() if "|" in ln]


def test_a_synchronised_clock_passes_and_touches_nothing(tmp_path: Path) -> None:
    r = _run_step(tmp_path, synced=True, check=0)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _lines(r)[0].startswith("PASS|"), r.stdout
    assert not (tmp_path / "systemctl.log").exists(), \
        "a host whose clock is already disciplined must not be reconfigured"


def test_check_only_reports_the_item_without_fixing_it(tmp_path: Path) -> None:
    r = _run_step(tmp_path, synced=False, check=1)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _lines(r)[0].startswith("FIX|"), r.stdout
    assert "COUNTERS|1|0" in r.stdout
    assert not (tmp_path / "systemctl.log").exists(), "--check must not change the host"


def test_a_successful_enable_is_reported_as_fixed(tmp_path: Path) -> None:
    r = _run_step(tmp_path, synced=False, check=0)
    assert r.returncode == 0, r.stdout + r.stderr
    line = _lines(r)[0]
    assert line.startswith("FIXED|"), r.stdout
    assert "timedatectl" in line, "the FIXED line must say how to verify the result"
    assert "COUNTERS|0|0" in r.stdout
    assert "enable --now systemd-timesyncd" in (tmp_path / "systemctl.log").read_text()


def test_a_failed_enable_is_reported_as_a_failure_with_the_command_to_run(tmp_path: Path) -> None:
    """The P3 defect: this used to print FIXED on a host whose clock was never
    going to be disciplined."""
    r = _run_step(tmp_path, synced=False, check=0, systemctl_rc=1,
                  systemctl_err="Failed to enable unit: Unit systemd-timesyncd.service not found.")
    assert r.returncode == 0, r.stdout + r.stderr
    line = _lines(r)[0]
    assert line.startswith("FIXFAILED|"), \
        f"a failed time-sync fix must not be reported as FIXED: {r.stdout}"
    assert "systemd-timesyncd.service not found" in line, \
        "the failure must carry what the command said, not a generic message"
    assert "systemctl enable --now systemd-timesyncd" in line, \
        "the failure must name the command the operator can run"
    assert "COUNTERS|0|1" in r.stdout, "a failed fix must count towards a non-zero exit"


def test_the_failure_line_is_one_line(tmp_path: Path) -> None:
    """Multi-line stderr must not spray the report (the reporters take one arg)."""
    r = _run_step(tmp_path, synced=False, check=0, systemctl_rc=1,
                  systemctl_err="first line\\nsecond line\\nthird line")
    assert len([ln for ln in r.stdout.splitlines() if ln.startswith("FIXFAILED|")]) == 1
    assert "third line" in r.stdout


# ── the class, not just this step ───────────────────────────────────────────

SWALLOW_THEN_CLAIM = re.compile(r"\|\|\s*true\s*;\s*fixd\b")


def test_no_step_swallows_its_command_and_then_claims_it_fixed_it() -> None:
    """§16.1: `cmd || true; fixd "…"` is a FIXED line with nothing behind it."""
    src = PREP.read_text(encoding="utf-8")
    offenders = [ln for ln in src.splitlines() if SWALLOW_THEN_CLAIM.search(ln)]
    assert not offenders, (
        "these steps report FIXED regardless of what the command did (FMEA P3):\n  "
        + "\n  ".join(offenders))


@pytest.mark.parametrize("word", ["fixfail", "fixd"])
def test_the_time_sync_step_uses_the_shared_reporters(word: str) -> None:
    assert word in _step(), (
        f"the time-sync step no longer reports through {word}() — every step "
        "reports its outcome the same way")
