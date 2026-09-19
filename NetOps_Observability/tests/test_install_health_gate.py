# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The health gate must scale with the host and name its own failure.

Fresh install on .123, 2026-09-16: every one of the 27 containers was running
and healthy, the dashboard answered, and the installer still finished with
"Installation did not complete cleanly" — because `wait_healthy` could not read
the container state and said only "could not list this install's containers
(docker compose ps / docker inspect failed)". Two defects in one line:

  * the reason was thrown away (`2>/dev/null` on both commands, §16.1), so
    neither the operator nor the log could say WHY; and
  * the budgets were fixed (60 s per query, 7 minutes overall) on a host whose
    own profile said `budget_factor: 3` — install.py had already stretched every
    one of its waits, this gate had not.

These tests pin the replacement. No docker, no network: the functions under
test are sourced out of the script and driven with fakes on PATH.

Run:  python3 -m pytest tests/test_install_health_gate.py -v
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install-correlix.sh"


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _functions(*names: str) -> str:
    """The named shell functions, lifted verbatim from the script."""
    src = _src()
    out = []
    for n in names:
        m = re.search(rf"^{re.escape(n)}\(\) \{{.*?^\}}$", src, re.S | re.M)
        assert m, f"{n}() not found in install-correlix.sh"
        out.append(m.group(0))
    return "\n".join(out)


def _run(body: str, *, path_dir: Path | None = None, root: Path | None = None) -> subprocess.CompletedProcess:
    preamble = [
        "set -uo pipefail",
        f'ROOT="{root or ROOT}"',
        f'COMPOSE_DIR="{root or ROOT}"',
        'warn() { printf "[warn ] %s\\n" "$1" >&2; }',
        'say()  { printf "%s\\n" "$1"; }',
        'ok()   { printf "[ ok  ] %s\\n" "$1"; }',
    ]
    env = {"PATH": f"{path_dir}:/usr/bin:/bin" if path_dir else "/usr/bin:/bin", "HOME": str(root or ROOT)}
    return subprocess.run(["bash", "-c", "\n".join(preamble) + "\n" + body],
                          capture_output=True, text=True, timeout=120, env=env)


def _fake_docker(tmp_path: Path, script: str) -> Path:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    f = d / "docker"
    f.write_text("#!/bin/bash\n" + script)
    f.chmod(0o755)
    (d / "timeout").symlink_to("/usr/bin/timeout")
    return d


def _profile(root: Path, factor) -> None:
    (root / "data").mkdir(parents=True, exist_ok=True)
    (root / "data" / ".host-profile.json").write_text(json.dumps({"class": "very-slow", "budget_factor": factor}))


# ── the budgets follow the host profile install.py already measured ──────────

@pytest.mark.parametrize("factor,expect", [(1, "420"), (2, "840"), (3, "1260")])
def test_the_wait_budget_scales_with_the_measured_host(tmp_path, factor, expect):
    _profile(tmp_path, factor)
    r = _run(_functions("host_budget_factor", "scaled_s") + "\nscaled_s 420", root=tmp_path)
    assert r.stdout.strip() == expect, r.stderr


def test_a_missing_or_broken_profile_means_unscaled_never_a_crash(tmp_path):
    r = _run(_functions("host_budget_factor", "scaled_s") + "\nscaled_s 420", root=tmp_path)
    assert r.stdout.strip() == "420"
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / ".host-profile.json").write_text("{ this is not json")
    r = _run(_functions("host_budget_factor", "scaled_s") + "\nscaled_s 60", root=tmp_path)
    assert r.stdout.strip() == "60"


def test_an_absurd_factor_is_clamped(tmp_path):
    _profile(tmp_path, 99)
    r = _run(_functions("host_budget_factor", "scaled_s") + "\nscaled_s 100", root=tmp_path)
    assert r.stdout.strip() == "400", "the factor must be clamped to 4"


# ── the failure names itself (§16.1: never swallow the reason) ───────────────

def test_a_compose_failure_is_reported_with_dockers_own_words(tmp_path):
    bind = _fake_docker(tmp_path, 'echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2; exit 1\n')
    body = _functions("host_budget_factor", "scaled_s", "compose_q_errfile", "compose_q_err", "compose_q", "container_snapshot") + """
container_snapshot >/dev/null; rc=$?
printf 'rc=%s\\nerr=%s\\n' "$rc" "$SNAPSHOT_ERR"
"""
    r = _run(body, path_dir=bind, root=tmp_path)
    assert "rc=1" in r.stdout
    assert "Cannot connect to the Docker daemon" in r.stdout, r.stdout + r.stderr


def test_an_inspect_failure_is_reported_with_its_exit_code(tmp_path):
    bind = _fake_docker(tmp_path, """
case "$1" in
  compose) echo deadbeefcafe ;;
  inspect) echo "template parsing error" >&2; exit 2 ;;
esac
""")
    body = _functions("host_budget_factor", "scaled_s", "compose_q_errfile", "compose_q_err", "compose_q", "container_snapshot") + """
container_snapshot >/dev/null; printf 'err=%s\\n' "$SNAPSHOT_ERR"
"""
    r = _run(body, path_dir=bind, root=tmp_path)
    assert "docker inspect (exit 2)" in r.stdout and "template parsing error" in r.stdout, r.stdout


def test_an_empty_container_list_says_so_rather_than_failing_blankly(tmp_path):
    bind = _fake_docker(tmp_path, 'case "$1" in compose) exit 0 ;; esac\n')
    body = _functions("host_budget_factor", "scaled_s", "compose_q_errfile", "compose_q_err", "compose_q", "container_snapshot") + """
container_snapshot >/dev/null; printf 'err=%s\\n' "$SNAPSHOT_ERR"
"""
    r = _run(body, path_dir=bind, root=tmp_path)
    assert "listed no containers" in r.stdout, r.stdout


def test_a_timeout_is_named_as_a_timeout_with_the_budget(tmp_path):
    _profile(tmp_path, 3)
    bind = _fake_docker(tmp_path, 'sleep 30\n')
    body = _functions("host_budget_factor", "scaled_s", "compose_q_errfile", "compose_q_err", "compose_q") + """
compose_q ps -aq >/dev/null; printf 'err=%s\\n' "$(compose_q_err)"
"""
    r = _run(body.replace('timeout "$(scaled_s 60)"', 'timeout 1'), path_dir=bind, root=tmp_path)
    assert "timed out after" in r.stdout, r.stdout


# ── the operator-facing text ─────────────────────────────────────────────────

def test_the_gate_no_longer_hardcodes_seven_minutes_or_hides_the_reason():
    src = _src()
    assert 'warn "services did not all become ready within $((budget / 60)) minutes:"' in src, \
        "the message must state the budget actually used, which now scales with the host"
    assert "could not list this install's containers (docker compose ps / docker inspect failed)." not in src, \
        "the blank failure line must be gone"
    assert 'warn "could not read this install\'s container state: ${lasterr:-' in src
    assert "./install-correlix.sh status" in src, "a failure to read state must point at the next step"


def test_no_query_in_the_gate_throws_its_error_away():
    """§16.1: the two commands whose silence caused the .123 false failure."""
    src = _src()
    block = src[src.index("container_snapshot() {"):src.index("stability_window_s() {")]
    assert "2>/dev/null" not in block, "container_snapshot must keep docker's error, not discard it"
    cq = re.search(r"^compose_q\(\) \{.*?^\}$", src, re.S | re.M).group(0)
    assert "2>\"${f:-/dev/null}\"" in cq, "compose_q must capture docker's error to a file that survives the subshell"
