# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""host-hygiene.sh dev-host leftovers (2026-11-08): the lint cache, worktree
caches and stale Claude session scratch are reclaimed — and NOTHING outside
$HOME/.cache or /tmp/claude-<uid> can ever be emptied. Runs the REAL shell
functions (extracted from the script) against temp dirs and a fake `docker`."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts" / "host-hygiene.sh").read_text(encoding="utf-8")


def _functions() -> str:
    start = SCRIPT.index("# shellcheck disable=SC2329  # called from empty_dir_via_docker")
    end = SCRIPT.index("lab_dev_leftovers() {")
    return SCRIPT[start:end]


def _run(tmp: Path, body: str) -> subprocess.CompletedProcess:
    fakebin = tmp / "bin"
    fakebin.mkdir(exist_ok=True)
    log = tmp / "docker.log"
    docker = fakebin / "docker"
    docker.write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 0\n')
    docker.chmod(0o755)
    env = {**os.environ, "HOME": str(tmp / "home"), "PATH": f"{fakebin}:{os.environ['PATH']}"}
    return subprocess.run(["bash", "-c", "set -u\n" + _functions() + "\n" + body],
                          capture_output=True, text=True, env=env, timeout=30, check=False)


def test_the_script_is_lab_only_tooling() -> None:
    make = (ROOT / "scripts" / "make-installer.sh").read_text(encoding="utf-8")
    m = re.search(r"^LAB_PATHS='([^']*)'", make, re.MULTILINE)
    assert m and "scripts/host-hygiene" in m.group(1), "host-hygiene.sh must never ship in a customer bundle"


def test_tier1_calls_the_leftover_sweep() -> None:
    t1 = SCRIPT[SCRIPT.index("tier1() {"):SCRIPT.index("tier2() {")]
    assert "lab_dev_leftovers" in t1


def test_stale_session_dirs_lists_only_untouched_sessions(tmp_path: Path) -> None:
    root = tmp_path / "claude"
    old = root / "proj" / "old-session" / "scratchpad"
    new = root / "proj" / "active-session" / "scratchpad"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "f").write_text("x")
    (new / "f").write_text("x")
    subprocess.run(["touch", "-d", "10 days ago", str(old / "f"), str(old), str(old.parent)], check=True)
    r = _run(tmp_path, f'stale_session_dirs "{root}" 3')
    assert r.returncode == 0, r.stderr
    listed = [ln for ln in r.stdout.splitlines() if ln]
    assert listed == [str(root / "proj" / "old-session")], listed


def test_an_active_session_with_one_recent_file_is_kept(tmp_path: Path) -> None:
    root = tmp_path / "claude"
    s = root / "proj" / "s1"
    (s / "deep").mkdir(parents=True)
    (s / "old").write_text("x")
    subprocess.run(["touch", "-d", "10 days ago", str(s / "old"), str(s), str(s / "deep")], check=True)
    (s / "deep" / "recent").write_text("x")      # one fresh file deep inside
    r = _run(tmp_path, f'stale_session_dirs "{root}" 3')
    assert r.stdout.strip() == "", r.stdout


def test_empty_dir_refuses_anything_outside_the_safe_roots(tmp_path: Path) -> None:
    (tmp_path / "home" / ".cache").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    link = tmp_path / "home" / ".cache" / "escape"
    link.symlink_to(outside)                     # symlink escape out of .cache
    for target in (str(outside), "", "/etc", str(link)):
        r = _run(tmp_path, f'empty_dir_via_docker "{target}"; echo "rc=$?"')
        assert "rc=2" in r.stdout, (target, r.stdout, r.stderr)
    assert not (tmp_path / "docker.log").exists(), "docker must never run for a refused path"


def test_empty_dir_runs_one_scoped_container_for_a_cache_dir(tmp_path: Path) -> None:
    cache = tmp_path / "home" / ".cache" / "golangci-lint-docker"
    cache.mkdir(parents=True)
    r = _run(tmp_path, f'empty_dir_via_docker "{cache}"; echo "rc=$?"')
    assert "rc=0" in r.stdout, r.stderr
    call = (tmp_path / "docker.log").read_text()
    assert f"-v {cache.resolve()}:/target" in call or f"-v {cache}:/target" in call, call
    assert "find /target -mindepth 1 -delete" in call, call
