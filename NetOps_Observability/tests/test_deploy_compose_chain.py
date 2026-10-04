# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""scripts/deploy.sh must drive compose through the install's own COMPOSE_FILE chain.

2026-10-04: deploy.sh ran `docker compose -f deployment/docker/docker-compose.yml`.
An explicit -f keeps the .env VARIABLES but drops every overlay the .env's
COMPOSE_FILE names. On a TLS install that recreated the api with a verify-full
Postgres DSN but no TLS mounts: it crash-looped, the site answered 502, and the
rollback used the same -f, so it could not recover either.

These tests run the REAL script against stub docker/curl/sleep binaries (the live
stack is never touched) and assert every compose call — deploy and rollback —
runs from deployment/docker with no -f, which is what makes compose read .env.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deploy.sh"
COMPOSE_DIR = (ROOT / "deployment" / "docker").resolve()


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def _run(tmp_path: Path, healthy: bool) -> tuple[subprocess.CompletedProcess, list[str]]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "docker-calls.log"
    # docker: record "<cwd>|<args>"; answer the few queries deploy.sh makes.
    _stub(bindir / "docker", (
        f'echo "$PWD|$*" >> "{calls}"\n'
        'case "$*" in\n'
        '  *"ps -q"*) echo cid-1 ;;\n'
        '  inspect*) echo sha256:oldimage ;;\n'
        'esac\n'
        'exit 0\n'))
    _stub(bindir / "curl", "exit 0\n" if healthy else "exit 7\n")
    _stub(bindir / "sleep", "exit 0\n")  # the health waits must not cost real time
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    # "api" only: skips the real frontend build, which these tests do not exercise.
    r = subprocess.run(["bash", str(SCRIPT), "api"], env=env, capture_output=True,
                       text=True, timeout=120, cwd=tmp_path)
    lines = calls.read_text().splitlines() if calls.exists() else []
    return r, [ln for ln in lines if "|compose " in ln]


def _assert_chain(compose_calls: list[str]) -> None:
    assert compose_calls, "deploy.sh made no compose calls — the stub was not reached"
    for ln in compose_calls:
        cwd, args = ln.split("|", 1)
        assert Path(cwd).resolve() == COMPOSE_DIR, (
            f"compose ran from {cwd}, not {COMPOSE_DIR}: it would not read the install's .env "
            f"COMPOSE_FILE chain ({args})")
        assert " -f " not in f" {args} " and "--file" not in args, (
            f"compose was given an explicit file ({args}): that drops every overlay in "
            "COMPOSE_FILE, compose.tls.yml included")


def test_deploy_runs_compose_through_the_env_chain(tmp_path):
    r, compose_calls = _run(tmp_path, healthy=True)
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_chain(compose_calls)
    assert any(" up -d --build api" in ln for ln in compose_calls), compose_calls


def test_rollback_also_runs_compose_through_the_env_chain(tmp_path):
    # Unhealthy after deploy: the rollback path must recreate from the same chain,
    # or it repeats the half-plaintext recreate it is meant to undo.
    r, compose_calls = _run(tmp_path, healthy=False)
    assert r.returncode != 0, "an unhealthy deploy must not report success"
    _assert_chain(compose_calls)
    assert any(" up -d --no-build api" in ln for ln in compose_calls), (
        "the rollback never re-created the service", compose_calls)


def test_no_explicit_compose_file_anywhere_in_deploy_sh():
    code = "\n".join(ln for ln in SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#"))
    assert "docker compose -f" not in code and "compose --file" not in code, (
        "deploy.sh names a compose file explicitly — that bypasses COMPOSE_FILE")
