# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The two POSIX bridges that carry file-mounted credentials into third-party
tools (tracker 367 layer 1), run under the host's /bin/sh:

  * deployment/docker/gnmic/cx-secret-env.sh — VAR=file pairs into the PROCESS
    env, then exec; any refusal is exit 78 and names the variable only.
  * deployment/docker/vector/cx-secret-exec.sh — Vector's `exec` secret
    backend: {"version":"1.0","secrets":[...]} on stdin, {key:{value,error}}
    on stdout; unresolvable keys are per-key errors (fail closed).

Both apply the internal/credfile format: one trailing newline trimmed; empty,
> 1 KiB and non-printable refused. The in-image behaviour (busybox ash, real
gnmic / vector) was verified by hand on the pinned images, 2026-11-07.

Run:  python3 -m pytest tests/test_secret_file_wrappers.py -v
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENV_WRAPPER = ROOT / "deployment" / "docker" / "gnmic" / "cx-secret-env.sh"
EXEC_BACKEND = ROOT / "deployment" / "docker" / "vector" / "cx-secret-exec.sh"
SH = shutil.which("sh") or "/bin/sh"


def run(argv: list[str], stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          timeout=20, check=False)


def secret(tmp: Path, content: str | bytes, name: str = "password") -> Path:
    p = tmp / name
    p.write_bytes(content.encode() if isinstance(content, str) else content)
    return p


# ── cx-secret-env.sh ─────────────────────────────────────────────────────────

def env_run(tmp: Path, pairs: list[str], prog: list[str] | None = None):
    prog = prog or [SH, "-c", 'printf "%s|%s" "${CX_A-unset}" "${CX_B-unset}"']
    return run([SH, str(ENV_WRAPPER), *pairs, "--", *prog])


def test_env_wrapper_loads_values_and_execs(tmp_path):
    a = secret(tmp_path, "alpha\n", "a")
    b = secret(tmp_path, "be ta", "b")
    r = env_run(tmp_path, [f"CX_A={a}", f"CX_B={b}"])
    assert r.returncode == 0, r.stderr
    assert r.stdout == "alpha|be ta"            # ONE trailing newline trimmed
    assert "loaded 2 credential(s)" in r.stderr
    assert "alpha" not in r.stderr and "be ta" not in r.stderr


@pytest.mark.parametrize("content,why", [
    ("", "empty"),
    ("\n", "empty"),
    ("x\n\n", "non-printable"),
    ("a\tb", "non-printable"),
    ("x" * 1025, "than 1024 bytes"),
    ("x" * 1100, "larger than 1024"),
    (b"caf\xc3\xa9", "non-printable"),
], ids=["empty", "newline-only", "two-newlines", "tab", "1025-bytes", "1100-bytes", "utf8"])
def test_env_wrapper_refuses_bad_files_exit_78_without_the_value(tmp_path, content, why):
    p = secret(tmp_path, content)
    r = env_run(tmp_path, [f"CX_A={p}"])
    assert r.returncode == 78, (r.returncode, r.stderr)
    assert why in r.stderr and "CX_A" in r.stderr
    assert r.stdout == "", "the program must not have run"


def test_env_wrapper_exactly_at_the_limit_is_accepted(tmp_path):
    p = secret(tmp_path, "y" * 1024 + "\n")
    r = env_run(tmp_path, [f"CX_A={p}"], [SH, "-c", 'printf "%s" "${#CX_A}"'])
    assert r.returncode == 0, r.stderr
    assert r.stdout == "1024"


@pytest.mark.parametrize("pairs,why", [
    (["CX_A=/nonexistent/password"], "missing or unreadable"),
    (["CX_A=relative/path"], "must be absolute"),
    (["1BAD=/x"], "invalid environment variable name"),
    (["BAD-NAME=/x"], "invalid environment variable name"),
    (["noequals"], "without '='"),
    ([], "no VAR=file pairs"),
])
def test_env_wrapper_refuses_bad_arguments(tmp_path, pairs, why):
    r = env_run(tmp_path, pairs)
    assert r.returncode == 78, (r.returncode, r.stderr)
    assert why in r.stderr


def test_env_wrapper_refuses_without_a_program(tmp_path):
    p = secret(tmp_path, "pw")
    r = run([SH, str(ENV_WRAPPER), f"CX_A={p}", "--"])
    assert r.returncode == 78 and "no program" in r.stderr


# ── cx-secret-exec.sh ────────────────────────────────────────────────────────

def backend(root: Path, keys: list[str], *, raw: str | None = None):
    req = raw if raw is not None else json.dumps({"version": "1.0", "secrets": keys})
    return run([SH, str(EXEC_BACKEND), str(root)], req)


def identity(root: Path, key: str, content: str | bytes) -> None:
    (root / key).mkdir(parents=True, exist_ok=True)
    secret(root / key, content)


def test_exec_backend_resolves_keys(tmp_path):
    identity(tmp_path, "vector", "vec-pw\n")
    identity(tmp_path, "gnmic", 'with"quote\\and-backslash')
    r = backend(tmp_path, ["vector", "gnmic"])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {
        "vector": {"value": "vec-pw", "error": None},
        "gnmic": {"value": 'with"quote\\and-backslash', "error": None},
    }
    assert "vec-pw" not in r.stderr


def test_exec_backend_tolerates_a_qualified_key(tmp_path):
    identity(tmp_path, "vector", "vec-pw")
    r = backend(tmp_path, ["vmauth.vector"])
    assert json.loads(r.stdout) == {"vector": {"value": "vec-pw", "error": None}}


def test_exec_backend_fails_closed_per_key(tmp_path):
    identity(tmp_path, "vector", "ok-pw")
    identity(tmp_path, "empty", "")
    r = backend(tmp_path, ["vector", "missing", "empty"])
    assert r.returncode == 1, "a degraded run must be loud"
    reply = json.loads(r.stdout)
    assert reply["vector"] == {"value": "ok-pw", "error": None}
    assert reply["missing"]["value"] is None and "missing or unreadable" in reply["missing"]["error"]
    assert reply["empty"]["value"] is None and "empty" in reply["empty"]["error"]
    assert "ok-pw" not in r.stderr


def test_exec_backend_cannot_be_steered_outside_its_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    identity(tmp_path, "outside", "SHOULD-NOT-LEAK")
    r = backend(root, ["../outside", "/etc/passwd", "a b"])
    assert r.returncode == 1
    assert json.loads(r.stdout) == {}
    assert "SHOULD-NOT-LEAK" not in r.stdout + r.stderr


@pytest.mark.parametrize("argv_root,why", [
    ("", "absolute directory"),
    ("relative", "absolute directory"),
    ("/nonexistent-cx-root", "not a directory"),
])
def test_exec_backend_refuses_a_bad_root(argv_root, why):
    r = run([SH, str(EXEC_BACKEND), argv_root], '{"version":"1.0","secrets":["x"]}')
    assert r.returncode == 1 and why in r.stderr
    assert json.loads(r.stdout) == {}


def test_exec_backend_refuses_a_malformed_request(tmp_path):
    r = backend(tmp_path, [], raw="not json at all")
    assert r.returncode == 1 and "no valid secret keys" in r.stderr


@pytest.mark.parametrize("script", [ENV_WRAPPER, EXEC_BACKEND])
def test_wrappers_are_shellcheck_clean(script):
    sc = shutil.which("shellcheck")
    if sc is None:
        pytest.skip("shellcheck not installed (CI's supply-chain/lint legs run it)")
    r = run([sc, "-s", "sh", str(script)])
    assert r.returncode == 0, r.stdout + r.stderr
