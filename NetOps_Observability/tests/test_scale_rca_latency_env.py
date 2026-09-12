# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`scale-rca-latency.py` must not resolve its ClickHouse container from a
compose .env it could not read.

THE SWALLOW THIS KILLS. `env_get` caught OSError and returned "" — so a missing
or permission-denied `.env` was indistinguishable from "the key isn't set", and
`main()` silently fell back to the project name "netops":

    args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"

On a stack whose COMPOSE_PROJECT_NAME is anything else that means every
`SELECT` runs against the wrong container — or none — and the operator reads a
TTUR measurement of a fleet that was never sampled. That is the §16.1
warn-and-continue class (the hygiene cron that reported `91% -> 91%` while
reclaiming nothing), and `tests/test_error_swallow_guard.py` fails the build on
it.

The contract these tests pin:
  * a MISSING KEY in a readable file -> ""  (callers decide; main() defaults)
  * a file that cannot be READ       -> die() naming the path and the errno

Run:  python3 -m pytest tests/test_scale_rca_latency_env.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_tool():
    path = ROOT / "scripts" / "scale-rca-latency.py"
    spec = importlib.util.spec_from_file_location("scale_rca_latency_env", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_rca_latency_env"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, (
        "importing the tool must not mutate PATH — pin it in main() instead")
    return mod


rl = _load_tool()


def test_present_key_is_returned(tmp_path):
    env = tmp_path / ".env"
    env.write_text("BASE_PORT=8000\nCOMPOSE_PROJECT_NAME=netops-lab\n")
    assert rl.env_get(str(env), "COMPOSE_PROJECT_NAME") == "netops-lab"


def test_missing_key_in_a_readable_file_returns_empty(tmp_path):
    """A key that isn't set is NOT an error — main() falls back to 'netops'."""
    env = tmp_path / ".env"
    env.write_text("BASE_PORT=8000\n")
    assert rl.env_get(str(env), "COMPOSE_PROJECT_NAME") == ""


def test_missing_env_file_is_fatal_and_names_the_path(tmp_path, capsys):
    missing = tmp_path / "nope" / ".env"
    with pytest.raises(SystemExit) as exc:
        rl.env_get(str(missing), "COMPOSE_PROJECT_NAME")
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert str(missing) in err
    assert "errno 2" in err
    assert "--project" in err, "the message must state the operator's way out"


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a 0o000 file")
def test_unreadable_env_file_is_fatal_not_an_empty_string(tmp_path, capsys):
    """Permission denied is the shape that made this silent: the file EXISTS,
    so nothing looks wrong — and the query runs against the wrong project."""
    env = tmp_path / ".env"
    env.write_text("COMPOSE_PROJECT_NAME=netops-lab\n")
    env.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as exc:
            rl.env_get(str(env), "COMPOSE_PROJECT_NAME")
    finally:
        env.chmod(0o600)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert str(env) in err
    assert "errno 13" in err


def test_a_directory_in_place_of_the_env_file_is_fatal(tmp_path, capsys):
    with pytest.raises(SystemExit):
        rl.env_get(str(tmp_path), "COMPOSE_PROJECT_NAME")
    assert "cannot read compose env file" in capsys.readouterr().err
