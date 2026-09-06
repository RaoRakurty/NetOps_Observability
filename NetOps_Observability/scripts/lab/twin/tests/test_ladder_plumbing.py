# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Mini-ladder composition plumbing (design §8.3): the `--load-generator twin`
flag exists, requires a scenario, and — crucially — the DEFAULT path is
untouched: default argv parses to the internal generator with the exact
pre-flag defaults, and burst() dispatches to the internal loop."""
import importlib.util
import os
import sys

import pytest
from conftest import REPO_ROOT

_ML_PATH = os.path.join(REPO_ROOT, "scripts", "scale-miniladder.py")


def _load_ml():
    spec = importlib.util.spec_from_file_location("scale_miniladder", _ML_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_miniladder"] = mod
    spec.loader.exec_module(mod)
    return mod


ml = _load_ml()


def test_default_args_unchanged():
    args = ml.parse_args([])
    assert args.load_generator == "internal"
    # the pre-flag defaults, byte-for-byte
    assert (args.devices, args.burst_minutes, args.eps) == (1000, 5, 2000)
    assert (args.linearity_floor, args.drain_factor,
            args.lag_epsilon) == (0.6, 3.0, 100)
    assert args.mem_factor == 1.3 and args.max_baseline_lag == 5000
    assert args.dry_run is False


def test_twin_mode_requires_scenario():
    with pytest.raises(SystemExit):
        ml.parse_args(["--load-generator", "twin"])


def test_twin_mode_parses():
    args = ml.parse_args(["--load-generator", "twin",
                          "--twin-scenario", "/tmp/x.yaml",
                          "--twin-duration-minutes", "3",
                          "--twin-fidelity", "source_ip"])
    assert args.load_generator == "twin"
    assert args.twin_scenario == "/tmp/x.yaml"
    assert args.twin_duration_minutes == 3.0
    assert args.twin_fidelity == "source_ip"


def _harness(argv: list[str]):
    args = ml.parse_args(argv)
    args.project = "netops"
    args.base_url = "http://localhost:8000"
    return ml.Harness(args)


def test_burst_dispatches_internal_by_default(monkeypatch):
    h = _harness([])
    calls = []
    monkeypatch.setattr(h, "_burst_internal", lambda: calls.append("i") or True)
    monkeypatch.setattr(h, "_burst_twin", lambda: calls.append("t") or True)
    assert h.burst() is True
    assert calls == ["i"]


def test_burst_dispatches_twin_when_flagged(monkeypatch):
    h = _harness(["--load-generator", "twin", "--twin-scenario", "/tmp/x"])
    calls = []
    monkeypatch.setattr(h, "_burst_internal", lambda: calls.append("i") or True)
    monkeypatch.setattr(h, "_burst_twin", lambda: calls.append("t") or True)
    assert h.burst() is True
    assert calls == ["t"]


def test_accounting_identity_defaults_to_own_namespace():
    h = _harness([])
    assert h.acct_prefix == h.prefix and h.acct_prefix.startswith("mlx-")
    assert h.acct_runid == h.runid
    assert h.twin_run == {}


def test_twin_burst_command_shape(monkeypatch):
    """The delegated command line: twin.py with global flags before the run
    subcommand, --keep so accounting can count, fidelity passed through."""
    h = _harness(["--load-generator", "twin", "--twin-scenario", "/s.yaml",
                  "--twin-duration-minutes", "2"])
    seen = {}

    def fake_run(cmd, timeout, input_text=None):
        seen["cmd"] = cmd
        return 1, "", "stopped by test"   # fail fast after capturing argv

    monkeypatch.setattr(ml, "run", fake_run)
    h.evidence_file = lambda name, content: name   # no run dir in unit test
    assert h.burst() is False                      # rc=1 → honest FAIL
    cmd = seen["cmd"]
    assert cmd[1].endswith(os.path.join("twin", "twin.py"))
    i_run = cmd.index("run")
    assert "--env-file" in cmd[:i_run]             # global flags precede sub
    assert cmd[i_run + 1:i_run + 3] == ["--scenario", "/s.yaml"]
    assert "--keep" in cmd and "--fidelity" in cmd
    assert cmd[cmd.index("--duration-minutes") + 1] == "2.0"
