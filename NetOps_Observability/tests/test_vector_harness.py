# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tests/vector_harness.py — the bounded, logged retry for the upstream Vector
buffer race (tracker 350). Pure Python: the runner is faked, so these pin the
DECISION (when a run may be retried, and that it is never silent) without docker.

The outputs below are the real CI failure bodies, trimmed to the lines the
parser reads (PR #88 run 40142538158 and PR #24 run 39041076150)."""

from __future__ import annotations

import re
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vector_harness as vh

ROOT = Path(__file__).resolve().parent.parent

NO_EVENTS = ('checks for transforms ["flows_decoded"] failed: no events received. '
             'Topology may be disconnected or transform is missing inputs.')

PIM_RACE = f"""Running tests
2026-10-24T23:27:28.512048Z  WARN transform{{component_kind="transform"}}: acknowledgements
test flows: protocol IPv6-ICMP is 58 ... passed
test flows: protocol PIM is 103 ... failed
test flows: protocol VRRP is 112 ... passed

failures:

test flows: protocol PIM is 103:

{NO_EVENTS}

2026-10-24T23:27:28.512048Z  WARN transform{{component_kind="transform" component_id=flows_decoded}}: vrl::stdlib::log::implementation: component=flows_decoded dropped an exporter application_id
2026-10-24T23:27:28.512706Z  WARN transform{{component_kind="transform"}}: Internal log [x] is being suppressed to avoid flooding.
"""

FIXTURE14_RACE = """Running tests
test fixture 13: x ... passed
test fixture 14: traffic/forward ... failed
test fixture 15: y ... passed

failures:

test fixture 14: traffic/forward:

checks for transforms ["syslog_admission_stamp"] failed: no events received. Topology may be disconnected or transform is missing inputs.


"""

REAL_FAILURE = """Running tests
test flows: protocol PIM is 103 ... failed

failures:

test flows: protocol PIM is 103:

check[0] for transforms ["flows_decoded"] failed conditions:
  condition[0]: function call error for "assert_eq" at (0:72): every goflow2 protocol name maps to its IANA number
output payloads from ["flows_decoded"] (events encoded as JSON):
  {"proto":0}
"""

PASS = """Running tests
test flows: protocol PIM is 103 ... passed
test flows: protocol VRRP is 112 ... passed
"""


def _race_body(names: list[str]) -> str:
    out = ["Running tests"] + [f"test {n} ... failed" for n in names] + ["", "failures:", ""]
    for n in names:
        out += [f"test {n}:", "", NO_EVENTS, ""]
    return "\n".join(out)


class FakeRunner:
    def __init__(self, *outputs: tuple[int, str]) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs) -> subprocess.CompletedProcess:
        assert kwargs["timeout"] > 0 and kwargs["check"] is False
        self.calls.append(cmd)
        rc, out = self.outputs.pop(0)
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")


CMD = ["docker", "run", "--rm", "timberio/vector:0.40.0-alpine", "test", "/x.yaml"]


# ── the parser ───────────────────────────────────────────────────────────────

def test_the_real_ci_failures_are_diagnosed_as_the_race():
    for out, case in ((PIM_RACE, "flows: protocol PIM is 103"),
                      (FIXTURE14_RACE, "fixture 14: traffic/forward")):
        d = vh.diagnose(out)
        assert d.failed == (case,)
        assert d.race_only, d


def test_a_failed_condition_is_never_the_race():
    d = vh.diagnose(REAL_FAILURE)
    assert d.failed == ("flows: protocol PIM is 103",)
    assert not d.race_only


def test_a_race_case_next_to_a_real_failure_is_not_retried():
    mixed = _race_body(["a"]).replace("Running tests", "Running tests\ntest b ... failed")
    mixed += "\ntest b:\n\ncheck[0] for transforms [\"t\"] failed conditions:\n  condition[0]: nope\n"
    d = vh.diagnose(mixed)
    assert set(d.failed) == {"a", "b"}
    assert not d.race_only


def test_too_many_race_cases_is_a_wiring_problem_not_the_race():
    assert vh.diagnose(_race_body(["a", "b"])).race_only
    assert not vh.diagnose(_race_body(["a", "b", "c"])).race_only


def test_a_failure_with_no_parsable_body_is_not_the_race():
    # e.g. a config build error: non-zero exit, no `... failed` case line.
    assert not vh.diagnose("Failed to build test 'x':\n  boom\n").race_only
    assert not vh.diagnose("test a ... failed\n").race_only     # no failures: block


def test_a_signature_with_extra_error_text_is_not_the_race():
    out = _race_body(["a"]) + "expected no outputs\n"
    assert not vh.diagnose(out).race_only


# ── the retry policy ─────────────────────────────────────────────────────────

def test_a_green_run_is_run_exactly_once():
    r = FakeRunner((0, PASS))
    run = vh.run_vector_test(CMD, label="x", timeout=60, runner=r)
    assert len(r.calls) == 1 and not run.retried and run.final.returncode == 0


def test_a_real_failure_is_never_retried():
    r = FakeRunner((78, REAL_FAILURE))
    with warnings.catch_warnings():
        warnings.simplefilter("error")          # any retry warning would raise
        run = vh.run_vector_test(CMD, label="x", timeout=60, runner=r)
    assert len(r.calls) == 1 and not run.retried and run.final.returncode == 78


def test_the_race_is_retried_once_and_loudly(monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    r = FakeRunner((78, PIM_RACE), (0, PASS))
    with pytest.warns(vh.VectorHarnessRaceRetry, match=r"PIM is 103.*24695"):
        run = vh.run_vector_test(CMD, label="router parse-trace", timeout=60, runner=r)
    assert len(r.calls) == 2 and r.calls[0] == r.calls[1] == CMD
    assert run.retried and run.final.returncode == 0
    assert run.race_cases == ("flows: protocol PIM is 103",)
    text = summary.read_text(encoding="utf-8")
    assert "router parse-trace" in text and "Tracker 350" in text


def test_a_retry_that_fails_again_fails_and_reports_both_attempts():
    r = FakeRunner((78, FIXTURE14_RACE), (78, FIXTURE14_RACE))
    with pytest.warns(vh.VectorHarnessRaceRetry):
        run = vh.run_vector_test(CMD, label="x", timeout=60, runner=r)
    assert len(r.calls) == 2, "retry-ONCE: never a third run"
    assert run.final.returncode == 78
    rep = run.report()
    assert rep.count("fixture 14: traffic/forward ... failed") == 2
    assert "ATTEMPT 1" in rep and "ATTEMPT 2" in rep


# ── the guards that keep the workaround honest ───────────────────────────────

def _shipped_vector_images() -> list[str]:
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    router = (ROOT / "deployment" / "docker" / "vector-router" / "Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"timberio/vector:[^\s\"']+", compose + "\n" + router)
    assert images, "no shipped timberio/vector image found"
    return images


def test_the_retry_is_deleted_once_the_shipped_vector_has_the_fix():
    """The retry exists ONLY because 0.40 lacks vectordotdev/vector#24695. When
    the shipped runtime reaches v0.54.0 this fails: delete tests/vector_harness.py's
    retry (call the runner once) and this test, and close the loop on tracker 350."""
    for image in _shipped_vector_images():
        version = vh.image_version(image)
        assert version is not None, image
        assert version < vh.UPSTREAM_FIX_VERSION, (
            f"{image} contains {vh.UPSTREAM_FIX}: the race-retry in "
            "tests/vector_harness.py is now dead weight that could only hide a "
            "real 'no events received' — remove it")


def test_the_suites_run_on_the_image_the_stack_ships():
    shipped = {vh.image_version(i) for i in _shipped_vector_images()}
    assert len(shipped) == 1, shipped
    for path in ("test_pipeline_debug_vrl.py", "test_syslog_admission.py"):
        src = (ROOT / "tests" / path).read_text(encoding="utf-8")
        m = re.search(r'VECTOR_IMAGE = "([^"]+)"', src)
        assert m and vh.image_version(m.group(1)) in shipped, path


def test_every_vector_test_invocation_goes_through_the_harness():
    """A bare `subprocess.run([... "test", ...])` against the vector image would
    bring back the unexplained red (or, worse, invite a hand-rolled silent retry)."""
    offenders = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        src = path.read_text(encoding="utf-8")
        runs_vector = '"--entrypoint", "vector"' in src
        runs_test = re.search(r'"test",', src) is not None
        if runs_vector and runs_test and "run_vector_test(" not in src:
            offenders.append(path.name)
    assert not offenders, offenders
    for name in ("test_pipeline_debug_vrl.py", "test_syslog_admission.py"):
        assert "run_vector_test(" in (ROOT / "tests" / name).read_text(encoding="utf-8"), name
