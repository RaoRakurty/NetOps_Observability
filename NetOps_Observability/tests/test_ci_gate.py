# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""scripts/ci/ci_gate.py — every row of the gate's truth table.

The gate exists because GitHub reports a skipped job as passing: without it, a
job skipped by a broken plan and a job skipped by a correct one look the same.
Every ambiguous state must FAIL.
"""
import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "scripts", "ci", "ci_gate.py")
_spec = importlib.util.spec_from_file_location("ci_gate", GATE)
gate = importlib.util.module_from_spec(_spec)
sys.modules["ci_gate"] = gate
_spec.loader.exec_module(gate)

JOBS = {"test": "backend", "build": "frontend", "lint": "always"}


def _plan(**groups):
    g = {"backend": False, "correlation": False, "frontend": False, "install-boot": False}
    g.update({k.replace("_", "-"): v for k, v in groups.items()})
    return {"result": "success", "outputs": {"plan": json.dumps({"schema": 1, "mode": "selective", "groups": g})}}


def _needs(plan, **results):
    n = {"plan": plan}
    n.update({j: {"result": r} for j, r in results.items()})
    return n


def test_selected_success_and_unselected_skip_pass():
    assert gate.evaluate(_needs(_plan(backend=True), test="success", build="skipped", lint="success"), JOBS) == []


def test_unselected_job_that_ran_and_passed_is_fine():
    assert gate.evaluate(_needs(_plan(), test="success", build="success", lint="success"), JOBS) == []


def test_selected_failure_fails():
    errs = gate.evaluate(_needs(_plan(backend=True), test="failure", build="skipped", lint="success"), JOBS)
    assert errs and "test" in errs[0] and "failure" in errs[0]


def test_selected_cancelled_fails():
    assert gate.evaluate(_needs(_plan(backend=True), test="cancelled", build="skipped", lint="success"), JOBS)


def test_selected_but_skipped_fails():
    errs = gate.evaluate(_needs(_plan(backend=True), test="skipped", build="skipped", lint="success"), JOBS)
    assert errs and "unexpectedly skipped" in errs[0]


def test_always_job_skipped_fails():
    assert gate.evaluate(_needs(_plan(), test="skipped", build="skipped", lint="skipped"), JOBS)


def test_unselected_failure_is_never_ignored():
    errs = gate.evaluate(_needs(_plan(), test="failure", build="skipped", lint="success"), JOBS)
    assert errs and "not selected" in errs[0]


def test_unselected_cancelled_fails():
    assert gate.evaluate(_needs(_plan(), test="cancelled", build="skipped", lint="success"), JOBS)


def test_planner_failed_or_cancelled_fails():
    for res in ("failure", "cancelled", "skipped", None):
        p = {"result": res, "outputs": {}}
        errs = gate.evaluate(_needs(p, test="skipped", build="skipped", lint="success"), JOBS)
        assert errs and "planner" in errs[0], res


def test_planner_missing_fails():
    assert gate.evaluate({"test": {"result": "success"}}, JOBS)


def test_malformed_plan_output_fails():
    for raw in ("", "not json", json.dumps({"schema": 2, "groups": {}}),
                json.dumps({"schema": 1, "groups": {"backend": "false"}}),
                json.dumps({"schema": 1})):
        p = {"result": "success", "outputs": {"plan": raw}}
        assert gate.evaluate(_needs(p, test="success", build="success", lint="success"), JOBS), raw


def test_unknown_result_fails():
    assert gate.evaluate(_needs(_plan(backend=True), test="neutral", build="skipped", lint="success"), JOBS)


def test_unmapped_job_in_needs_fails():
    n = _needs(_plan(), test="skipped", build="skipped", lint="success", extra="success")
    assert any("no --job mapping" in e for e in gate.evaluate(n, JOBS))


def test_mapped_job_missing_from_needs_fails():
    n = _needs(_plan(), test="skipped", lint="success")
    assert any("not in needs" in e for e in gate.evaluate(n, JOBS))


def test_group_the_planner_did_not_report_fails():
    assert gate.evaluate(_needs(_plan(), test="skipped", build="skipped", lint="success"),
                         {**JOBS, "lint": "nonexistent-group"})


def _cli(needs_env, *jobs):
    env = {**os.environ, "NEEDS": needs_env}
    args = [sys.executable, GATE] + [a for j in jobs for a in ("--job", j)]
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=30, check=False)


def test_cli_pass_and_fail_exit_codes():
    ok = json.dumps(_needs(_plan(backend=True), test="success"))
    assert _cli(ok, "test=backend").returncode == 0
    bad = json.dumps(_needs(_plan(backend=True), test="skipped"))
    assert _cli(bad, "test=backend").returncode == 1


def test_cli_unreadable_needs_fails():
    assert _cli("{not json", "test=backend").returncode == 1
    assert _cli("[]", "test=backend").returncode == 1


def test_cli_bad_job_spec_is_a_usage_error():
    assert _cli(json.dumps(_needs(_plan())), "test").returncode == 2
