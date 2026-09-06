# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Unit tests for `scripts/release-qualify.py` — the V1 release qualification.

The script decides whether a candidate build still meets
`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md`. It costs an hour of rig time per
run and its output is a release decision, so everything it can get wrong is
tested here against a MOCKED host: no docker, no ClickHouse, no network, no
harness, no scorer is touched by this suite.

What is asserted, and why it matters:

  stage ordering       The stages run in the V1 order and the environment gate
                       is FIRST — a refusal that arrives after two minutes of
                       pytest is a refusal that has already burned the thing it
                       was protecting.
  three-valued verdict SKIPPED never fails a run (it is "not measured", the
                       honest third value); INVALID short-circuits and can
                       never be reported as PASS or FAIL; a mixed record grades
                       INVALID over FAIL, because a measurement we cannot trust
                       is not a failure we can report.
  environment          V1 section 8(e): the disk/quiet refusal fires, and
                       `--allow-unquiet` downgrades it to a recorded WARN AND
                       marks `qualification_grade: false`, so an ungraded run
                       can never be mistaken for qualification evidence.
  accuracy             The 0.93 boundary is inclusive; a scorer_version other
                       than 2 FAILS regardless of the number, because a v1
                       accuracy figure is not a V1 accuracy figure (V1
                       section 5).
  aggregation          V1 section 7 is asserted on the PRE/POST DELTA. A
                       replica that RESTARTED mid-run has reset counters, so
                       post-minus-pre is not a delta at all and could balance
                       by coincidence — that is INVALID, never a false PASS.
  baseline extraction  Deterministic and byte-stable: the checked-in baseline is
                       generated, never hand-typed, so it cannot drift from the
                       run it claims to describe.
  --skip-leg           Re-grading the real storm-s11 artifacts (fixtures under
                       tests/fixtures/storm-s11/) reproduces the leg of record:
                       9/9 harness gates and 345/345 on scorer v2.

Run:  python3 -m pytest tests/test_release_qualify.py -q
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "storm-s11"


def _load_qualifier():
    """Import the hyphen-named script by path, asserting it does not touch PATH.

    Its cron-proof PATH is applied in main(), not at import: as module-scope
    code it leaks into every process that merely imports the file (the lesson
    scale-miniladder.py records).
    """
    path = ROOT / "scripts" / "release-qualify.py"
    spec = importlib.util.spec_from_file_location("release_qualify", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["release_qualify"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, "import must not rewrite PATH"
    return mod


rq = _load_qualifier()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def make_args(**over) -> argparse.Namespace:
    base = {"run_dir": "/tmp/does-not-exist", "baseline": str(rq.DEFAULT_BASELINE),
            "max_load1": 6.0, "allow_unquiet": False, "dry_run": False,
            "extract_baseline": "", "skip_leg": "", "project": "netops",
            "env_file": "/nonexistent/.env", "tenant": "global"}
    base.update(over)
    return argparse.Namespace(**base)


class FakeDriver:
    """Only the pieces release-qualify imports from scale-ab-driver."""

    class Driver:
        METRICS_PROBE = "print('metrics probe for {ip}')"

    @staticmethod
    def prom_value(text: str, name: str):
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == name:
                try:
                    return float(parts[1])
                except ValueError:
                    return None
        return None

    @staticmethod
    def last_error_line(text: str) -> str:
        return (text or "").strip().splitlines()[-1] if (text or "").strip() else ""


METRICS_ON = """
corr_agg_enabled 1
corr_agg_observed_total 100
corr_agg_forwarded_total{class="first"} 60
corr_agg_forwarded_total{class="repeat"} 10
corr_agg_suppressed_total 30
"""


def counters(observed, first, repeat, suppressed, started_at="T0"):
    return {"enabled": 1.0, "observed": float(observed),
            "suppressed": float(suppressed),
            "forwarded_by_class": {"first": float(first), "repeat": float(repeat)},
            "forwarded_total": float(first + repeat),
            "started_at": started_at, "name": "netops-correlation-7"}


# ---------------------------------------------------------------------------
# environment — V1 section 8(e)
# ---------------------------------------------------------------------------
def test_quiet_host_has_no_violations():
    fs = [{"path": "/", "free_gib": 11.0, "total_gib": 77.0}]
    assert rq.environment_violations(fs, 2.9, 10.0, 6.0) == []


def test_disk_below_the_floor_is_a_violation():
    fs = [{"path": "/", "free_gib": 9.4, "total_gib": 77.0}]
    problems = rq.environment_violations(fs, 1.0, 10.0, 6.0)
    assert len(problems) == 1 and "9.4 GiB free" in problems[0]


def test_unreadable_filesystem_is_a_violation_not_a_pass():
    """An unmeasured filesystem is not a headroom guarantee (16.1)."""
    fs = [{"path": "/var/lib/docker", "error": "permission denied"}]
    problems = rq.environment_violations(fs, 1.0, 10.0, 6.0)
    assert problems and "UNKNOWN" in problems[0]


def test_load_above_the_bound_is_a_violation():
    fs = [{"path": "/", "free_gib": 40.0, "total_gib": 77.0}]
    problems = rq.environment_violations(fs, 16.4, 10.0, 6.0)
    assert len(problems) == 1 and "load1 16.40" in problems[0]


def test_loadavg_parse_refuses_garbage():
    assert rq.parse_loadavg("2.83 3.57 3.71 4/2078 738348") == 2.83
    with pytest.raises(rq.QualifyError):
        rq.parse_loadavg("")
    with pytest.raises(rq.QualifyError):
        rq.parse_loadavg("nan-ish 1 2")


def test_meminfo_total_is_informational_and_never_fatal():
    assert rq.parse_meminfo_total_kib("MemTotal:       16373052 kB\n") == 16373052
    assert rq.parse_meminfo_total_kib("nothing here") == -1


def _env_qualifier(monkeypatch, tmp_path, free_gib, load1, allow_unquiet):
    args = make_args(run_dir=str(tmp_path), allow_unquiet=allow_unquiet)
    qual = rq.Qualifier(args, runner=lambda *a, **k: (0, "/var/lib/docker\n", ""),
                        driver=FakeDriver)
    monkeypatch.setattr(qual, "read_environment", lambda: {
        "clause": "8(e)",
        "filesystems": [{"path": "/", "free_gib": free_gib, "total_gib": 77.0}],
        "docker_root": "/var/lib/docker", "load1": load1, "load1_error": "",
        "max_load1": 6.0, "min_free_gib": 10.0, "nproc": 4, "mem_total_kib": 1})
    return qual


def test_environment_refuses_an_unquiet_host(monkeypatch, tmp_path):
    qual = _env_qualifier(monkeypatch, tmp_path, 3.4, 22.0, allow_unquiet=False)
    assert qual.stage_environment() == rq.INVALID
    assert qual.qualification_grade is True   # never reached "graded but bad"
    assert len(qual.records[0]["evidence"]["violations"]) == 2


def test_allow_unquiet_downgrades_to_a_recorded_warn(monkeypatch, tmp_path):
    """The result is not blocked, but it is not qualification evidence either."""
    qual = _env_qualifier(monkeypatch, tmp_path, 3.4, 22.0, allow_unquiet=True)
    assert qual.stage_environment() == rq.PASS
    record = qual.records[0]
    assert record["warn"] is True
    assert record["evidence"]["verdict"] == "WARN"
    assert record["evidence"]["downgraded_by"] == "--allow-unquiet"
    assert qual.qualification_grade is False


def test_quiet_host_passes_without_the_override(monkeypatch, tmp_path):
    qual = _env_qualifier(monkeypatch, tmp_path, 11.0, 2.9, allow_unquiet=False)
    assert qual.stage_environment() == rq.PASS
    assert "warn" not in qual.records[0]
    assert qual.qualification_grade is True


# ---------------------------------------------------------------------------
# three-valued verdict
# ---------------------------------------------------------------------------
def test_skipped_never_fails_the_run():
    records = [{"status": rq.PASS}, {"status": rq.SKIPPED}, {"status": rq.PASS}]
    assert rq.overall_verdict(records) == rq.PASS


def test_invalid_beats_fail():
    records = [{"status": rq.PASS}, {"status": rq.FAIL}, {"status": rq.INVALID}]
    assert rq.overall_verdict(records) == rq.INVALID


def test_a_single_fail_fails_the_run():
    assert rq.overall_verdict([{"status": rq.PASS},
                               {"status": rq.FAIL}]) == rq.FAIL


def test_all_skipped_is_invalid_never_pass():
    """Measuring nothing is not passing."""
    assert rq.overall_verdict([{"status": rq.SKIPPED}] * 3) == rq.INVALID
    assert rq.overall_verdict([]) == rq.INVALID


def test_environment_invalid_short_circuits_and_exits_2(monkeypatch, tmp_path):
    """No pytest, no docker, no leg after an environment refusal — and the
    record is still written, because an INVALID that leaves no artifact is
    indistinguishable from a run that never happened."""
    args = make_args(run_dir=str(tmp_path / "q"), allow_unquiet=False)
    qual = rq.Qualifier(args, runner=lambda *a, **k: (0, "", ""), driver=FakeDriver)
    monkeypatch.setattr(qual, "read_environment", lambda: {
        "filesystems": [{"path": "/", "free_gib": 1.0, "total_gib": 77.0}],
        "docker_root": "/", "load1": 1.0, "load1_error": "", "max_load1": 6.0,
        "min_free_gib": 10.0, "nproc": 4, "mem_total_kib": 1})
    for name in ("stage_pins", "stage_candidate", "stage_leg"):
        monkeypatch.setattr(qual, name, lambda *_: pytest.fail(
            "a stage ran after the environment refusal"))
    assert qual.execute() == 2
    doc = json.loads((tmp_path / "q" / "qualification.json").read_text())
    assert doc["verdict"] == rq.INVALID
    assert [s["stage"] for s in doc["stages"]] == ["environment"]


def test_stage_order_is_the_v1_order(monkeypatch, tmp_path):
    args = make_args(run_dir=str(tmp_path / "q"), allow_unquiet=True)
    qual = rq.Qualifier(args, runner=lambda *a, **k: (0, "", ""), driver=FakeDriver)
    monkeypatch.setattr(qual, "read_environment", lambda: {
        "filesystems": [{"path": "/", "free_gib": 99.0, "total_gib": 100.0}],
        "docker_root": "/", "load1": 1.0, "load1_error": "", "max_load1": 6.0,
        "min_free_gib": 10.0, "nproc": 4, "mem_total_kib": 1})
    def stub(stage_name: str):
        def _run() -> str:
            return qual.record(stage_name, rq.PASS, {})
        return _run

    for name in ("stage_pins", "stage_candidate", "stage_leg", "stage_accuracy",
                 "stage_aggregation", "stage_ttur", "stage_baseline"):
        monkeypatch.setattr(qual, name, stub(name[len("stage_"):]))
    qual.execute()
    assert [r["stage"] for r in qual.records] == [
        "environment", "pins", "candidate", "leg", "accuracy", "aggregation",
        "ttur", "rebalance", "baseline"]


def test_red_digest_pins_stop_before_the_hour_long_leg(monkeypatch, tmp_path):
    """A moved scenario/profile re-bases every recorded number, so a leg run
    against it would produce numbers that mean nothing (V1 section 3)."""
    args = make_args(run_dir=str(tmp_path / "q"), allow_unquiet=True)
    qual = rq.Qualifier(args, runner=lambda *a, **k: (1, "", "1 failed"),
                        driver=FakeDriver)
    monkeypatch.setattr(qual, "read_environment", lambda: {
        "filesystems": [{"path": "/", "free_gib": 99.0, "total_gib": 100.0}],
        "docker_root": "/", "load1": 1.0, "load1_error": "", "max_load1": 6.0,
        "min_free_gib": 10.0, "nproc": 4, "mem_total_kib": 1})
    monkeypatch.setattr(qual, "stage_candidate",
                        lambda: qual.record("candidate", rq.PASS, {}))
    monkeypatch.setattr(qual, "stage_leg", lambda: pytest.fail(
        "the leg ran with red digest pins"))
    assert qual.execute() == 1
    assert qual.status_of("pins") == rq.FAIL


# ---------------------------------------------------------------------------
# accuracy — V1 sections 4 + 5
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("accuracy,expected", [
    (0.9299, rq.FAIL),
    (0.93, rq.PASS),        # the boundary is INCLUSIVE (">= 93 %")
    (0.9301, rq.PASS),
    (1.0, rq.PASS),
])
def test_accuracy_boundary_at_0_93(accuracy, expected):
    status, ev = rq.grade_accuracy({"scorer_version": 2, "accuracy_slo": accuracy,
                                    "stories_passed": 1, "stories_total": 1})
    assert status == expected
    assert ev["accuracy"] == accuracy


def test_scorer_v1_fails_even_at_a_perfect_score():
    status, ev = rq.grade_accuracy({"scorer_version": 1, "accuracy_slo": 1.0,
                                    "stories_passed": 345, "stories_total": 345})
    assert status == rq.FAIL
    assert "scorer_version" in ev["reason"]


def test_missing_accuracy_is_a_fail_not_a_pass():
    status, _ = rq.grade_accuracy({"scorer_version": 2})
    assert status == rq.FAIL


# ---------------------------------------------------------------------------
# aggregation — V1 section 7, on the DELTA
# ---------------------------------------------------------------------------
def test_delta_accounting_closes_exactly():
    pre = counters(observed=100, first=60, repeat=10, suppressed=30)
    post = counters(observed=300, first=160, repeat=20, suppressed=120)
    out = rq.agg_delta(pre, post)
    assert out["status"] == rq.PASS
    assert out["observed"] == 200
    assert out["forwarded_total"] == 110
    assert out["suppressed"] == 90
    assert out["exact"] is True
    assert out["suppressed_share"] == 45.0


def test_delta_that_does_not_close_is_a_fail():
    pre = counters(observed=100, first=60, repeat=10, suppressed=30)
    post = counters(observed=301, first=160, repeat=20, suppressed=120)
    out = rq.agg_delta(pre, post)
    assert out["status"] == rq.FAIL
    assert "V1 section 7 requires exactness" in out["reason"]


def test_a_replica_restarted_mid_run_is_invalid_not_a_false_pass():
    """Counters reset on restart, so post-minus-pre is not a delta. A coincidental
    balance must never be reported as a PASS."""
    pre = counters(observed=1000, first=600, repeat=100, suppressed=300,
                   started_at="2026-09-01T19:31:12Z")
    post = counters(observed=100, first=60, repeat=10, suppressed=30,
                    started_at="2026-09-01T21:05:00Z")
    out = rq.agg_delta(pre, post)
    assert out["status"] == rq.INVALID
    assert "restarted mid-run" in out["reason"]


def test_a_counter_going_backwards_on_a_live_container_is_invalid():
    pre = counters(observed=1000, first=600, repeat=100, suppressed=300)
    post = counters(observed=900, first=600, repeat=100, suppressed=300)
    out = rq.agg_delta(pre, post)
    assert out["status"] == rq.INVALID
    assert "BACKWARDS" in out["reason"]


def test_a_disappearing_forwarded_class_is_invalid_not_a_silent_sum():
    pre = counters(observed=100, first=60, repeat=10, suppressed=30)
    post = {"observed": 300.0, "suppressed": 120.0, "forwarded_total": 160.0,
            "forwarded_by_class": {"first": 160.0}, "started_at": "T0"}
    out = rq.agg_delta(pre, post)
    assert out["status"] == rq.INVALID
    assert "class set changed" in out["reason"]


def test_agg_counters_reads_labelled_and_unlabelled_samples():
    got = rq.agg_counters(METRICS_ON, FakeDriver.prom_value)
    assert got["observed"] == 100.0
    assert got["suppressed"] == 30.0
    assert got["forwarded_by_class"] == {"first": 60.0, "repeat": 10.0}
    assert got["forwarded_total"] == 70.0


def test_aggregation_without_a_pre_run_capture_is_skipped_not_failed(tmp_path):
    """Grading a historical leg has no pre-run counters. That is 'not measured',
    which is SKIPPED — the baseline's cumulative numbers are display only."""
    args = make_args(run_dir=str(tmp_path), skip_leg=str(FIXTURE))
    qual = rq.Qualifier(args, runner=lambda *a, **k: pytest.fail("touched docker"),
                        driver=FakeDriver)
    assert qual.stage_aggregation() == rq.SKIPPED
    ev = qual.records[0]["evidence"]
    assert ev["baseline_display_only"] is True
    assert ev["per_leg_observed_expected"] == 54767


# ---------------------------------------------------------------------------
# harness phases — V1 section 8(a)
# ---------------------------------------------------------------------------
def test_all_nine_phases_must_be_present_and_green():
    report = {"runid": "x", "overall": "PASS",
              "phases": [{"phase": name, "status": "PASS"} for name in rq.V1_PHASES]}
    status, ev = rq.grade_phases(report)
    assert status == rq.PASS
    assert ev["phases_passed"] == 9 and ev["phases_total"] == 9


def test_a_missing_phase_is_invalid_not_a_pass():
    report = {"runid": "x", "phases": [{"phase": n, "status": "PASS"}
                                       for n in rq.V1_PHASES[:8]]}
    status, ev = rq.grade_phases(report)
    assert status == rq.INVALID
    assert ev["missing_phases"] == ["cleanup"]


def test_a_failed_phase_fails_the_leg():
    phases = [{"phase": n, "status": "PASS"} for n in rq.V1_PHASES]
    phases[1]["status"] = "FAIL"
    status, ev = rq.grade_phases({"runid": "x", "phases": phases})
    assert status == rq.FAIL and ev["failed_phases"] == ["onboard"]


# ---------------------------------------------------------------------------
# baseline extraction
# ---------------------------------------------------------------------------
def _fake_docker(cmd, timeout, cwd=None):
    if cmd[:2] == ["docker", "inspect"]:
        return 0, "sha256:23dc2b88e966f000988a9d04be1f88d385b6aa9866045d\n", ""
    return 127, "", "unexpected command in a unit test"


def test_baseline_extraction_is_deterministic_and_byte_stable():
    first = rq.dump_baseline(rq.extract_baseline(str(FIXTURE), runner=_fake_docker,
                                                 driver=FakeDriver))
    second = rq.dump_baseline(rq.extract_baseline(str(FIXTURE), runner=_fake_docker,
                                                  driver=FakeDriver))
    assert first == second
    doc = json.loads(first)
    assert doc["runid"] == "090121382mk4"
    assert doc["workload"]["seed"] == 20260829
    assert doc["accuracy"] == {"accuracy": 1.0, "detection_rate": 1.0,
                               "scorer_version": 2, "specificity": 1.0,
                               "stories_passed": 345, "stories_total": 345}
    assert doc["phases"] == {name: "PASS" for name in rq.V1_PHASES}
    assert doc["harness"]["injected_total"] == 900001
    assert doc["harness"]["dlq_run_lines"] == 0
    assert doc["t1"]["p95_s"] == "876"
    # V1 section 7: the s11 counters are CUMULATIVE across s10+s11 and the
    # baseline must SAY so rather than present them as a per-leg count.
    assert doc["aggregation"]["scope"] == "cumulative_s10_s11"
    assert doc["aggregation"]["observed"] == 109534.0
    assert doc["aggregation"]["exact"] is True
    assert doc["aggregation"]["per_leg_observed_expected"] == 54767
    assert doc["leg"] == "storm-s11"


def test_baseline_records_the_container_identities_from_the_run_dir():
    doc = rq.extract_baseline(str(FIXTURE), runner=_fake_docker, driver=FakeDriver)
    names = [entry["name"] for entry in doc["images"]["correlation"]]
    assert names == ["netops-correlation-6", "netops-correlation-7"]
    assert all(e["image"] == "23dc2b88e966" for e in doc["images"]["correlation"])
    # The api image is NOT recoverable from a run dir; the baseline says so
    # instead of stamping today's image onto a historical leg.
    assert doc["images"]["api"]["image"] is None


def test_baseline_reports_an_absent_container_instead_of_inventing_an_image():
    def gone(cmd, timeout, cwd=None):
        return 1, "", "Error: No such object: e5cd469c9e6f\n"
    doc = rq.extract_baseline(str(FIXTURE), runner=gone, driver=FakeDriver)
    entry = doc["images"]["correlation"][0]
    assert entry["image"] is None and "No such object" in entry["error"]


def test_the_checked_in_baseline_matches_a_fresh_extraction():
    """The checked-in file is generated, never hand-typed."""
    checked_in = json.loads((ROOT / "docs" / "scale" / "baselines" /
                             "storm-s11.v1.json").read_text())
    fresh = rq.extract_baseline(str(FIXTURE), runner=_fake_docker, driver=FakeDriver)
    for key in ("runid", "workload", "phases", "overall", "accuracy", "t1"):
        assert checked_in[key] == fresh[key], key
    assert checked_in["harness"] == fresh["harness"]
    assert checked_in["aggregation"] == fresh["aggregation"]


def test_ttur_row_parsing_refuses_an_empty_scope():
    with pytest.raises(rq.QualifyError):
        rq.parse_ttur_tsv("inc\tversions\n")
    row = rq.parse_ttur_tsv((FIXTURE / "ttur.tsv").read_text())
    assert row["t1p50"] == "80" and row["t1p95"] == "876"


def test_metrics_final_splits_by_replica():
    bodies = rq.split_metrics_by_replica((FIXTURE / "metrics-final.txt").read_text())
    assert set(bodies) == {"03e7111d6c71", "e5cd469c9e6f"}
    carrier = rq.agg_counters(bodies["e5cd469c9e6f"], FakeDriver.prom_value)
    idle = rq.agg_counters(bodies["03e7111d6c71"], FakeDriver.prom_value)
    assert carrier["observed"] == 109534.0 and idle["observed"] == 0.0
    assert (carrier["forwarded_total"] + carrier["suppressed"]
            == carrier["observed"])


# ---------------------------------------------------------------------------
# --skip-leg: re-grading the real storm-s11 artifacts
# ---------------------------------------------------------------------------
def _skip_leg_qualifier(tmp_path):
    leg = tmp_path / "storm-s11-09012138"
    shutil.copytree(FIXTURE, leg)
    baseline = tmp_path / "storm-s11.v1.json"
    baseline.write_text(rq.dump_baseline(
        rq.extract_baseline(str(leg), runner=_fake_docker, driver=FakeDriver)))
    run_dir = tmp_path / "qualify"
    run_dir.mkdir()
    args = make_args(run_dir=str(run_dir), skip_leg=str(leg),
                     baseline=str(baseline), allow_unquiet=True)
    qual = rq.Qualifier(args, runner=_fake_docker, driver=FakeDriver)
    return qual, leg, run_dir


def test_skip_leg_reproduces_storm_s11(tmp_path):
    """9/9 harness gates, 345/345 on scorer v2, the V1 section 9 T1 numbers."""
    qual, _leg, run_dir = _skip_leg_qualifier(tmp_path)
    assert qual.stage_leg() == rq.PASS
    leg_ev = qual.records[-1]["evidence"]
    assert (leg_ev["phases_passed"], leg_ev["phases_total"]) == (9, 9)
    assert leg_ev["runid"] == "090121382mk4"

    assert qual.stage_accuracy() == rq.PASS
    acc = qual.records[-1]["evidence"]
    assert (acc["stories_passed"], acc["stories_total"]) == (345, 345)
    assert acc["scorer_version"] == 2

    assert qual.stage_aggregation() == rq.SKIPPED
    assert qual.stage_ttur() == rq.PASS
    assert qual.records[-1]["evidence"]["row"]["t1p95"] == "876"
    assert qual.stage_rebalance() == rq.SKIPPED
    assert qual.stage_baseline() == rq.PASS
    assert qual.records[-1]["evidence"]["gated_regressions"] == []

    qual.candidate = {"correlation": [{"image": "23dc2b88e966"}],
                      "api": {"image": "f6c67a4d0195"}}
    assert qual.stage_verdict() == rq.PASS
    doc = json.loads((run_dir / "qualification.json").read_text())
    assert doc["verdict"] == rq.PASS
    assert doc["qualification_grade"] is True
    assert [s["stage"] for s in doc["stages"]][-1] == "baseline"
    md = (run_dir / "qualification.md").read_text()
    assert "p95 **876 s**" in md
    assert "NOT a pass/fail gate" in md      # T1 is published, never gated


def test_skip_leg_never_rescores_or_requeries(tmp_path):
    """A re-grade must not touch the stack: the leg's own cleanup purged its
    ClickHouse corpus, so a fresh scorer pass would measure an empty store."""
    qual, _leg, _ = _skip_leg_qualifier(tmp_path)
    qual.runner = lambda *a, **k: pytest.fail("a re-grade shelled out")
    qual.stage_leg()
    assert qual.stage_accuracy() == rq.PASS
    assert "existing accuracy-report.json" in qual.records[-1]["evidence"]["source"]
    assert qual.stage_ttur() == rq.PASS
    assert "existing ttur.tsv" in qual.records[-1]["evidence"]["source"]


def test_a_regressed_gate_against_the_baseline_fails(tmp_path):
    qual, leg, _ = _skip_leg_qualifier(tmp_path)
    report = json.loads((leg / "report.json").read_text())
    for phase in report["phases"]:
        if phase["phase"] == "memflat":
            phase["status"] = "FAIL"
    (leg / "report.json").write_text(json.dumps(report))
    assert qual.stage_leg() == rq.FAIL
    qual.stage_accuracy()
    assert qual.stage_baseline() == rq.FAIL
    regressions = qual.records[-1]["evidence"]["gated_regressions"]
    assert [r["clause"] for r in regressions] == ["harness gate `memflat`"]


def test_informational_rows_report_a_regression_without_gating_it():
    rows = rq.informational_rows(
        {"completion_s": 200.0, "t1_p95": 1400.0, "accuracy": 1.0, "memory": {}},
        {"completion_s": 94.8, "t1_p95": 876.0, "accuracy": 1.0, "memory": {}})
    by = {r["metric"]: r for r in rows}
    assert "REGRESSION (informational)" in by["engine completion"]["note"]
    assert "REGRESSION (informational)" in \
        by["T1 p95 (published, not gated)"]["note"]
    assert by["accuracy"]["note"] == "+0.0%"


# ---------------------------------------------------------------------------
# misc contracts
# ---------------------------------------------------------------------------
def test_leg_argv_carries_only_the_frozen_v1_parameters(tmp_path, monkeypatch):
    """No tuning flags: the harness defaults ARE the V1 gates, so an extra flag
    here would silently re-base the qualification (a V2, not a V1 rerun)."""
    seen = {}

    def streamer(argv, log_path, timeout, cwd):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return 0, "completed"

    args = make_args(run_dir=str(tmp_path))
    qual = rq.Qualifier(args, runner=lambda *a, **k: (0, "", ""),
                        driver=FakeDriver, streamer=streamer)
    qual.stage_leg()
    argv = seen["argv"]
    assert argv[1].endswith("scale-miniladder.py")
    assert argv[2:] == ["--profile", "t-storm-2.5k", "--devices", "2500",
                        "--eps", "1000", "--run-dir", str(tmp_path)]
    assert seen["timeout"] >= 4 * 3600


def test_short_image_matches_the_form_v1_quotes():
    assert rq.short_image("sha256:23dc2b88e966f000988a9d04be") == "23dc2b88e966"
    assert rq.short_image("") == ""


def test_leg_label_strips_the_run_dir_stamp():
    assert rq.leg_label("/var/tmp/scale-runs/storm-s11-09012138") == "storm-s11"
    assert rq.leg_label("/x/qualify") == "qualify"


def test_rebalance_is_skipped_with_the_reason_recorded(tmp_path):
    qual = rq.Qualifier(make_args(run_dir=str(tmp_path)),
                        runner=lambda *a, **k: (0, "", ""), driver=FakeDriver)
    assert qual.stage_rebalance() == rq.SKIPPED
    reason = qual.records[0]["evidence"]["reason"]
    assert "OWNERSHIP_155_VALIDATION" in reason
    assert "no CLI" in reason
    assert qual.records[0]["evidence"]["graded_elsewhere"] == "leg.phases.stability"


# ---------------------------------------------------------------------------
# the self-test — the suite proving its own logic where the rig does not exist
# ---------------------------------------------------------------------------
# A qualification leg is an hour of owner-gated rig time, so between legs
# NOTHING would catch a change that broke this grader. `--self-test` re-grades
# the checked-in storm-s11 leg fixture and mutations of it; these tests are the
# CI hook for it, and — critically — the proof that it is not vacuous.
def _self_test_args(tmp_path, **over):
    kwargs = {"run_dir": str(tmp_path / "unused"),
              "baseline": str(ROOT / "docs" / "scale" / "baselines" /
                              "storm-s11.v1.json")}
    kwargs.update(over)
    return make_args(**kwargs)


def test_the_self_test_passes_with_no_stack_no_rig_no_env(tmp_path, capsys):
    assert rq.self_test(_self_test_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "SELF-TEST PASS" in out
    # the grader's own [FAIL] lines belong to the MUTATION checks; a failed
    # self-test CHECK is the two-space-indented form.
    assert "\n  [FAIL]" not in out
    assert "not qualification evidence" in out


def test_the_self_test_is_not_vacuous(tmp_path, monkeypatch):
    """A grader that has stopped detecting an accuracy miss must FAIL the
    self-test. Without this, a green self-test would prove nothing."""
    monkeypatch.setattr(rq, "grade_accuracy",
                        lambda report: (rq.PASS, {"scorer_version": 2}))
    assert rq.self_test(_self_test_args(tmp_path)) == 1


def test_the_self_test_writes_nothing_outside_its_temp_dir(tmp_path):
    """It must not create the default /var/tmp run dir, touch the repo, or
    leave a temp tree behind."""
    seen: list[str] = []
    real = rq.tempfile.TemporaryDirectory

    class Recording(real):                      # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            seen.append(self.name)

    rq.tempfile.TemporaryDirectory = Recording
    try:
        args = _self_test_args(tmp_path, run_dir="/var/tmp/scale-runs/should-not-exist")
        assert rq.self_test(args) == 0
    finally:
        rq.tempfile.TemporaryDirectory = real
    assert seen and not any(os.path.exists(path) for path in seen)
    assert not os.path.exists("/var/tmp/scale-runs/should-not-exist")


def test_a_missing_fixture_is_a_usage_error_never_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(rq, "SELF_TEST_FIXTURE", str(tmp_path / "gone"))
    assert rq.self_test(_self_test_args(tmp_path)) == 2


def test_the_self_test_needs_no_env_file():
    """`.env` is generated at install and gitignored — CI has none, and the
    suite's own proof must not depend on one."""
    args = rq.parse_args(["--self-test", "--env-file", "/nonexistent/.env"])
    assert args.self_test is True
    assert args.project == "self-test"


def test_the_self_test_is_not_a_leg_job():
    for extra in (["--dry-run"], ["--skip-leg", "/tmp"],
                  ["--extract-baseline", "/tmp"]):
        with pytest.raises(SystemExit):
            rq.parse_args(["--self-test"] + extra)


def test_main_routes_self_test_before_anything_touches_a_stack(monkeypatch):
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))   # restored on teardown
    calls: list[str] = []
    monkeypatch.setattr(rq, "self_test", lambda args: calls.append("ran") or 0)
    monkeypatch.setattr(rq, "Qualifier", lambda *a, **k: pytest.fail(
        "a self-test must never build a Qualifier against a stack"))
    assert rq.main(["--self-test"]) == 0
    assert calls == ["ran"]


def test_the_report_grades_every_clause_against_the_v1_reference(tmp_path):
    """The dated report must SHOW the per-clause comparison, not just carry it
    in the JSON: that table is what a release decision is read off."""
    qual, _leg, run_dir = _skip_leg_qualifier(tmp_path)
    qual.stage_leg()
    qual.stage_accuracy()
    qual.stage_baseline()
    qual.candidate = {"correlation": [{"image": "23dc2b88e966"}],
                      "api": {"image": "f6c67a4d0195"}}
    qual.stage_verdict()
    md = (run_dir / "qualification.md").read_text()
    assert "Gated clauses vs the V1 reference" in md
    for phase in rq.V1_PHASES:
        assert f"harness gate `{phase}`" in md
    assert "accuracy >= 0.93 on scorer v2" in md
    assert "Generated:" in md
