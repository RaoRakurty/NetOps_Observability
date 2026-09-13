# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""memflat judges VictoriaMetrics on TWO end samples, not on warm->end (#308).

THE FALSE FAIL THIS PINS. Nightly 33727173163 (2026-09-03):

    [FAIL] memflat — netops-victoria-1: LEAK SLOPE (cgroup_anon)
           195 -> 259 MiB (x1.33 > x1.3) after input stopped

Refuted from the ten surviving run artifacts (2026-09-13):

  * the end state is the whole claim and it is unremarkable — 259.2 MiB =
    16.3 % of the 1,587 MiB cap, and THREE PASSING runs ended holding MORE
    (278.7 / 284.5 / 286.1 MiB);
  * the nine prior runs' warm->end ratio is 0.942 / 0.982 / 1.011 / 1.042 /
    1.067 / 1.104 / 1.125 / 1.168 / 1.198 — mean 1.071, sd 0.081 — so x1.3 sits
    ~2.8 sd out on a 9-sample base, INSIDE VictoriaMetrics' own spread;
  * what moved was the ANCHOR: that run's cold sample (172.4 MiB) was the
    LOWEST of the ten and its warm (194.6 MiB) the second lowest. It started
    light, converged to a mid-range steady state, and the ratio read
    convergence as slope — clearing both guards by a hair (x1.3322 vs x1.30,
    64.641 MiB vs the 64 MiB absolute floor).

WHY warm->end CANNOT ASK THE QUESTION HERE. VictoriaMetrics' working set
materializes AFTER input stops: background part merges plus the harness's own
post-burst query storm populate its tsid / metricName / index-block caches,
which are anon and are not reclaimed. This is the THIRD service in that class —
ClickHouse (docker_stats -> cgroup_anon) and correlation (the `pending==0`
anchor) were fixed the same way, by replacing the anchor rather than widening
`--mem-factor`, which would buy one quiet run and blind every other service.

THE CLAUSE THIS FILE GUARDS:

    end1   the ordinary end sample, cgroup anon, input stopped
    quiet  VM_MEM_QUIET_S (90 s) of silence — no injection, and memflat itself
           touches nothing on VM inside it
    end2   a second cgroup anon sample
    slope  end2/end1 vs VM_MEM_QUIET_FACTOR (x1.05) AND a 64 MiB-per-120 s
           floor scaled to the interval (48 MiB over the default 90 s)

A materialized cache is flat across that interval; a leak keeps climbing. No
second sample, or a short one, is UNKNOWN — never PASS, and never a LEAK
verdict either, because accusing VM of leaking on evidence that cannot separate
a leak from a materialization is the defect itself. The offline
`--rescore-memflat` path obeys the same rule: it cannot reconstruct a quiet
interval, so a report without the second sample re-scores UNKNOWN.

Run:  python3 -m pytest tests/test_miniladder_memflat_victoria.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_harness():
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location(
        "scale_miniladder_memflat_vm", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_memflat_vm"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()

MIB = 1024 ** 2
VM = "netops-victoria-1"

# ── run 33727173163, VERBATIM ───────────────────────────────────────────────
# cgroup anon at preflight / end of burst / end of run, and the container cap.
# The MiB figures are the ones in the tracker row; the gate's own line rounds
# them to 195 -> 259.
COLD_MIB = 172.4
WARM_MIB = 194.6
END_MIB = 259.2
CAP_MIB = 1587
# docker stats for the same container: page-cache-inflated, reported, never
# judged (the 2026-08-29 instrument split).
DOCKER_END_MIB = 1100.0


def _b(mib_value: float) -> int:
    return int(mib_value * MIB)


class FakeClock:
    """Virtual clock: the 90 s quiet interval must not cost a test 90 s."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept += seconds
        self.t += seconds


def _refusing_ch(query, timeout=60):
    """ClickHouse is NOT in MEM_SERVICES for these tests, so any probe against
    it is a bug in the phase, not a fixture gap."""
    raise AssertionError(f"memflat probed ClickHouse for a victoria-only "
                         f"run: {query[:120]}")


def _harness(tmp_path, monkeypatch, *, second, cold=COLD_MIB, warm=WARM_MIB,
             end=END_MIB, limit_mib=CAP_MIB, services=("victoria",), **flags):
    """A memflat harness with TWO successive cgroup anon samples for VM.

    `second` is the MiB figure the second (post-quiet) sample returns; None
    means the sample could not be taken at all (memory.stat unreadable), which
    the harness records as -1 and the clause must report as UNKNOWN.
    """
    monkeypatch.setattr(ml, "MEM_SERVICES", list(services))
    clock = FakeClock()
    monkeypatch.setattr(ml, "time", clock)
    argv = ["--run-dir", str(tmp_path)]
    for k, v in flags.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    args = ml.parse_args(argv)
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    stats = {VM: {"used": _b(DOCKER_END_MIB), "limit": _b(limit_mib)}}
    h.stack.mem_stats = lambda: stats                # type: ignore[assignment]
    h.stack.ch = _refusing_ch                        # type: ignore[assignment]
    samples = [{VM: _b(end)},
               {VM: -1 if second is None else _b(second)}]

    def anon_sample(services_asked):
        return dict(samples.pop(0)) if samples else {}

    h.stack.anon_sample = anon_sample                # type: ignore[assignment]
    h.baseline["mem"] = {VM: _b(DOCKER_END_MIB)}
    h.baseline["mem_anon"] = {VM: _b(cold)}
    h.warm_mem = {VM: _b(DOCKER_END_MIB)}
    h.warm_anon = {VM: _b(warm)}
    h.burst_seconds = 120.0
    h.corr_mem_track = {}
    h.clock = clock                                  # type: ignore[attr-defined]
    return h


def _row(h):
    rows = h.phases[-1]["evidence"]["containers"]
    assert len(rows) == 1, rows
    return rows[0]


# ── (a) the run that false-failed, with a flat second sample: PASS ──────────

def test_33727173163_passes_once_the_second_end_sample_is_flat(
        tmp_path, monkeypatch):
    """THE RUN THIS CLAUSE WAS BUILT FOR. Same three numbers the nightly saw;
    the quiet interval shows the 259 MiB is a materialized cache, not a slope.

    Against the UNFIXED judge this is the red: warm->end is x1.3322 with a
    64.641 MiB delta, which clears x1.30 and the 64 MiB floor by a hair.
    """
    h = _harness(tmp_path, monkeypatch, second=END_MIB + 0.2)
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE" not in notes
    row = _row(h)
    assert row["instrument"] == "cgroup_anon"
    assert row["anchor"] == "post-burst quiet interval"
    assert row["verdict"] == "FLAT"
    # The judged slope is across the quiet interval, and it is ~1.0.
    assert row["ratio_vs_anchor"] == pytest.approx(1.001, abs=0.002)
    assert row["quiet_interval_s"] == ml.VM_MEM_QUIET_S
    assert row["quiet_waited_s"] == pytest.approx(ml.VM_MEM_QUIET_S, abs=0.1)
    # The x1.33 that failed the nightly is EVIDENCE, and explicitly unjudged.
    assert row["ratio_warm_to_end_unjudged"] == pytest.approx(1.332, abs=0.002)
    # And the end state the refutation turns on: 16.3 % of the cap.
    assert row["pct_of_limit"] == pytest.approx(16.3, abs=0.1)
    # Page-cache-bearing docker stats: reported, never judged.
    assert row["docker_stats_end_bytes"] == _b(DOCKER_END_MIB)
    assert "victoria netops-victoria-1 anon 195 MiB at input stop -> 259 MiB "\
           "end -> 259 MiB after 90s quiet" in notes
    assert "FLAT)" in notes
    # The wait was real (virtual clock), i.e. the interval is not a no-op.
    assert h.clock.slept == pytest.approx(ml.VM_MEM_QUIET_S, abs=0.1)
    quiet = h.phases[-1]["evidence"]["victoria_quiet"]
    assert quiet["second_sample"] is True
    assert quiet["floor_bytes"] == pytest.approx(48 * MIB, rel=1e-6)


def test_MUTANT_the_generic_warm_to_end_clause_calls_that_run_a_leak(
        tmp_path, monkeypatch):
    """THE MUTANT / the red-before, pinned. Send the SAME numbers through the
    generic clause — the one every other service still uses — and the nightly's
    exact FAIL line comes back. That is what makes the VM anchor load-bearing
    rather than decorative."""
    h = _harness(tmp_path, monkeypatch, second=END_MIB + 0.2)
    monkeypatch.setattr(ml, "VM_MEM_SERVICE", "not-a-service")
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE (cgroup_anon) 195 -> 259 MiB (x1.33 > x1.3)" in notes
    assert "after input stopped" in notes


def test_the_three_passing_runs_that_ended_holding_more_still_pass(
        tmp_path, monkeypatch):
    """278.7 / 284.5 / 286.1 MiB are the end states of runs the gate PASSED.
    A clause that fails 259.2 while passing those is not measuring memory."""
    for end_mib in (278.7, 284.5, 286.1):
        h = _harness(tmp_path, monkeypatch, end=end_mib,
                     second=end_mib + 0.4)
        assert h.memflat() is True, (end_mib, h.phases[-1]["notes"])
        assert _row(h)["verdict"] == "FLAT"


# ── (b) still climbing across the quiet interval: FAIL ──────────────────────

def test_growth_across_the_quiet_interval_is_a_leak(tmp_path, monkeypatch):
    """The invariant the phase exists for. Nothing is arriving, nothing is
    being queried, and it is still allocating: +71 MiB in 90 s = ~2.8 GiB/h
    against a 1,587 MiB cap."""
    h = _harness(tmp_path, monkeypatch, second=330.0)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert ("LEAK SLOPE (cgroup_anon, anchored on the post-burst quiet "
            "interval) 259 -> 330 MiB") in notes
    assert "x1.27 > x1.05" in notes
    assert "+71 MiB > the 48 MiB floor for this interval" in notes
    assert "over 90s of QUIET" in notes
    assert _row(h)["verdict"] == "LEAK"


def test_a_climb_inside_the_scaled_floor_is_not_a_leak(tmp_path, monkeypatch):
    """The floor, not the ratio, is what keeps a tight factor off jitter:
    +40 MiB is x1.154 — past x1.05 — and still under the 48 MiB the interval
    allows. Both guards must fire, exactly as in the generic clause."""
    h = _harness(tmp_path, monkeypatch, second=END_MIB + 40)
    assert h.memflat() is True, h.phases[-1]["notes"]
    row = _row(h)
    assert row["verdict"] == "FLAT"
    assert row["ratio_vs_anchor"] == pytest.approx(1.154, abs=0.002)


def test_the_floor_travels_with_the_interval(tmp_path, monkeypatch):
    """Scaled, not a constant: at 240 s of quiet the same clause allows
    128 MiB, and the +40 MiB above would be nowhere near it."""
    assert ml.vm_quiet_floor_bytes(90) == pytest.approx(48 * MIB, rel=1e-6)
    assert ml.vm_quiet_floor_bytes(240) == pytest.approx(128 * MIB, rel=1e-6)
    # ...and it is CLAMPED, so a misconfigured short interval cannot make the
    # clause hair-trigger on a page of jitter.
    assert ml.vm_quiet_floor_bytes(1) == pytest.approx(32 * MIB, rel=1e-6)
    assert ml.vm_quiet_floor_bytes(0) == pytest.approx(32 * MIB, rel=1e-6)
    monkeypatch.setattr(ml, "VM_MEM_QUIET_S", 240.0)
    monkeypatch.setattr(ml, "VM_MEM_QUIET_MAX_S", 480.0)
    h = _harness(tmp_path, monkeypatch, second=END_MIB + 100)
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert _row(h)["quiet_floor_bytes"] == pytest.approx(128 * MIB, rel=1e-6)


def test_the_OOM_clause_is_anchor_independent_and_takes_the_worse_sample(
        tmp_path, monkeypatch):
    """A container at 90 % of its cap is one burst from a kill whatever its
    slope says — and the FIRST end sample counts even when the second dips."""
    h = _harness(tmp_path, monkeypatch, end=1500.0, second=1400.0,
                 limit_mib=CAP_MIB)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "1500 MiB (cgroup_anon) is 94.5% of its 1587 MiB cap" in notes
    assert "one burst from an OOM kill" in notes
    # The slope itself is FLAT: the two verdicts are independent.
    assert _row(h)["verdict"] == "FLAT"


# ── (c) no second sample: UNKNOWN, never PASS and never LEAK ────────────────

def test_a_missing_second_sample_is_UNKNOWN_not_a_pass(tmp_path, monkeypatch):
    h = _harness(tmp_path, monkeypatch, second=None)
    assert h.memflat() is False, "UNKNOWN is not a PASS"
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE UNKNOWN — no SECOND end sample across the 90s quiet" \
        in notes
    assert "cannot separate a cache that materializes after input stops" in notes
    assert "This is NOT judged" in notes
    # NOT an accusation, and the refuted ratio is still only evidence.
    assert "LEAK SLOPE (cgroup_anon, anchored" not in notes
    row = _row(h)
    assert row["verdict"] == "UNKNOWN"
    assert row["anon_end_second"] == -1
    assert row["ratio_warm_to_end_unjudged"] == pytest.approx(1.332, abs=0.002)


def test_a_missing_FIRST_sample_says_so_and_judges_nothing(
        tmp_path, monkeypatch):
    h = _harness(tmp_path, monkeypatch, end=-1 / MIB, second=END_MIB)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "no cgroup_anon end sample" in notes
    assert "docker stats cannot substitute for it" in notes
    assert _row(h)["verdict"] == "UNKNOWN"


def test_disabling_the_quiet_interval_yields_UNKNOWN_not_silence(
        tmp_path, monkeypatch):
    """MLX_VM_MEM_QUIET_S=0 is the explicit opt-out. It must cost the clause its
    verdict, loudly — not hand back a pass on the ratio it replaced."""
    monkeypatch.setattr(ml, "VM_MEM_QUIET_S", 0.0)
    h = _harness(tmp_path, monkeypatch, second=END_MIB)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE UNKNOWN — no SECOND end sample" in notes
    assert "the quiet interval is DISABLED" in notes
    assert h.clock.slept == 0.0
    assert h.phases[-1]["evidence"]["victoria_quiet"]["second_sample"] is False


def test_an_interval_cut_short_by_its_budget_is_UNKNOWN(tmp_path, monkeypatch):
    """The wait is bounded (§9). A budget that fires means the interval was not
    the one the clause asks for, so the slope across it is not judged."""
    monkeypatch.setattr(ml, "VM_MEM_QUIET_MAX_S", 30.0)
    h = _harness(tmp_path, monkeypatch, second=END_MIB + 60)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE UNKNOWN — the second end sample is only 30s past the "\
           "first (needs 90s of quiet, budget 30s)" in notes
    assert _row(h)["verdict"] == "UNKNOWN"


def test_no_quiet_interval_is_spent_when_victoria_is_not_judged(
        tmp_path, monkeypatch):
    """A gate must not spend 90 s of wall clock sampling a container this phase
    will not look at."""
    stats = {"netops-api-1": {"used": 200 * MIB, "limit": 789 * MIB}}
    h = _harness(tmp_path, monkeypatch, second=END_MIB, services=("api",))
    h.stack.mem_stats = lambda: stats                # type: ignore[assignment]
    h.baseline["mem"] = {"netops-api-1": 190 * MIB}
    h.warm_mem = {"netops-api-1": 195 * MIB}
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert h.clock.slept == 0.0
    quiet = h.phases[-1]["evidence"]["victoria_quiet"]
    assert quiet["second_sample"] is False
    assert "not in MEM_SERVICES" in quiet["note"]


def test_every_other_service_keeps_the_generic_clause(tmp_path, monkeypatch):
    """One bounded change: opensearch is still judged warm->end on anon, with
    no second sample and no quiet interval of its own."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["opensearch"])
    clock = FakeClock()
    monkeypatch.setattr(ml, "time", clock)
    args = ml.parse_args(["--run-dir", str(tmp_path)])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    name = "netops-opensearch-1"
    stats = {name: {"used": 2200 * MIB, "limit": 4096 * MIB}}
    h.stack.mem_stats = lambda: stats                # type: ignore[assignment]
    h.stack.anon_sample = lambda s: {name: 2200 * MIB}  # type: ignore[assignment]
    h.stack.ch = _refusing_ch                        # type: ignore[assignment]
    h.baseline["mem"] = {name: 900 * MIB}
    h.baseline["mem_anon"] = {name: 900 * MIB}
    h.warm_mem = {name: 1000 * MIB}
    h.warm_anon = {name: 1000 * MIB}
    h.corr_mem_track = {}
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE (cgroup_anon) 1000 -> 2200 MiB (x2.20 > x1.3)" in notes
    assert clock.slept == 0.0
    row = h.phases[-1]["evidence"]["containers"][0]
    assert "anchor" not in row and "end_bytes_second" not in row


# ── (d) the offline re-score: no second sample => UNKNOWN, never PASS ───────

def _ev(rows):
    return {"containers": rows}


def _new_style_row(*, first=END_MIB, second=END_MIB + 0.2, waited=90.0,
                   quiet=90.0):
    return {"container": VM, "service": "victoria",
            "instrument": "cgroup_anon",
            "anchor": "post-burst quiet interval",
            "cold_bytes": _b(COLD_MIB), "warm_bytes": _b(WARM_MIB),
            "end_bytes": _b(first),
            "end_bytes_second": -1 if second is None else _b(second),
            "anon_end": _b(first),
            "anon_end_second": -1 if second is None else _b(second),
            "quiet_interval_s": quiet, "quiet_waited_s": waited,
            "ratio_warm_to_end_unjudged": 1.332,
            "verdict": "FLAT"}


OLD_STYLE_ROW = {
    # Exactly what nightly 33727173163's report.json carries: the generic
    # clause's row, warm-anchored, with no second sample anywhere.
    "container": VM, "service": "victoria", "instrument": "cgroup_anon",
    "cold_bytes": _b(COLD_MIB), "warm_bytes": _b(WARM_MIB),
    "end_bytes": _b(END_MIB), "limit_bytes": _b(CAP_MIB),
    "pct_of_limit": 16.3, "ratio_vs_anchor": 1.332,
    "ratio_cold_to_end": 1.504,
}


def test_rescore_of_a_report_without_the_second_sample_is_UNKNOWN():
    """THE POINT OF (d). A quiet interval cannot be reconstructed after the
    fact, so the old report re-scores UNKNOWN — not PASS, and not the LEAK the
    warm->end ratio it does carry once claimed."""
    ev, problems = ml._rescore_victoria(_ev([OLD_STYLE_ROW]))
    assert ev["source"] == "none"
    assert ev["containers"][VM]["verdict"] == "UNKNOWN"
    assert ev["containers"][VM]["anon_end_second"] == -1
    joined = "; ".join(problems)
    assert "UNKNOWN: this run predates the post-burst quiet interval" in joined
    assert "warm->end ratio in the run's own report is NOT reused" in joined
    assert "LEAK" not in joined
    assert "Re-run to get a judged VictoriaMetrics slope" in joined


def test_rescore_of_a_flat_quiet_interval_passes():
    ev, problems = ml._rescore_victoria(_ev([_new_style_row()]))
    assert problems == []
    assert ev["containers"][VM]["verdict"] == "FLAT"
    assert ev["source"].startswith("memflat evidence")


def test_rescore_of_a_climbing_quiet_interval_is_a_LEAK():
    ev, problems = ml._rescore_victoria(_ev([_new_style_row(second=330.0)]))
    assert ev["containers"][VM]["verdict"] == "LEAK"
    assert any("LEAK SLOPE across the post-burst quiet interval" in p
               for p in problems)


def test_rescore_uses_the_default_factor_not_the_environment():
    """A finished run is judged by the threshold it was judged by — the same
    rule MEM_FACTOR_RESCORE exists for."""
    assert ml.VM_MEM_QUIET_FACTOR_DEFAULT == 1.05
    ev, _ = ml._rescore_victoria(_ev([_new_style_row()]))
    assert ev["factor"] == ml.VM_MEM_QUIET_FACTOR_DEFAULT


def test_rescore_of_a_half_recorded_interval_is_UNKNOWN():
    """The run recorded the interval but lost one of the two samples."""
    ev, problems = ml._rescore_victoria(_ev([_new_style_row(second=None)]))
    assert ev["containers"][VM]["verdict"] == "UNKNOWN"
    assert any("not both end samples" in p for p in problems)
    # ...and one cut short by its budget, likewise.
    ev, problems = ml._rescore_victoria(_ev([_new_style_row(waited=20.0)]))
    assert ev["containers"][VM]["verdict"] == "UNKNOWN"
    assert any("short of the 90s the clause asks for" in p for p in problems)


def test_rescore_of_a_garbled_report_is_UNKNOWN_and_never_a_crash():
    """A saved report is untrusted input like any other (§3): nulls and strings
    where numbers belong must produce UNKNOWN, not a traceback and not a
    plausible-looking zero."""
    row = _new_style_row()
    row.update({"anon_end": None, "anon_end_second": "259.4 MiB",
                "end_bytes": None, "end_bytes_second": None,
                "quiet_waited_s": "ninety"})
    ev, problems = ml._rescore_victoria(_ev([row]))
    assert ev["containers"][VM]["verdict"] == "UNKNOWN"
    assert any("not both end samples" in p for p in problems)


def test_rescore_of_a_report_with_no_victoria_row_at_all_is_UNKNOWN():
    ev, problems = ml._rescore_victoria(_ev([]))
    assert ev["source"] == "none"
    assert any("carries no victoria container at all" in p for p in problems)


def test_rescore_end_to_end_reports_victoria_UNKNOWN_and_exits_nonzero(
        tmp_path, monkeypatch):
    """The wiring, not just the clause: an old run's re-score says UNKNOWN in
    the document and in the exit code, and never touches the run's report."""
    (tmp_path / "report.json").write_text(json.dumps({"phases": [
        {"phase": "memflat", "status": "FAIL",
         "notes": ("netops-victoria-1: LEAK SLOPE (cgroup_anon) 195 -> 259 MiB "
                   "(x1.33 > x1.3) after input stopped"),
         "evidence": {"containers": [OLD_STYLE_ROW],
                      "clickhouse": {"sample_census": {
                          "window_start": "2026-09-03 02:00:00"}}}}]}),
        encoding="utf-8")
    before = (tmp_path / "report.json").read_text()
    # This test is about the VictoriaMetrics clause; ClickHouse's own re-score
    # has its own suite (tests/test_miniladder_memflat_clickhouse.py), so it is
    # stubbed clean here to leave VM as the only thing that can speak.
    monkeypatch.setattr(ml, "_rescore_clickhouse",
                        lambda stack, start, end: ({"window_start": start,
                                                    "window_end": end}, []))
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: object())
    args = ml.parse_args(["--rescore-memflat", str(tmp_path)])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    assert ml.rescore_memflat(args) == 1, "UNKNOWN is not a PASS"
    assert (tmp_path / "report.json").read_text() == before
    doc = (tmp_path / ml.RESCORE_FILE).read_text()
    assert "## clause (1) — VictoriaMetrics, two end samples a quiet interval" \
        in doc
    assert "victoria: UNKNOWN: this run predates the post-burst quiet interval" \
        in doc
    assert "anon_end 259 MiB -> anon_end_second unmeasured" in doc
    assert "re-scored verdict: **FAIL/UNKNOWN**" in doc
    # The original verdict is quoted, not erased.
    assert "195 -> 259 MiB" in doc


# A correlation row already scored at its own (2026-08-29) anchor, so the
# end-to-end re-score below turns on the VictoriaMetrics clause alone rather
# than on correlation's UNKNOWN.
SCORED_CORRELATION_ROW = {
    "container": "netops-correlation-1", "service": "correlation",
    "instrument": "docker_stats", "anchor": "corr_engine_pending==0",
    "rss_at_input_stop": 470 * MIB, "rss_at_pending_zero": 560 * MIB,
    "rss_end": 566 * MIB, "ratio_vs_anchor": 1.011, "verdict": "FLAT",
}


def test_rescore_end_to_end_passes_a_run_that_recorded_the_interval(
        tmp_path, monkeypatch):
    (tmp_path / "report.json").write_text(json.dumps({"phases": [
        {"phase": "memflat", "status": "PASS", "notes": "all within bounds",
         "evidence": {"containers": [_new_style_row(),
                                     SCORED_CORRELATION_ROW],
                      "clickhouse": {"sample_census": {
                          "window_start": "2026-09-13 02:00:00"}}}}]}),
        encoding="utf-8")
    monkeypatch.setattr(ml, "_rescore_clickhouse",
                        lambda stack, start, end: ({"window_start": start,
                                                    "window_end": end}, []))
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: object())
    args = ml.parse_args(["--rescore-memflat", str(tmp_path)])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    assert ml.rescore_memflat(args) == 0
    doc = (tmp_path / ml.RESCORE_FILE).read_text()
    assert "victoria: PASS" in doc
    assert "after 90s of quiet (x1.001, FLAT" in doc
    assert "warm->end x1.332 UNJUDGED" in doc
