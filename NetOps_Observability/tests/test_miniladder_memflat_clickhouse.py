"""memflat judges ClickHouse on ClickHouse's numbers (2026-08-29).

THE DEFECT THIS PINS. `docker stats` MemUsage is cgroup
`memory.current - inactive_file` — page cache and reclaimable slab included.
Measured on the container that failed the gate: anon 984 MiB + active_file
1,516 MiB + slab_reclaimable 621 MiB = 3.14 GiB reported, against ClickHouse's
own MemoryResident of 994 MiB. Two runs of the SAME CODE therefore disagreed:

    p2-s04-08290653   warm 4,314 -> end 3,281 MiB  = x0.76  PASS
    p2-s04b-08290858  warm 2,246 -> end 3,854 MiB  = x1.72  FAIL

s04b's warm sample simply landed after the previous run's cleanup dropped the
page cache. Meanwhile the real risk went unreported in BOTH runs: peak
MemoryTracking 4,566 MiB = 95.2 % of the 4,794 MiB server cap, with background
merges alone at 3,978 MiB (83 %).

So the ClickHouse clause is now three assertions
(docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md §(c)):
  1. leak slope on cgroup `anon` only, x1.3 with the 64 MiB floor;
  2. peak MemoryTracking < 85 % and peak merge memory < 50 % of the effective
     `max_server_memory_usage` — the assertion that fails s04b for the RIGHT
     reason (drop it and the s04b fixture below goes green: the mutant);
  3. MaxPartCountForPartition back within +20 % of its preflight value and
     under parts_to_delay_insert / 2.

Run:  python3 -m pytest tests/test_miniladder_memflat_clickhouse.py -v
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
    spec = importlib.util.spec_from_file_location("scale_miniladder_memflat", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder_memflat"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before
    return mod


ml = _load_harness()

MIB = 1024 ** 2
# The live numbers from the investigation: cgroup limit 5.20 GiB x the 0.9
# ratio = 5,026,244,198 B = 4,794 MiB effective cap.
CGROUP_TOTAL = 5_584_715_776
CAP_MIB = 4793   # 5,026,244,198 B — the doc rounds it to 4,794


class FakeClock:
    """Virtual clock so the parts settle-wait never sleeps in a test."""

    def __init__(self) -> None:
        self.t = 0.0
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept += seconds
        self.t += seconds


def _census(key, value):
    """metric_log fixtures are written as the two PEAKS; the query also returns
    the SAMPLE CENSUS (plausible, total) since 2026-08-29, so a two-cell
    fixture means "every sample in the window was plausible"."""
    if key != "system.metric_log" or not isinstance(value, str):
        return value
    return value if len(value.split("\t")) >= 4 else value + "\t3600\t3600"


def _ch_stub(sequence=None, **overrides):
    """A ClickHouse that answers exactly memflat's probes — healthy defaults.

    `sequence` optionally maps a probe key to a LIST of successive answers, so
    a test can make the part count settle on the third poll.
    """
    answers = {
        "toString(now())": "2026-08-29 07:00:00",
        "'max_server_memory_usage'": "0",
        "'max_server_memory_usage_to_ram_ratio'": "0.9",
        "'CGroupMemoryTotal'": str(CGROUP_TOTAL),
        "'OSMemoryTotal'": "16764780544",
        "system.metric_log": f"{1000 * MIB}\t{500 * MIB}",
        "system.metrics": (f"MemoryTracking\t{900 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{400 * MIB}"),
        "'MaxPartCountForPartition'": "180",
        "'parts_to_delay_insert'": "1000",
    }
    answers.update(overrides)
    queue = {k: list(v) for k, v in (sequence or {}).items()}
    calls: list[str] = []

    def ch(query, timeout=60):
        calls.append(query)
        for key, values in queue.items():
            if key in query and values:
                return True, _census(key, values.pop(0))
        for key, value in answers.items():
            if key in query:
                if isinstance(value, tuple):
                    return False, value[1]
                return True, _census(key, value)
        return False, f"unstubbed probe: {query[:120]}"

    ch.calls = calls          # type: ignore[attr-defined]
    return ch


def _named(d):
    return {f"netops-{k}-1": v for k, v in d.items()}


def _harness(tmp_path, monkeypatch, *, cold_anon, warm_anon, end_anon,
             docker_stats=None, ch=None, part_baseline=180, clock=None,
             services=("clickhouse",), corr_track=None, **flags):
    monkeypatch.setattr(ml, "MEM_SERVICES", list(services))
    argv = ["--run-dir", str(tmp_path)]
    for k, v in flags.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    args = ml.parse_args(argv)
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    stats = docker_stats or _named(
        {"clickhouse": {"used": 3854 * MIB, "limit": 5326 * MIB}})
    h.stack.mem_stats = lambda: stats                    # type: ignore[assignment]
    h.stack.anon_sample = lambda services: dict(end_anon)  # type: ignore[assignment]
    h.stack.ch = ch or _ch_stub()                        # type: ignore[assignment]
    h.baseline["mem"] = {n: v["used"] for n, v in stats.items()}
    h.baseline["mem_anon"] = dict(cold_anon)
    h.baseline["ch_window_start"] = "2026-08-29 07:00:00"
    h.baseline["ch_max_part_count"] = part_baseline
    h.warm_mem = {n: v["used"] for n, v in stats.items()}
    h.warm_anon = dict(warm_anon)
    h.burst_seconds = 900.0
    h.corr_mem_track = dict(corr_track or {})
    if clock is not None:
        monkeypatch.setattr(ml, "time", clock)
    return h


# ── clause 1: the slope is measured on anon, not on the page cache ──────────

def test_s04b_page_cache_swing_no_longer_decides_the_verdict(tmp_path, monkeypatch):
    """s04b's exact shape: docker stats x1.72 (cache), anon flat at ~1 GiB."""
    h = _harness(tmp_path, monkeypatch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}),
                 docker_stats=_named({"clickhouse": {"used": 3854 * MIB,
                                                     "limit": 5326 * MIB}}))
    # The docker-stats anchor really is the x1.72 that failed the old gate.
    h.warm_mem = _named({"clickhouse": 2246 * MIB})
    assert h.memflat() is True, h.phases[-1]["notes"]
    row = h.phases[-1]["evidence"]["containers"][0]
    assert row["instrument"] == "cgroup_anon"
    assert row["ratio_vs_anchor"] == pytest.approx(994 / 984, abs=0.01)
    # The cache-bearing number is REPORTED, never judged.
    assert row["docker_stats_end_bytes"] == 3854 * MIB
    assert row["docker_stats_ratio_unjudged"] == pytest.approx(1.716, abs=0.01)


def test_a_real_anon_leak_still_fails(tmp_path, monkeypatch):
    """The invariant the phase exists for, on the honest instrument."""
    h = _harness(tmp_path, monkeypatch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 1000 * MIB}),
                 end_anon=_named({"clickhouse": 2200 * MIB}))
    assert h.memflat() is False
    assert "LEAK SLOPE (cgroup_anon)" in h.phases[-1]["notes"]


def test_unreadable_cgroup_is_a_failure_not_a_docker_stats_fallback(
        tmp_path, monkeypatch):
    h = _harness(tmp_path, monkeypatch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": -1}))
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "no cgroup_anon sample" in notes and "docker stats cannot substitute" in notes


def test_stateless_services_keep_the_docker_stats_ratio(tmp_path, monkeypatch):
    """api caches nothing — its docker-stats figure IS its RSS, and it holds no
    backlog, so it keeps the input-stop anchor (correlation does not: see
    tests/test_scale_miniladder_group_parse.py's pending-zero anchor tests)."""
    stats = _named({"api": {"used": 400 * MIB, "limit": 789 * MIB}})
    h = _harness(tmp_path, monkeypatch, services=("api",),
                 cold_anon={}, warm_anon={}, end_anon={},
                 docker_stats=stats)
    h.warm_mem = _named({"api": 180 * MIB})
    assert h.memflat() is False, "a stateless leak must still be caught"
    row = h.phases[-1]["evidence"]["containers"][0]
    assert row["instrument"] == "docker_stats"
    assert "LEAK SLOPE (docker_stats)" in h.phases[-1]["notes"]


# ── clause 2: ClickHouse's own accounting against its own cap ───────────────

def test_s04b_merge_memory_fails_for_the_right_reason(tmp_path, monkeypatch):
    """THE MUTANT TEST: peak 4,566 MiB = 95.2 % of the 4,794 MiB cap and merges
    3,978 MiB = 83 %. Drop clause 2 and this s04b-shaped fixture goes green."""
    ch = _ch_stub(**{"system.metric_log": f"{4566 * MIB}\t{3978 * MIB}",
                     "system.metrics": (f"MemoryTracking\t{4000 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t{3000 * MIB}")})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "peak MemoryTracking 4566 MiB is 95.3%" in notes
    assert "peak MERGE memory 3978 MiB is 83.0%" in notes
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["cap_bytes"] == 5_026_244_198        # 0.9 x the 5.20 GiB cgroup
    assert ch_ev["memory_tracking_pct"] == 95.3
    assert ch_ev["merges_memory_pct"] == 83.0
    assert ch_ev["cap_source"] == "ratio x CGroupMemoryTotal"


def test_healthy_clickhouse_memory_passes(tmp_path, monkeypatch):
    h = _harness(tmp_path, monkeypatch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["memory_tracking_pct"] == pytest.approx(20.9, abs=0.2)
    assert ch_ev["merges_memory_pct"] == pytest.approx(10.4, abs=0.2)


def test_explicit_max_server_memory_usage_wins_over_the_ratio(tmp_path, monkeypatch):
    ch = _ch_stub(**{"'max_server_memory_usage'": str(2000 * MIB),
                     "system.metric_log": f"{1900 * MIB}\t{100 * MIB}"})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["cap_source"] == "server_settings.max_server_memory_usage"
    assert ch_ev["memory_tracking_pct"] == 95.0


def test_host_derived_cap_is_named_as_such(tmp_path, monkeypatch):
    """CGroupMemoryTotal invisible ⇒ the cap is the HOST's — the very trap that
    makes merges_mutations_memory_usage_soft_limit inert in a container."""
    ch = _ch_stub(**{"'CGroupMemoryTotal'": ""})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    h.memflat()
    assert "HOST-derived" in h.phases[-1]["evidence"]["clickhouse"]["cap_source"]


def test_unmeasurable_cap_fails_rather_than_passing_blind(tmp_path, monkeypatch):
    ch = _ch_stub(**{"'CGroupMemoryTotal'": "", "'OSMemoryTotal'": "",
                     "'max_server_memory_usage_to_ram_ratio'": ""})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    assert "unreadable" in h.phases[-1]["notes"]
    assert "must not pass blind" in h.phases[-1]["notes"]


def test_metric_log_disabled_falls_back_to_harness_samples(tmp_path, monkeypatch):
    """A disabled system.metric_log degrades resolution; it must not blind the
    clause — the harness's own system.metrics samples carry the peak."""
    ch = _ch_stub(**{"system.metric_log": ("", "table system.metric_log doesn't exist"),
                     "system.metrics": (f"MemoryTracking\t{4566 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t{100 * MIB}")})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_source"] == "harness system.metrics samples"
    assert ch_ev["memory_tracking_pct"] == 95.3


def test_negative_merge_counter_is_not_a_uint64_wrap(tmp_path, monkeypatch):
    """MergesMutationsMemoryTracking reads slightly negative on an idle server;
    read as UInt64 that becomes 1.8e19 and fails the gate at 3.7e11 % of cap."""
    ch = _ch_stub(**{"system.metric_log": f"{900 * MIB}\t-4096",
                     "system.metrics": (f"MemoryTracking\t{900 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t-4096")})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert h.phases[-1]["evidence"]["clickhouse"]["merges_memory_pct"] == 0.0


# ── clause 3: the store settles its parts after input stops ────────────────

def test_parts_above_the_envelope_fail_after_the_settle_budget(tmp_path, monkeypatch):
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "927"})
    h = _harness(tmp_path, monkeypatch, ch=ch, clock=clock, part_baseline=180,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "parts NEVER SETTLED" in notes and "927" in notes
    parts = h.phases[-1]["evidence"]["clickhouse"]["parts"]
    assert parts["baseline"] == 180 and parts["current"] == 927
    assert parts["envelope"] == 216.0
    # Bounded: min(drain_factor x burst, 600 s), and it really waited.
    assert parts["settle_budget_s"] == 600.0
    assert clock.slept >= 600.0


def test_parts_settling_during_the_wait_passes(tmp_path, monkeypatch):
    clock = FakeClock()
    ch = _ch_stub(sequence={"'MaxPartCountForPartition'": ["900", "400", "200"]})
    h = _harness(tmp_path, monkeypatch, ch=ch, clock=clock, part_baseline=180,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    parts = h.phases[-1]["evidence"]["clickhouse"]["parts"]
    assert parts["current"] == 200 and parts["settle_waited_s"] == 30.0


def test_parts_near_the_insert_delay_threshold_fail(tmp_path, monkeypatch):
    """Settled relative to a HIGH baseline is still inside the throttle band."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "520",
                     "'parts_to_delay_insert'": "1000"})
    h = _harness(tmp_path, monkeypatch, ch=ch, clock=clock, part_baseline=600,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    assert "HALF of parts_to_delay_insert" in h.phases[-1]["notes"]


def test_small_baselines_get_an_absolute_part_floor(tmp_path, monkeypatch):
    """+20 % of 3 parts is 3.6 — a 4th part must not fail the run."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "9"})
    h = _harness(tmp_path, monkeypatch, ch=ch, clock=clock, part_baseline=3,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert h.phases[-1]["evidence"]["clickhouse"]["parts"]["envelope"] == 11.0


def test_unmeasurable_part_count_fails(tmp_path, monkeypatch):
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": ""})
    h = _harness(tmp_path, monkeypatch, ch=ch, clock=clock,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    assert "MaxPartCountForPartition unmeasurable" in h.phases[-1]["notes"]


# ── all three numbers reach the operator ───────────────────────────────────

def test_phase_line_prints_all_three_clauses(tmp_path, monkeypatch):
    h = _harness(tmp_path, monkeypatch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "clickhouse anon 994 MiB (x1.01 vs anchor)" in notes
    assert f"peak MemoryTracking 1000 MiB = 20.9% of cap {CAP_MIB} MiB" in notes
    assert "merges 500 MiB = 10.4%" in notes
    assert "MaxPartCountForPartition 180 (preflight 180, envelope 216.0" in notes
    assert "delay at 1000)" in notes


# ── clause 2, THE p2-s05 METRIC DEFECT (2026-08-29) ────────────────────────
#
# Run p2-s05-08291138 failed memflat with
#
#   clickhouse: peak MERGE memory 4084 MiB is 99.7% of the 4096 MiB server cap
#   (> 50.0%) … peak MemoryTracking 2952 MiB = 72.1% of cap 4096 MiB
#
# Merge memory is a SUBSET of the server's tracked total, so 4,084 > 2,952 is
# not a measurement — it is a `CurrentMetric_MergesMutationsMemoryTracking`
# underflow, and `max()` taken independently over each raw column let 50 of
# the window's 3,711 samples decide the verdict. Ground truth for the same
# window, glitches excluded: 1,950 MiB and 421 MiB — a PASS.
#
# ROWS BELOW ARE VERBATIM from that server's system.metric_log (bytes).
P2_S05_ROWS = [
    (939723571, 56389553),        # 11:43:00  ordinary
    (1004857728, 49353545),       # 11:43:03  ordinary
    (1427111936, 441679413),      # 12:17:53  the run's TRUE merge peak (421 MiB)
    (2044551720, 0),              # 12:33:49  the run's TRUE MemoryTracking peak
    (1985249297, 100690621),      # 12:03:48  ordinary
    (1117843990, -152276),        # a merge counter legitimately below zero
    (3095901496, 3220538533),     # 11:43:06  IMPOSSIBLE: merges above the total
    (1139407161, 4159233902),     # 11:43:07  IMPOSSIBLE
    (1340034797, 4282450045),     # 11:43:52  IMPOSSIBLE — and the printed "peak"
]
# The exact predicate the fixture keys on. Kept as a LITERAL, never as
# `ml.CH_PLAUSIBLE_SAMPLE`, so a test may blank the constant (the mutant) and
# this ClickHouse stand-in answers like the real server would.
PLAUSIBLE_SQL = ("CurrentMetric_MergesMutationsMemoryTracking <= "
                 "CurrentMetric_MemoryTracking")
S05_CAP_MIB = 4096


def _metric_log_server(rows=P2_S05_ROWS, **overrides):
    """A ClickHouse whose metric_log holds ROWS and answers either query shape.

    It evaluates the harness's aggregate the way the server does: with the
    plausibility predicate it maxes over self-consistent rows only, without it
    over everything — which is precisely the difference between 1,950/421 and
    2,952/4,084.
    """
    def answer(query):
        good = [r for r in rows if r[0] >= 0 and r[1] <= r[0]]
        used = good if PLAUSIBLE_SQL in query else list(rows)
        track = max((max(r[0], 0) for r in used), default=0)
        merges = max((max(r[1], 0) for r in used), default=0)
        return f"{track}\t{merges}\t{len(used)}\t{len(rows)}"

    base = {"'max_server_memory_usage'": str(S05_CAP_MIB * MIB),
            # The live sample the harness itself took at the end of the burst.
            "system.metrics": (f"MemoryTracking\t{1208 * MIB}\n"
                               f"MergesMutationsMemoryTracking\t{23 * MIB}")}
    base.update(overrides)
    stub = _ch_stub(**base)

    def ch(query, timeout=60):
        if "system.metric_log" in query:
            return True, answer(query)
        return stub(query, timeout)
    return ch


def _s05(tmp_path, monkeypatch, ch):
    return _harness(tmp_path, monkeypatch, ch=ch,
                    cold_anon=_named({"clickhouse": 900 * MIB}),
                    warm_anon=_named({"clickhouse": 1086 * MIB}),
                    end_anon=_named({"clickhouse": 881 * MIB}))


def test_p2_s05_impossible_merge_samples_no_longer_decide_the_verdict(
        tmp_path, monkeypatch):
    """The printed peaks ARE the metric_log maxima — 1,950 and 421 MiB — and
    the clause PASSes, on the exact rows that produced the false FAIL."""
    h = _s05(tmp_path, monkeypatch, _metric_log_server())
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_memory_tracking_bytes"] == 2_044_551_720   # 1,950 MiB
    assert ch_ev["peak_merges_memory_bytes"] == 441_679_413       # 421 MiB
    assert ch_ev["memory_tracking_pct"] == pytest.approx(47.6, abs=0.1)
    assert ch_ev["merges_memory_pct"] == pytest.approx(10.3, abs=0.1)
    assert ch_ev["peaks_self_consistent"] is True
    notes = h.phases[-1]["notes"]
    assert f"peak MemoryTracking 1950 MiB = 47.6% of cap {S05_CAP_MIB} MiB" in notes
    assert "merges 421 MiB = 10.3%" in notes
    # The live 1,208 / 23 MiB sample is a FLOOR, never a ceiling: it is below
    # both metric_log maxima, so it must not move them.
    assert ch_ev["peak_source"].startswith("system.metric_log since")


def test_the_excluded_samples_are_counted_not_hidden(tmp_path, monkeypatch):
    """A filter that will not say how much it threw away is its own defect."""
    h = _s05(tmp_path, monkeypatch, _metric_log_server())
    assert h.memflat() is True, h.phases[-1]["notes"]
    census = h.phases[-1]["evidence"]["clickhouse"]["sample_census"]
    assert census["metric_log_samples"] == len(P2_S05_ROWS)
    assert census["metric_log_plausible"] == len(P2_S05_ROWS) - 3
    assert census["metric_log_rejected"] == 3
    assert "3/9 impossible samples excluded" in h.phases[-1]["notes"]


def test_MUTANT_dropping_the_plausibility_filter_is_never_a_false_FAIL(
        tmp_path, monkeypatch):
    """THE MUTANT: blank the predicate and the server answers 2,952 / 4,084
    again — the shape that failed run p2-s05. The invariant net must catch it:
    UNKNOWN, with neither the false '99.7% of cap' FAIL nor a PASS."""
    monkeypatch.setattr(ml, "CH_PLAUSIBLE_SAMPLE", "1 = 1")
    h = _s05(tmp_path, monkeypatch, _metric_log_server())
    assert h.memflat() is False, "an impossible reading must never PASS"
    notes = h.phases[-1]["notes"]
    assert "memory peaks UNKNOWN" in notes
    assert "physically impossible" in notes
    assert "99.7%" not in notes, "the false cap-exceeded FAIL must not be made"
    assert "can starve the query/insert path" not in notes
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peaks_self_consistent"] is False
    assert ch_ev["memory_tracking_pct"] is None
    assert ch_ev["merges_memory_pct"] is None


def test_INVARIANT_a_merge_peak_above_the_tracked_total_is_UNKNOWN(
        tmp_path, monkeypatch):
    """Whatever the instrument says, the two numbers the phase PRINTS must
    satisfy merge <= tracked total, or the clause refuses to judge."""
    ch = _ch_stub(**{"system.metric_log":
                     f"{1000 * MIB}\t{3000 * MIB}\t3600\t3600",
                     "system.metrics": (f"MemoryTracking\t{10 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t{1 * MIB}")})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "memory peaks UNKNOWN" in notes and "NOT judged either way" in notes
    assert "> 50.0%" not in notes


def test_an_impossible_live_sample_is_discarded_whole(tmp_path, monkeypatch):
    """The fallback path gets the same guard: half a corrupt pair must never
    be folded into the peak."""
    ch = _ch_stub(**{
        "system.metric_log": ("", "table system.metric_log doesn't exist"),
        "system.metrics": (f"MemoryTracking\t{1000 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{4084 * MIB}")})
    h = _harness(tmp_path, monkeypatch, ch=ch,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 984 * MIB}),
                 end_anon=_named({"clickhouse": 994 * MIB}))
    assert h.memflat() is False, "no peak at all is UNKNOWN, never PASS"
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_memory_tracking_bytes"] == -1, "the pair was discarded"
    assert ch_ev["peak_merges_memory_bytes"] == -1
    assert ch_ev["sample_census"]["live_samples_rejected"] >= 1
    assert "unmeasurable" in h.phases[-1]["notes"]


def test_a_window_with_no_plausible_sample_does_not_read_as_zero(
        tmp_path, monkeypatch):
    """`maxIf` over an empty set is 0 in ClickHouse, and 0 MiB of memory would
    read as the flattest possible server. Every metric_log sample corrupt =>
    the peaks come from the harness's own (plausible) live sample instead."""
    ch = _metric_log_server(rows=[(1139407161, 4159233902)])
    h = _s05(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_memory_tracking_bytes"] == 1208 * MIB, "never 0"
    assert ch_ev["peak_merges_memory_bytes"] == 23 * MIB
    assert ch_ev["peak_source"] == "harness system.metrics samples"
    assert ch_ev["sample_census"]["metric_log_plausible"] == 0


# ── --rescore-memflat: what the corrected clauses say about a FINISHED run ──
#
# A run costs an hour. Re-running one to find out what a fixed clause says
# about it is not the answer: the run's own evidence plus a read-only
# metric_log query for its window is. It writes memflat-rescore.md and NEVER
# touches the run's own report files.

def _rescore_stack(rows=P2_S05_ROWS, **overrides):
    """A Stack stand-in answering the re-score's read-only probes."""
    inner = _metric_log_server(rows=rows, **overrides)

    def ch(query, timeout=60):
        if "system.metric_log" in query:
            good = [r for r in rows if r[0] >= 0 and r[1] <= r[0]]
            return True, "\t".join(str(v) for v in (
                max((max(r[0], 0) for r in good), default=0),
                max((max(r[1], 0) for r in good), default=0),
                len(good), len(rows),
                max((r[0] for r in rows), default=0),
                max((r[1] for r in rows), default=0)))
        return inner(query, timeout)
    return type("S", (), {"ch": staticmethod(ch)})()


def test_rescore_reproduces_the_ground_truth_for_p2_s05():
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(), "2026-08-29 11:39:00", "2026-08-29 12:37:00")
    assert not problems, problems
    assert ev["peak_memory_tracking_bytes"] == 2_044_551_720    # 1,950 MiB
    assert ev["peak_merges_memory_bytes"] == 441_679_413        # 421 MiB
    assert ev["memory_tracking_pct"] == pytest.approx(47.6, abs=0.1)
    assert ev["merges_memory_pct"] == pytest.approx(10.3, abs=0.1)
    assert ev["rejected_samples"] == 3
    # ...and it states what the OLD, unfiltered max() printed, so the reader
    # can see the defect rather than take the correction on trust.
    assert ev["unfiltered_memory_tracking_bytes"] == 3_095_901_496   # 2,952 MiB
    assert ev["unfiltered_merges_memory_bytes"] == 4_282_450_045     # 4,084 MiB


def test_rescore_still_reports_a_genuine_cap_breach():
    """The re-score is a correction, not an amnesty."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(rows=[(3900 * MIB, 3500 * MIB)]),
        "2026-08-29 11:39:00", "")
    assert any("peak MemoryTracking" in p for p in problems)
    assert any("peak MERGE memory" in p for p in problems)
    assert ev["rejected_samples"] == 0


def test_rescore_of_a_run_without_the_rss_curve_is_UNKNOWN(tmp_path):
    """Runs before 2026-08-29 recorded no per-replica RSS. The old input-stop
    ratio must NOT be reused to invent a correlation verdict."""
    (tmp_path / "correlation-completion.json").write_text(
        json.dumps([{"t_s": 0.0, "pending": 22736, "cohorts": 3}]),
        encoding="utf-8")
    ev, problems = ml._rescore_correlation(str(tmp_path), {"containers": [
        {"container": "netops-correlation-3", "service": "correlation",
         "warm_bytes": 470 * MIB, "end_bytes": 647 * MIB,
         "ratio_vs_anchor": 1.377}]})
    assert ev["source"] == "none"
    assert len(problems) == 1
    assert "UNKNOWN" in problems[0] and "predates" in problems[0]


def test_rescore_judges_correlation_from_a_saved_rss_curve(tmp_path):
    curve = [
        {"t_s": 0.0, "per_replica": {"netops-correlation-3":
                                     {"pending": 22736.0, "rss": 470 * MIB}}},
        {"t_s": 1986.0, "per_replica": {"netops-correlation-3":
                                        {"pending": 0.0, "rss": 560 * MIB}}},
    ]
    (tmp_path / "correlation-completion.json").write_text(
        json.dumps(curve), encoding="utf-8")
    memflat = {"containers": [{"container": "netops-correlation-3",
                               "service": "correlation",
                               "end_bytes": 647 * MIB}]}
    ev, problems = ml._rescore_correlation(str(tmp_path), memflat)
    rec = ev["replicas"]["netops-correlation-3"]
    assert rec["rss_at_pending_zero"] == 560 * MIB
    assert rec["ratio_vs_anchor"] == pytest.approx(1.155, abs=0.005)
    assert rec["verdict"] == "FLAT"
    assert not problems


def test_rescore_from_a_saved_curve_still_catches_a_real_leak(tmp_path):
    curve = [
        {"t_s": 0.0, "per_replica": {"netops-correlation-3":
                                     {"pending": 22736.0, "rss": 470 * MIB}}},
        {"t_s": 1986.0, "per_replica": {"netops-correlation-3":
                                        {"pending": 0.0, "rss": 470 * MIB}}},
    ]
    (tmp_path / "correlation-completion.json").write_text(
        json.dumps(curve), encoding="utf-8")
    _, problems = ml._rescore_correlation(str(tmp_path), {"containers": [
        {"container": "netops-correlation-3", "service": "correlation",
         "end_bytes": 647 * MIB}]})
    assert any("LEAK SLOPE at the pending-zero anchor" in p for p in problems)


def test_rescore_never_writes_the_runs_own_report_files(tmp_path, monkeypatch):
    """The original verdict is the record of what the gate said at the time."""
    (tmp_path / "report.json").write_text(json.dumps({"phases": [
        {"phase": "memflat", "status": "FAIL", "notes": "the original",
         "evidence": {"containers": [], "clickhouse": {
             "sample_census": {"window_start": "2026-08-29 11:39:00"}}}}]}),
        encoding="utf-8")
    (tmp_path / "report.md").write_text("original md", encoding="utf-8")
    before = ((tmp_path / "report.json").read_text(),
              (tmp_path / "report.md").read_text())
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: _rescore_stack())
    args = ml.parse_args(["--rescore-memflat", str(tmp_path)])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    assert ml.rescore_memflat(args) == 1, "correlation is UNKNOWN => not PASS"
    assert ((tmp_path / "report.json").read_text(),
            (tmp_path / "report.md").read_text()) == before
    doc = (tmp_path / ml.RESCORE_FILE).read_text()
    assert "peak MemoryTracking: **1950 MiB**" in doc
    assert "peak MERGE memory: **421 MiB**" in doc
    assert "clause (2): PASS" in doc
    assert "the original" in doc, "the original verdict is quoted, not erased"


def test_rescore_refuses_without_a_window():
    """No window => no re-score. Guessing one would judge another run."""
    args = ml.parse_args(["--rescore-memflat", "/nonexistent-run-dir"])
    with pytest.raises(SystemExit):
        ml.rescore_memflat(args)
