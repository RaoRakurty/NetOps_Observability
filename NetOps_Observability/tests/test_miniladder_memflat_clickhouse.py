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
                return True, values.pop(0)
        for key, value in answers.items():
            if key in query:
                return (False, value[1]) if isinstance(value, tuple) else (True, value)
        return False, f"unstubbed probe: {query[:120]}"

    ch.calls = calls          # type: ignore[attr-defined]
    return ch


def _named(d):
    return {f"netops-{k}-1": v for k, v in d.items()}


def _harness(tmp_path, monkeypatch, *, cold_anon, warm_anon, end_anon,
             docker_stats=None, ch=None, part_baseline=180, clock=None,
             services=("clickhouse",), **flags):
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
    """api/correlation cache nothing — their docker-stats figure IS their RSS."""
    stats = _named({"correlation": {"used": 400 * MIB, "limit": 789 * MIB}})
    h = _harness(tmp_path, monkeypatch, services=("correlation",),
                 cold_anon={}, warm_anon={}, end_anon={},
                 docker_stats=stats)
    h.warm_mem = _named({"correlation": 180 * MIB})
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
