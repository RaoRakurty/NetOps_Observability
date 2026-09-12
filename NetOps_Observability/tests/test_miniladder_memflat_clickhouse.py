# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""memflat judges ClickHouse on ClickHouse's numbers (2026-08-29).

THE FIRST DEFECT THIS PINS. `docker stats` MemUsage is cgroup
`memory.current - inactive_file` — page cache and reclaimable slab included.
Measured on the container that failed the gate: anon 984 MiB + active_file
1,516 MiB + slab_reclaimable 621 MiB = 3.14 GiB reported, against ClickHouse's
own MemoryResident of 994 MiB. Two runs of the SAME CODE therefore disagreed:

    p2-s04-08290653   warm 4,314 -> end 3,281 MiB  = x0.76  PASS
    p2-s04b-08290858  warm 2,246 -> end 3,854 MiB  = x1.72  FAIL

s04b's warm sample simply landed after the previous run's cleanup dropped the
page cache.

THE SECOND, and the reason this file was rewritten
(docs/scale/P2_CLICKHOUSE_PEAK_S06_2026-08-29.md). The replacement clause
asserted peak `MemoryTracking` < 85 % and peak `MergesMutationsMemoryTracking`
< 50 % of the server cap, and DISCARDED every metric_log sample where the merge
figure read above the total — "merge memory is a subset of the total". On
ClickHouse 24.8 that premise is false:

    system.metrics  MemoryTracking = 692.12 MiB
    async_metrics   MemoryResident = 692.10 MiB     <- identical to 2 dp

`CurrentMetric_MemoryTracking` is the global tracker HARD-SET TO PROCESS RSS
once a second (`MemoryTracker::setRSS`), not a sum of child trackers, so
`MergesMutationsMemoryTracking` legitimately reads above it — and the filter
was discarding exactly the diagnostic samples. Two more facts from the same
decomposition:

  * `system.query_log` recorded 2 of run p2-s06-08291421's 17
    MEMORY_LIMIT_EXCEEDED. `system.error_log` / `system.errors` recorded all
    17 — background threads raise the rest.
  * s06 (17 errors) and s05 (clean) have the SAME median (1.25-1.40 GiB) and
    near-identical p99 (1,596 vs 1,567 MiB). What separates them is 13
    one-second RSS transients. A max-based gate cannot tell those apart.

So the ClickHouse clause is now:
  1. leak slope on cgroup `anon` only, x1.3 with the 64 MiB floor;
  2a. ZERO new MEMORY_LIMIT_EXCEEDED across the run (`system.errors` delta,
      cross-checked against `system.error_log`) — the clause that fails the
      s06 fixture below; drop it and s06 goes green (the mutant);
  2b. p99 MemoryTracking < 85 % of the effective `max_server_memory_usage`.
      The peak is REPORTED, and warned about at/above the cap when no error
      followed it. `MergesMutationsMemoryTracking` is INFORMATIONAL: no
      verdict, because in 24.8 it is not bounded by the total;
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


WINDOW_START = "2026-08-29 07:00:00"


def _metric_log(peak_mib, p99_mib, merge_mib, samples=3600,
                first=WINDOW_START):
    """The five cells CH_PEAK_SELECT returns: peak, p99, merge peak, count and
    the EARLIEST in-window sample — the coverage check, because a RECREATED
    table will happily answer for a window it does not hold."""
    return (f"{int(peak_mib * MIB)}\t{int(p99_mib * MIB)}\t"
            f"{int(merge_mib * MIB)}\t{samples}\t{first}")


def _error_log(count, rows=None, earliest="2026-08-29 00:00:00"):
    """The three cells the error_log probe returns: in-window count for code
    241, TOTAL rows in the table, and the table's earliest row. The last two
    are how a recreated table is caught answering 0 for a run it never saw."""
    if rows is None:
        rows = max(count, 1)
    return f"{count}\t{rows}\t{earliest}"


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
        "system.metric_log": _metric_log(1000, 800, 500),
        "system.metrics": (f"MemoryTracking\t{900 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{400 * MIB}"),
        # The lifetime MEMORY_LIMIT_EXCEEDED counter READ AT MEMFLAT; the
        # preflight baseline is set on the harness (see `_harness`).
        "system.errors": "0",
        "system.error_log": _error_log(0, rows=9),
        # The sole-producer probes (checks (c)/(d) of the full-delta
        # exemption): healthy defaults say the backfill was alone. The
        # foreign probe's key must sit BEFORE system.query_log — its query
        # reads that same table and would otherwise match the victims answer.
        "foreign_241": "0\t",
        "system.part_log": "0",
        "system.query_log": "",
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
                if isinstance(value, tuple):
                    return False, value[1]
                return True, value
        return False, f"unstubbed probe: {query[:120]}"

    ch.calls = calls          # type: ignore[attr-defined]
    return ch


def _named(d):
    return {f"netops-{k}-1": v for k, v in d.items()}


def _harness(tmp_path, monkeypatch, *, cold_anon, warm_anon, end_anon,
             docker_stats=None, ch=None, part_baseline=180, clock=None,
             services=("clickhouse",), corr_track=None, mem_errors=0, **flags):
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
    h.baseline["ch_mem_errors"] = mem_errors
    h.warm_mem = {n: v["used"] for n, v in stats.items()}
    h.warm_anon = dict(warm_anon)
    h.burst_seconds = 900.0
    h.corr_mem_track = dict(corr_track or {})
    if clock is not None:
        monkeypatch.setattr(ml, "time", clock)
    return h


def _ch(tmp_path, monkeypatch, ch=None, **kw):
    """The healthy-anon ClickHouse harness every clause-2 test starts from."""
    return _harness(tmp_path, monkeypatch, ch=ch,
                    cold_anon=_named({"clickhouse": 900 * MIB}),
                    warm_anon=_named({"clickhouse": 984 * MIB}),
                    end_anon=_named({"clickhouse": 994 * MIB}), **kw)


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


# ── clause 2a: MEMORY_LIMIT_EXCEEDED is the customer-visible fact ───────────
#
# Run p2-s06-08291421, 14:35-14:50. Peak MemoryTracking 4,406 MiB = 107.6 % of
# the 4,096 MiB cap — but the MEDIAN was 1.19 GiB and the p99 1,596 MiB (39 %),
# identical to the clean s05 run. The peak is 13 one-second RSS transients from
# `system.metric_log`'s own 997-column Wide+Horizontal merges. What actually
# happened to the customer is the 17 MEMORY_LIMIT_EXCEEDED between 14:36:34 and
# 14:54:16 — of which `system.query_log` recorded exactly TWO.
S06_CAP_MIB = 4096
S06_PEAK_MIB = 4406
S06_P99_MIB = 1596
S06_MERGE_MIB = 4045          # ABOVE the 4,096 cap's own tracked total at times


def _s06_stub(errors=17, **overrides):
    base = {
        "'max_server_memory_usage'": str(S06_CAP_MIB * MIB),
        "system.metric_log": _metric_log(S06_PEAK_MIB, S06_P99_MIB,
                                         S06_MERGE_MIB, samples=4141),
        "system.metrics": (f"MemoryTracking\t{1188 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{96 * MIB}"),
        # VERBATIM from the run: system.errors is a lifetime counter (the
        # preflight baseline was 1), error_log counts the window, and query_log
        # names only the two INSERTs it could see.
        "system.errors": str(1 + errors),
        "system.error_log": _error_log(errors, rows=max(errors, 9)),
        "system.query_log": "Insert\tnetops.findings\t2" if errors else "",
        "'MaxPartCountForPartition'": "12",
    }
    base.update(overrides)
    return _ch_stub(**base)


def _s06(tmp_path, monkeypatch, ch):
    return _harness(tmp_path, monkeypatch, ch=ch, part_baseline=15,
                    mem_errors=1,
                    cold_anon=_named({"clickhouse": 900 * MIB}),
                    warm_anon=_named({"clickhouse": 1072 * MIB}),
                    end_anon=_named({"clickhouse": 866 * MIB}))


def test_s06_fails_on_the_errors_not_on_the_memory_level(tmp_path, monkeypatch):
    """THE RUN THIS CLAUSE WAS REWRITTEN FOR. 17 refusals is the verdict; the
    4,406 MiB peak is a transient the report states and does not fail on."""
    h = _s06(tmp_path, monkeypatch, _s06_stub())
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "17 MEMORY_LIMIT_EXCEEDED during this run" in notes
    assert "system.errors delta 17" in notes
    # The victims are NAMED, and the shortfall query_log cannot explain is too.
    assert "2x Insert on netops.findings" in notes
    assert ("the other 15 were raised in BACKGROUND threads and query_log "
            "cannot name them") in notes
    # ...and NOT a word about the level being over a bound: p99 is 39 %, and
    # the 107.6 % peak does not even earn its WARN — an error clause already
    # condemned the run, so the transient line would only be noise.
    assert "is the level the store RUNS at" not in notes
    assert "a transient that touched the ceiling" not in notes
    assert h.phases[-1]["evidence"]["clickhouse"]["warnings"] == []
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["memory_limit_exceeded"]["delta"] == 17
    assert ch_ev["memory_limit_exceeded"]["window_count"] == 17
    assert ch_ev["p99_memory_tracking_pct"] == pytest.approx(39.0, abs=0.2)
    assert ch_ev["memory_tracking_pct"] == pytest.approx(107.6, abs=0.2)


def test_the_same_shape_with_zero_errors_passes_with_a_transient_WARN(
        tmp_path, monkeypatch):
    """The distinction the whole rewrite turns on: identical memory curve, no
    refusal behind it. The 107.6 % peak is a WARN line, never a FAIL."""
    h = _s06(tmp_path, monkeypatch, _s06_stub(errors=0))
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "WARN:" in notes
    assert "reached 107.6% of the 4096 MiB cap" in notes
    assert "a transient that touched the ceiling and cost no work" in notes
    warnings = h.phases[-1]["evidence"]["clickhouse"]["warnings"]
    assert len(warnings) == 1 and "Reported, not failed" in warnings[0]


def test_MUTANT_dropping_the_error_clause_lets_the_s06_shape_pass(
        tmp_path, monkeypatch):
    """THE MUTANT. Remove clause (2a) and the run that refused 17 pieces of
    work goes green on a memory curve indistinguishable from a clean one —
    which is precisely why the error delta, not the peak, is the gate."""
    monkeypatch.setattr(
        ml.Harness, "_ch_memory_errors",
        lambda self: ({"baseline": 1, "current": 18, "delta": 17,
                       "window_count": 17, "window_source": "muted",
                       "window_state": "ok", "window_start": "",
                       "window_end": "", "victims": ""},
                      []))
    h = _s06(tmp_path, monkeypatch, _s06_stub())
    assert h.memflat() is True, (
        "the mutant must go green — that is what makes the error clause "
        "load-bearing rather than decorative")


def test_p99_above_the_bound_fails_as_a_sustained_level(tmp_path, monkeypatch):
    """A real regression: the store RUNS at 90 % of its cap. No transient
    excuse — 1 % of the run was spent at or above that."""
    ch = _ch_stub(**{"system.metric_log": _metric_log(4700, 4320, 200)})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "p99 MemoryTracking 4320 MiB is 90.1%" in notes
    assert "this is the level the store RUNS at, not a transient" in notes


def test_a_peak_between_the_bound_and_the_cap_is_only_reported(
        tmp_path, monkeypatch):
    """95 % peak, 40 % p99, no errors: reported, no WARN, no FAIL. A gate that
    cried at every transient is a gate operators learn to ignore."""
    ch = _ch_stub(**{"system.metric_log": _metric_log(4550, 1900, 300)})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["memory_tracking_pct"] == pytest.approx(94.9, abs=0.2)
    assert ch_ev["warnings"] == []
    assert "peak 4550 MiB = 94.9%" in h.phases[-1]["notes"]


def test_error_counter_unreadable_fails_rather_than_passing_blind(
        tmp_path, monkeypatch):
    ch = _ch_stub(**{"system.errors": ("", "table system.errors doesn't exist")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "MEMORY_LIMIT_EXCEEDED counter is UNREADABLE" in notes
    assert "must not pass blind" in notes


def test_a_restart_mid_run_is_UNKNOWN_not_a_clean_delta(tmp_path, monkeypatch):
    """`system.errors` resets at server start. A counter that went BACKWARDS is
    a restart, and a restarted run is not comparable — it is not a PASS."""
    ch = _s06_stub(errors=0, **{"system.errors": "2"})
    h = _s06(tmp_path, monkeypatch, ch)     # preflight baseline was 1... but
    h.baseline["ch_mem_errors"] = 40        # ...40 before the restart
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "went BACKWARDS (preflight 40 -> 2)" in notes
    assert "ClickHouse RESTARTED during this run" in notes


def test_error_log_unavailable_leaves_the_delta_alone_with_a_WARN(
        tmp_path, monkeypatch):
    """error_log is optional (a builder may drop or re-create it). Its absence
    degrades the timeline, it does not invent a clean run."""
    ch = _ch_stub(**{
        "system.error_log": ("", "table system.error_log doesn't exist")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    warnings = h.phases[-1]["evidence"]["clickhouse"]["warnings"]
    assert any("system.error_log cannot answer for this run" in w for w in warnings)
    assert any("rests on the system.errors delta alone" in w for w in warnings)


def test_error_log_alone_can_condemn_the_run(tmp_path, monkeypatch):
    """The delta and the window count are two views of one fact; the LARGER
    wins. A delta of 0 with error_log saying 17 is still 17 refusals."""
    ch = _s06_stub(errors=17, **{"system.errors": "1"})   # delta 0
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    assert "17 MEMORY_LIMIT_EXCEEDED during this run" in h.phases[-1]["notes"]
    assert "system.errors delta 0" in h.phases[-1]["notes"]


def test_background_only_raises_say_query_log_could_name_none(
        tmp_path, monkeypatch):
    """15 of s06's 17 were background raises. A window where ALL of them are
    must say so, not print an empty victim list."""
    ch = _s06_stub(errors=4, **{"system.query_log": ""})
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    assert ("NO victim in system.query_log — every raise was in a BACKGROUND "
            "thread") in h.phases[-1]["notes"]


# ── clause 2a: budgeted-backfill NEGOTIATION is exempt, a STALL is not ──────
#
# RUN 08311437us3b (2026-08-31 14:38-15:35). The clause failed the run on 4
# MEMORY_LIMIT_EXCEEDED while the platform did exactly what 9ed38cbb designed
# it to do: the timeintel backfill's wide fetch NEGOTIATES with the server — a
# sub-fetch that does not fit is refused against the worker's OWN budgeted
# max_memory_usage (241) or read cap (307), the splitter halves the key list,
# the pass folds the pages and advances its watermark. Nothing else lost work.
#
# So the count is now taken on what is left after TWO conditions are BOTH met:
#   attributable  system.query_log names the refused statement as the worker's
#                 own (log_comment/user `worker:timeintel-backfill*`);
#   recovered     the worker logged `backfill pass complete` with pages > 0
#                 inside the run window.
# A refusal that is attributable but never completed a pass is the STALL shape
# 9ed38cbb fixed and still fails — that is the mutant below. A background
# victim (a merge query_log cannot even name) still fails, which is s06.

BACKFILL_TAG = "worker:timeintel-backfill"
BACKFILL_PICK_TAG = "worker:timeintel-backfill-pick"


def _pass_line(pages=3, written=1204):
    """The worker's applog JSON line, as timeintel_backfill.go emits it."""
    return json.dumps({
        "ts": "2026-08-31T15:02:11.412831Z", "level": "info",
        "component": "timeintel", "msg": "backfill pass complete",
        "written": written, "pages": pages, "caught_up": False,
        "cursor": "2026-08-14T09:11:02.5Z"})


def _early_line(pages=0):
    """The OTHER line the worker can emit: a pass that ended EARLY. This is the
    stall shape — same words in it, and it must never read as a completion."""
    return json.dumps({
        "ts": "2026-08-31T15:02:11.412831Z", "level": "warn",
        "component": "timeintel",
        "msg": "backfill pass ended early — resuming from the watermark next tick",
        "written": 0, "pages": pages, "retryable": False,
        "err": "code 241 MEMORY_LIMIT_EXCEEDED"})


def _api_log_stub(monkeypatch, blob, *, rc=0, ids=("netops-api-1",),
                  calls=None):
    """docker ps + docker logs for the api service, through ml.run — the same
    seam collect_stability_blobs uses."""
    def fake_run(cmd, timeout, *a, **k):
        if calls is not None:
            calls.append(cmd)
        if "ps" in cmd:
            return 0, "".join(f"{i}\n" for i in ids), ""
        if "logs" in cmd:
            return (0, blob, "") if rc == 0 else (rc, "", "no such container")
        return 0, "", ""
    monkeypatch.setattr(ml, "run", fake_run)


def _attribution(*rows):
    """The three cells the attribution probe returns per group: log_comment,
    user and the count of 241s under it."""
    return "\n".join(f"{tag}\t{user}\t{n}" for tag, user, n in rows)


def _refusal_stub(errors, attribution, victims="Select\tnetops.incidents\t4",
                  **overrides):
    """s06's plumbing with `errors` refusals and a QUIET memory curve (so the
    only thing under test is the error accounting), answering the ATTRIBUTION
    probe (the one that groups by log_comment) separately from the victims
    probe (which groups by query_kind)."""
    base = {
        "'max_server_memory_usage'": str(S06_CAP_MIB * MIB),
        "system.metric_log": _metric_log(1200, 900, 400, samples=4141),
        "system.metrics": (f"MemoryTracking\t{1188 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{96 * MIB}"),
        "system.errors": str(1 + errors),
        "system.error_log": _error_log(errors, rows=max(errors, 9)),
        "system.query_log": victims,
        "'MaxPartCountForPartition'": "12",
    }
    base.update(overrides)
    # `sequence` is consulted BEFORE the plain answers, which is how the
    # attribution probe (it names log_comment) is told apart from the victims
    # probe over the same table.
    return _ch_stub(sequence={"log_comment": [attribution]}, **base)


def test_a_recovered_backfill_negotiation_is_exempted_and_named(
        tmp_path, monkeypatch):
    """RUN 08311437us3b's exact shape: 4 refusals, every one of them the
    budgeted worker's own, and a pass that completed 3 pages."""
    _api_log_stub(monkeypatch, "INFO boot\n" + _pass_line(pages=3) + "\n")
    ch = _refusal_stub(4, _attribution((BACKFILL_TAG, "netops", 3),
                                       (BACKFILL_PICK_TAG, "netops", 1)))
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    # NEVER silently: the exemption is in the line the operator reads.
    assert "4 backfill-negotiation refusals exempted, pass completed" in notes
    assert BACKFILL_TAG in notes and "1 completed pass(es)" in notes
    assert "full-delta exemption: sole producer verified" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["window_count"] == 4 and err["delta"] == 4
    assert err["backfill_attributed"] == 4
    assert err["backfill_passes"] == 1
    assert err["backfill_exempt"] == 4
    assert err["counted"] == 0


def test_a_backfill_refusal_without_a_completed_pass_STILL_FAILS(
        tmp_path, monkeypatch):
    """THE STALL SHAPE — the defect 9ed38cbb fixed. Same refusals, same
    attribution, but the worker only ever logged passes that ended EARLY: the
    watermark never advanced and the gate must stay red."""
    _api_log_stub(monkeypatch, _early_line() + "\n" + _early_line() + "\n")
    ch = _refusal_stub(4, _attribution((BACKFILL_TAG, "netops", 4)))
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "4 MEMORY_LIMIT_EXCEEDED during this run" in notes
    assert "exempted" not in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["backfill_attributed"] == 4
    assert err["backfill_passes"] == 0
    assert err["backfill_exempt"] == 0 and err["counted"] == 4


def test_MUTANT_dropping_the_pass_completion_requirement_lets_a_stall_pass(
        tmp_path, monkeypatch):
    """THE MUTANT. Exempt on attribution ALONE — no recovery evidence — and the
    stall above goes green. That is what makes the completed pass load-bearing
    rather than decorative."""
    _api_log_stub(monkeypatch, _early_line() + "\n")
    monkeypatch.setattr(ml.Harness, "_backfill_pass_evidence",
                        lambda self, now=None: (1, "MUTANT: assumed recovered"))
    ch = _refusal_stub(4, _attribution((BACKFILL_TAG, "netops", 4)))
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, (
        "the mutant must go green — a stall is indistinguishable from a "
        "negotiation until the completed pass is required")


def test_a_background_victim_is_never_exempted(tmp_path, monkeypatch):
    """s06's shape, unchanged: raises query_log cannot attribute at all (a
    metric_log merge) are still the customer-visible fact, and a completed
    backfill pass in the same run does not launder them."""
    _api_log_stub(monkeypatch, _pass_line(pages=5) + "\n")
    ch = _refusal_stub(17, _attribution(("", "default", 2)),
                       victims="Insert\tnetops.findings\t2",
                       **{"system.errors": "18"})
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "17 MEMORY_LIMIT_EXCEEDED during this run" in notes
    assert "exempted" not in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["backfill_attributed"] == 0 and err["counted"] == 17
    # The pass evidence is not even read when nothing is attributable.
    assert err["backfill_passes"] == -1


def test_mixed_run_exempts_only_the_attributable_recovered_ones(
        tmp_path, monkeypatch):
    """6 refusals: 4 the budgeted worker's (recovered), 2 a foreign endpoint's.
    The foreign-producer probe sees the 2, so the exemption stays PER-ROW: the
    run fails on the 2, states the 4, and never rounds either into the other."""
    _api_log_stub(monkeypatch, _pass_line(pages=2) + "\n")
    ch = _refusal_stub(6, _attribution((BACKFILL_TAG, "netops", 4),
                                       ("endpoint:/api/incidents", "netops", 2)),
                       foreign_241="2\tendpoint:/api/incidents")
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "2 UNEXEMPTED MEMORY_LIMIT_EXCEEDED during this run" in notes
    assert "of 6 raised" in notes
    assert "4 backfill-negotiation refusals exempted, pass completed" in notes
    assert "partial: foreign producers present" in notes
    assert "endpoint:/api/incidents" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["backfill_attributed"] == 4
    assert err["foreign_241"] == 2
    assert err["backfill_exempt"] == 4 and err["counted"] == 2


def test_an_unreadable_api_log_exempts_nothing(tmp_path, monkeypatch):
    """A gate that cannot see must not forgive: no pass evidence is UNKNOWN,
    and UNKNOWN is not recovery."""
    _api_log_stub(monkeypatch, "", rc=1)
    ch = _refusal_stub(4, _attribution((BACKFILL_TAG, "netops", 4)))
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["backfill_passes"] == -1
    assert "unreadable" in err["backfill_pass_source"]
    assert err["backfill_exempt"] == 0 and err["counted"] == 4


def test_an_unreadable_query_log_exempts_nothing(tmp_path, monkeypatch):
    """The other half of the same rule: an attribution probe that cannot answer
    must not read as 'none attributable' NOR as 'all the worker's'."""
    _api_log_stub(monkeypatch, _pass_line() + "\n")
    ch = _refusal_stub(4, _attribution((BACKFILL_TAG, "netops", 4)))

    def refuse(query, timeout=60):
        if "log_comment" in query:
            return False, "Code 60: unknown column log_comment"
        return ch(query, timeout)

    h = _s06(tmp_path, monkeypatch, refuse)
    assert h.memflat() is False
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["backfill_attributed"] == -1
    assert "unreadable" in err["backfill_attribution_source"]
    assert err["backfill_exempt"] == 0 and err["counted"] == 4


def test_a_clean_run_asks_neither_backfill_question(tmp_path, monkeypatch):
    """No refusal, no probes: a healthy run must not pay a docker logs or a
    query_log scan, and its evidence must say the questions were not asked."""
    calls: list = []
    _api_log_stub(monkeypatch, _pass_line() + "\n", calls=calls)
    h = _s06(tmp_path, monkeypatch, _s06_stub(errors=0))
    assert h.memflat() is True
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["counted"] == 0 and err["backfill_exempt"] == 0
    assert err["backfill_attribution_source"] == "not examined (no refusal)"
    assert not [c for c in calls if "logs" in c]


def test_the_exempting_run_does_not_also_claim_no_error_fired(
        tmp_path, monkeypatch):
    """The peak WARN says 'NO MEMORY_LIMIT_EXCEEDED fired'. With refusals
    exempted that sentence would be false in the same report that exempts
    them, so it is withheld."""
    _api_log_stub(monkeypatch, _pass_line() + "\n")
    ch = _refusal_stub(
        4, _attribution((BACKFILL_TAG, "netops", 4)),
        **{"system.metric_log": _metric_log(S06_PEAK_MIB, S06_P99_MIB,
                                            S06_MERGE_MIB, samples=4141)})
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "a transient that touched the ceiling and cost no work" not in notes
    assert "4 backfill-negotiation refusals exempted" in notes


# -- like units: the full-delta exemption (run 083117507rl2) ----------------
#
# `system.errors` counts INCREMENTS — one per throwing thread plus the
# query-level rethrow (max_threads=2 means a refused statement raises 2+) —
# while `system.query_log` counts ROWS, one per statement. Subtracting rows
# from increments manufactured ~5 phantom "unexempted" errors on every
# negotiating run BY CONSTRUCTION (370 increments vs 365 rows; whole-history
# 1160 vs 1133), with zero real victims (part_log: 0 errored merges). The
# fix: when the backfill is the VERIFIED sole 241 producer, exempt the whole
# raised delta; any foreign evidence falls back to the per-row subtraction.


def _negotiating_stub(**overrides):
    """Run 083117507rl2's measured shape: 370 raised increments against 365
    attributed query rows, every row the budgeted worker's own."""
    return _refusal_stub(370, _attribution((BACKFILL_TAG, "netops", 360),
                                           (BACKFILL_PICK_TAG, "netops", 5)),
                         **overrides)


def test_the_measured_370_365_shape_passes_on_the_full_delta(
        tmp_path, monkeypatch):
    """370 increments, 365 rows, sole producer verified: the 5-increment gap
    is thread-fan-out inside the same refusals, not 5 phantom victims, and
    the whole delta is exempt."""
    _api_log_stub(monkeypatch, _pass_line(pages=4) + "\n")
    h = _s06(tmp_path, monkeypatch, _negotiating_stub())
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "370 backfill-negotiation refusals exempted" in notes
    assert "full-delta exemption: sole producer verified" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["window_count"] == 370 and err["delta"] == 370
    assert err["backfill_attributed"] == 365
    assert err["foreign_241"] == 0 and err["part_log_errored"] == 0
    assert err["backfill_exempt"] == 370 and err["counted"] == 0


def test_a_foreign_241_row_falls_back_to_the_per_row_subtraction(
        tmp_path, monkeypatch):
    """One producer that is NOT the backfill refused in the same window: the
    full delta is off the table. The per-row subtraction under-exempts (the
    5 counted here are increments, possibly phantoms) — the honest direction
    when a foreign producer muddies the window — and the foreign producer is
    NAMED so the operator knows why."""
    _api_log_stub(monkeypatch, _pass_line(pages=4) + "\n")
    ch = _negotiating_stub(foreign_241="2\tendpoint:/api/incidents")
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "5 UNEXEMPTED MEMORY_LIMIT_EXCEEDED" in notes
    assert "partial: foreign producers present" in notes
    assert "2x foreign 241 from endpoint:/api/incidents" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["foreign_241"] == 2
    assert err["backfill_exempt"] == 365 and err["counted"] == 5


def test_an_errored_merge_in_part_log_blocks_the_full_delta(
        tmp_path, monkeypatch):
    """Merges never produce a query_log row, so check (c) alone cannot clear
    them: an OOM'd merge shows in part_log as error != 0, and its presence
    means some raised increments may be a BACKGROUND victim's — per-row."""
    _api_log_stub(monkeypatch, _pass_line(pages=4) + "\n")
    ch = _negotiating_stub(**{"system.part_log": "3"})
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "5 UNEXEMPTED MEMORY_LIMIT_EXCEEDED" in notes
    assert "partial: foreign producers present" in notes
    assert "3 errored part op(s) in system.part_log" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["part_log_errored"] == 3
    assert err["backfill_exempt"] == 365 and err["counted"] == 5


def test_unreadable_sole_producer_probes_exempt_nothing(
        tmp_path, monkeypatch):
    """The standing rule extended to checks (c)/(d): a probe that cannot
    answer verifies nothing, and unverified is not sole — NOTHING is exempt,
    not even the per-row subset."""
    _api_log_stub(monkeypatch, _pass_line(pages=4) + "\n")
    ch = _negotiating_stub(**{
        "foreign_241": (False, "Code 60: unknown function"),
        "system.part_log": (False, "Code 60: no such table part_log")})
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is False, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "370 MEMORY_LIMIT_EXCEEDED during this run" in notes
    assert "nothing exempted: sole-producer verification unreadable" in notes
    err = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert err["foreign_241"] == -1 and err["part_log_errored"] == -1
    assert err["backfill_exempt"] == 0 and err["counted"] == 370


def test_MUTANT_dropping_the_foreign_producer_check_forgives_a_foreign_241(
        tmp_path, monkeypatch):
    """THE MUTANT for check (c). Assume 'no foreign producer' without asking
    and the foreign-row run above goes green on the full delta — which is
    what makes the probe load-bearing rather than decorative."""
    _api_log_stub(monkeypatch, _pass_line(pages=4) + "\n")
    monkeypatch.setattr(
        ml, "ch_memory_error_foreign_producers",
        lambda stack, start, end: (0, "", "MUTANT: assumed sole producer"))
    ch = _negotiating_stub(foreign_241="2\tendpoint:/api/incidents")
    h = _s06(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, (
        "the mutant must go green — the foreign-producer probe is the only "
        "thing standing between a foreign 241 and a full-delta exemption")


# -- the two instruments, read directly -------------------------------------

def test_pass_parser_counts_only_completions_with_pages(tmp_path):
    blob = "\n".join([
        "not json at all",
        _early_line(),                                   # the stall line
        json.dumps({"msg": "backfill pass complete", "pages": 0}),
        _pass_line(pages=1),
        "2026-08-31T15:04:00Z stdout " + _pass_line(pages=9),   # prefixed line
    ])
    assert ml.backfill_passes_completed(blob) == 2
    assert ml.backfill_passes_completed(None) == -1
    assert ml.backfill_passes_completed("") == 0


def test_pass_evidence_window_spans_the_whole_run_and_every_replica(
        monkeypatch):
    """The window reaches back to RUN start (preflight), not to burst start —
    a refusal raised before injection began still has its recovery inside the
    window — and every api replica is read."""
    calls: list = []
    _api_log_stub(monkeypatch, _pass_line() + "\n", calls=calls,
                  ids=("netops-api-1", "netops-api-2"))
    h = object.__new__(ml.Harness)
    h.stack = ml.Stack("/nonexistent.env", "http://localhost:8000", "netops")
    h.run_mono_t0 = 1000.0
    h.stability_t0 = 1000.0 + 1500.0        # burst started 1500s into the run
    passes, source = h._backfill_pass_evidence(now=1000.0 + 1800.0)
    assert passes == 2, "every replica is read, not cid()'s first one"
    since = [c[c.index("--since") + 1] for c in calls if "--since" in c]
    assert since and all(int(v.rstrip("s")) >= 1800 for v in since), (
        f"the evidence window is only {since} — it must span the run the "
        "error clause judges, which opens at preflight")
    assert "2 api container log(s)" in source


def test_one_unreadable_replica_is_named_but_the_other_still_counts(
        monkeypatch):
    def fake_run(cmd, timeout, *a, **k):
        if "ps" in cmd:
            return 0, "netops-api-1\nnetops-api-2\n", ""
        if "netops-api-2" in cmd:
            return 1, "", "no such container"
        return 0, _pass_line() + "\n", ""
    monkeypatch.setattr(ml, "run", fake_run)
    h = object.__new__(ml.Harness)
    h.stack = ml.Stack("/nonexistent.env", "http://localhost:8000", "netops")
    h.run_mono_t0 = 0.0
    passes, source = h._backfill_pass_evidence(now=600.0)
    assert passes == 1
    assert "1 replica(s) unreadable" in source


def test_no_api_container_is_unreadable_not_zero(monkeypatch):
    monkeypatch.setattr(ml, "run", lambda cmd, timeout, *a, **k: (0, "", ""))
    h = object.__new__(ml.Harness)
    h.stack = ml.Stack("/nonexistent.env", "http://localhost:8000", "netops")
    h.run_mono_t0 = 0.0
    passes, source = h._backfill_pass_evidence(now=60.0)
    assert passes == -1 and "no running api container" in source


# ── the instrument can be DESTROYED under you: 2026-08-29, mid-task ────────
#
# A config change recreated BOTH `system.metric_log` and `system.error_log`
# while these clauses were being written. Every earlier run's history went with
# them — and a naive `sum(value) WHERE code = 241` over a window the new table
# does not hold answers 0, i.e. "clean", about a run that raised 17. So both
# probes carry a coverage check, and an uncovered window is UNKNOWN.

def test_a_recreated_error_log_never_reads_as_zero(tmp_path, monkeypatch):
    """The exact shape of the false all-clear: rows exist, but the earliest is
    AFTER the run started, so the table cannot have seen the run."""
    ch = _ch_stub(**{
        "system.error_log": _error_log(0, rows=3,
                                       earliest="2026-08-29 16:06:12")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]   # the delta still says 0
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]["memory_limit_exceeded"]
    assert ch_ev["window_state"] == "uncovered"
    assert ch_ev["window_count"] == -1, "never 0 for a window it does not hold"
    assert "only goes back to 2026-08-29 16:06:12" in ch_ev["window_source"]
    assert any("cannot answer for this run" in w
               for w in h.phases[-1]["evidence"]["clickhouse"]["warnings"])


def test_an_empty_error_log_beside_a_zero_delta_is_not_worth_a_warning(
        tmp_path, monkeypatch):
    """The common clean run: no error has ever been raised, so the table is
    empty. Two instruments agreeing is not a broken cross-check, and a gate
    that cries every night is a gate nobody reads."""
    ch = _ch_stub(**{"system.error_log": _error_log(0, rows=0)})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["memory_limit_exceeded"]["window_state"] == "empty"
    assert ch_ev["warnings"] == []


def test_an_empty_error_log_beside_a_NONZERO_delta_does_warn(
        tmp_path, monkeypatch):
    """Errors happened and the timeline holds nothing: the cross-check IS
    broken, and the run cannot say when inside itself they fired."""
    ch = _ch_stub(**{"system.errors": "4",
                     "system.error_log": _error_log(0, rows=0)})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    assert "4 MEMORY_LIMIT_EXCEEDED during this run" in h.phases[-1]["notes"]
    assert any("cannot answer for this run" in w
               for w in h.phases[-1]["evidence"]["clickhouse"]["warnings"])


def test_a_partly_instrumented_metric_log_window_says_so(tmp_path, monkeypatch):
    """metric_log recreated mid-run: the p99 is over the covered tail only, and
    the phase line says that rather than quoting it as the run's p99."""
    ch = _ch_stub(**{"system.metric_log": _metric_log(
        1000, 800, 500, samples=600, first="2026-08-29 07:50:00")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    census = h.phases[-1]["evidence"]["clickhouse"]["sample_census"]
    assert census["metric_log"].startswith("PARTIAL")
    assert census["metric_log_gap_s"] == 3000.0
    assert any("covers only part of this run" in w
               for w in h.phases[-1]["evidence"]["clickhouse"]["warnings"])


def test_a_few_seconds_of_flush_lag_is_not_a_partial_window(tmp_path, monkeypatch):
    """One flush interval of slack: the window opens, the first row lands a
    moment later. That is normal, not a missing instrument."""
    ch = _ch_stub(**{"system.metric_log": _metric_log(
        1000, 800, 500, first="2026-08-29 07:00:07")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["sample_census"]["metric_log"] == "3600 sample(s) in the window"
    assert ch_ev["warnings"] == []


# ── clause 2b: p99 against the cap, and the merge counter as INFORMATION ────

def test_merge_memory_above_the_total_is_reported_and_never_judged(
        tmp_path, monkeypatch):
    """s05's exact numbers: peak 2,952 MiB, p99 1,567 MiB, merge peak 4,084 MiB
    — ABOVE the total, which the old clause called physically impossible and
    failed the run on. On 24.8 the total is process RSS: the merge tracker is
    not bounded by it. PASS, with the merge figure reported and unjudged."""
    ch = _ch_stub(**{"'max_server_memory_usage'": str(4096 * MIB),
                     "system.metric_log": _metric_log(2952, 1567, 4084,
                                                      samples=4773),
                     "system.metrics": (f"MemoryTracking\t{1208 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t{23 * MIB}"),
                     "'MaxPartCountForPartition'": "15"})
    h = _harness(tmp_path, monkeypatch, ch=ch, part_baseline=15,
                 cold_anon=_named({"clickhouse": 900 * MIB}),
                 warm_anon=_named({"clickhouse": 1086 * MIB}),
                 end_anon=_named({"clickhouse": 881 * MIB}))
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_merges_memory_bytes"] == 4084 * MIB
    assert ch_ev["peak_merges_memory_bytes"] > ch_ev["peak_memory_tracking_bytes"]
    assert "INFORMATIONAL" in ch_ev["merges_memory_verdict"]
    assert "not bounded by the tracked total" in ch_ev["merges_memory_verdict"]
    notes = h.phases[-1]["notes"]
    assert "merges 4084 MiB INFORMATIONAL, no verdict" in notes
    # Nothing about impossibility, and no merge-fraction verdict of any kind.
    assert "impossible" not in notes and "UNKNOWN" not in notes
    assert "99.7%" not in notes


def test_healthy_clickhouse_memory_passes(tmp_path, monkeypatch):
    h = _ch(tmp_path, monkeypatch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["memory_tracking_pct"] == pytest.approx(20.9, abs=0.2)
    assert ch_ev["p99_memory_tracking_pct"] == pytest.approx(16.7, abs=0.2)
    assert ch_ev["degraded"] is False


def test_explicit_max_server_memory_usage_wins_over_the_ratio(tmp_path, monkeypatch):
    ch = _ch_stub(**{"'max_server_memory_usage'": str(2000 * MIB),
                     "system.metric_log": _metric_log(1990, 1900, 100)})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["cap_source"] == "server_settings.max_server_memory_usage"
    assert ch_ev["p99_memory_tracking_pct"] == 95.0


def test_host_derived_cap_is_named_as_such(tmp_path, monkeypatch):
    """CGroupMemoryTotal invisible ⇒ the cap is the HOST's — the very trap that
    makes merges_mutations_memory_usage_soft_limit inert in a container."""
    h = _ch(tmp_path, monkeypatch, _ch_stub(**{"'CGroupMemoryTotal'": ""}))
    h.memflat()
    assert "HOST-derived" in h.phases[-1]["evidence"]["clickhouse"]["cap_source"]


def test_unmeasurable_cap_fails_rather_than_passing_blind(tmp_path, monkeypatch):
    ch = _ch_stub(**{"'CGroupMemoryTotal'": "", "'OSMemoryTotal'": "",
                     "'max_server_memory_usage_to_ram_ratio'": ""})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    assert "unreadable" in h.phases[-1]["notes"]
    assert "must not pass blind" in h.phases[-1]["notes"]


def test_negative_merge_counter_is_not_a_uint64_wrap(tmp_path, monkeypatch):
    """MergesMutationsMemoryTracking reads slightly negative on an idle server;
    read as UInt64 that becomes 1.8e19 and fails the gate at 3.7e11 % of cap."""
    ch = _ch_stub(**{"system.metric_log":
                     f"{900 * MIB}\t{800 * MIB}\t-4096\t3600\t{WINDOW_START}",
                     "system.metrics": (f"MemoryTracking\t{900 * MIB}\n"
                                        f"MergesMutationsMemoryTracking\t-4096")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert h.phases[-1]["evidence"]["clickhouse"]["peak_merges_memory_bytes"] == 0


# ── clause 2b, DEGRADED: metric_log is optional and its absence is loud ─────

def test_metric_log_absent_degrades_to_harness_samples_and_says_so(
        tmp_path, monkeypatch):
    """A builder may lower metric_log's cadence, and changing its <engine>
    makes ClickHouse rename the table on restart. Its absence costs the p99 —
    the harness's own samples still carry a peak, and the clause judges THAT
    in the p99's place rather than passing blind."""
    ch = _ch_stub(**{
        "system.metric_log": ("", "table system.metric_log doesn't exist"),
        "system.metrics": (f"MemoryTracking\t{4566 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{100 * MIB}")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["peak_source"] == "harness system.metrics samples"
    assert ch_ev["degraded"] is True
    assert ch_ev["p99_memory_tracking_bytes"] == -1
    assert ch_ev["memory_tracking_pct"] == 95.3
    notes = h.phases[-1]["notes"]
    assert "p99 MemoryTracking UNMEASURED" in notes
    assert "DEGRADED to 1 harness system.metrics sample(s)" in notes
    assert "judged in the p99's place" in notes
    assert "UNAVAILABLE" in ch_ev["sample_census"]["metric_log"]


def test_metric_log_present_but_empty_for_the_window_is_also_degraded(
        tmp_path, monkeypatch):
    """Zero rows is not a flat server. It is a missing instrument."""
    ch = _ch_stub(**{"system.metric_log": f"0\t0\t0\t0\t{WINDOW_START}"})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    ch_ev = h.phases[-1]["evidence"]["clickhouse"]
    assert ch_ev["degraded"] is True
    assert ch_ev["sample_census"]["metric_log"] == (
        "present but held 0 samples for this run's window")
    # The peak came from the harness's own live sample, never read as 0.
    assert ch_ev["peak_memory_tracking_bytes"] == 900 * MIB
    assert "p99 MemoryTracking UNMEASURED" in h.phases[-1]["notes"]


def test_a_degraded_run_with_no_sample_at_all_is_UNKNOWN(tmp_path, monkeypatch):
    """metric_log gone AND system.metrics gone: nothing is measured, so the
    clause refuses. UNKNOWN is a FAIL here, never a PASS."""
    ch = _ch_stub(**{
        "system.metric_log": ("", "table system.metric_log doesn't exist"),
        "system.metrics": ("", "connection refused")})
    h = _ch(tmp_path, monkeypatch, ch)
    assert h.memflat() is False
    assert "MemoryTracking unmeasurable" in h.phases[-1]["notes"]
    assert "cannot be judged" in h.phases[-1]["notes"]


# ── clause 3: the store settles its parts after input stops ────────────────

def test_parts_above_the_envelope_fail_after_the_settle_budget(tmp_path, monkeypatch):
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "927"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=180)
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
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=180)
    assert h.memflat() is True, h.phases[-1]["notes"]
    parts = h.phases[-1]["evidence"]["clickhouse"]["parts"]
    assert parts["current"] == 200 and parts["settle_waited_s"] == 30.0


def test_parts_near_the_insert_delay_threshold_fail(tmp_path, monkeypatch):
    """Settled relative to a HIGH baseline is still inside the throttle band."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "520",
                     "'parts_to_delay_insert'": "1000"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=600)
    assert h.memflat() is False
    assert "HALF of parts_to_delay_insert" in h.phases[-1]["notes"]


def test_small_baselines_get_an_absolute_part_floor(tmp_path, monkeypatch):
    """+20 % of 3 parts is 3.6 — a 4th part must not fail the run."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "9"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=3)
    assert h.memflat() is True, h.phases[-1]["notes"]
    assert h.phases[-1]["evidence"]["clickhouse"]["parts"]["envelope"] == 11.0


def test_unmeasurable_part_count_fails(tmp_path, monkeypatch):
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": ""})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock)
    assert h.memflat() is False
    assert "MaxPartCountForPartition unmeasurable" in h.phases[-1]["notes"]


def test_a_zero_part_preflight_is_a_baseline_not_an_unknown(tmp_path,
                                                            monkeypatch):
    """An idle, freshly-merged store preflights at ZERO parts — the CLEANEST
    baseline there is. `int(base or -1)` read that as "unmeasurable" and
    abandoned clause (3) on exactly the runs whose part growth is most legible
    (the same `or` defect the ch_mem_errors probe carried). Only a MISSING or
    unparsable value is unmeasurable."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "4"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=0)
    assert h.memflat() is True, h.phases[-1]["notes"]
    parts = h.phases[-1]["evidence"]["clickhouse"]["parts"]
    assert parts["baseline"] == 0, "a 0-part preflight was reported as -1"
    assert parts["current"] == 4
    # max(0 x 1.2, 0 + FLOOR) — the absolute floor, not the unmeasurable -1
    assert parts["envelope"] == float(ml.CH_PART_COUNT_FLOOR)
    assert "unmeasurable" not in h.phases[-1]["notes"]


def test_a_zero_part_preflight_still_fails_a_real_part_explosion(tmp_path,
                                                                 monkeypatch):
    """…and the clause it rescues must still be able to FAIL: a 0-part
    baseline is the strictest envelope, not a free pass."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "900"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock, part_baseline=0)
    assert h.memflat() is False
    assert "parts NEVER SETTLED" in h.phases[-1]["notes"]


def test_a_missing_part_baseline_is_still_unmeasurable(tmp_path, monkeypatch):
    """The other direction: no preflight value at all (the probe never ran)
    must STILL refuse to judge — a memory gate may not pass blind."""
    clock = FakeClock()
    ch = _ch_stub(**{"'MaxPartCountForPartition'": "12"})
    h = _ch(tmp_path, monkeypatch, ch, clock=clock)
    h.baseline.pop("ch_max_part_count")
    assert h.memflat() is False
    assert "MaxPartCountForPartition unmeasurable" in h.phases[-1]["notes"]


# ── every number reaches the operator ──────────────────────────────────────

def test_phase_line_prints_every_clause(tmp_path, monkeypatch):
    h = _ch(tmp_path, monkeypatch)
    assert h.memflat() is True, h.phases[-1]["notes"]
    notes = h.phases[-1]["notes"]
    assert "clickhouse anon 994 MiB (x1.01 vs anchor)" in notes
    assert "MEMORY_LIMIT_EXCEEDED +0" in notes
    assert f"p99 MemoryTracking 800 MiB = 16.7% of cap {CAP_MIB} MiB" in notes
    assert "peak 1000 MiB = 20.9%" in notes
    assert "merges 500 MiB INFORMATIONAL, no verdict" in notes
    assert "MaxPartCountForPartition 180 (preflight 180, envelope 216.0" in notes
    assert "delay at 1000)" in notes


# ── --rescore-memflat: what the corrected clauses say about a FINISHED run ──
#
# A run costs an hour. Re-running one to find out what a fixed clause says
# about it is not the answer: the run's own evidence plus a read-only
# metric_log / error_log query for its window is. It writes
# memflat-rescore-v2.md — VERSIONED, so it can never overwrite the v1 file the
# superseded clause wrote — and NEVER touches the run's own report files.

def _rescore_stack(**overrides):
    """A Stack stand-in answering the re-score's read-only probes."""
    inner = _ch_stub(**overrides)
    return type("S", (), {"ch": staticmethod(inner)})()


def test_rescore_reproduces_s06s_verdict_the_errors_not_the_peak():
    stack = _rescore_stack(**{
        "'max_server_memory_usage'": str(S06_CAP_MIB * MIB),
        "system.metric_log": _metric_log(S06_PEAK_MIB, S06_P99_MIB,
                                         S06_MERGE_MIB, samples=4141,
                                         first="2026-08-29 14:21:00"),
        "system.error_log": _error_log(17, rows=40),
        "system.query_log": "Insert\tnetops.findings\t2"})
    ev, problems = ml._rescore_clickhouse(
        stack, "2026-08-29 14:21:00", "2026-08-29 15:30:00")
    assert ev["memory_limit_exceeded"] == 17
    assert any("17 MEMORY_LIMIT_EXCEEDED in the window" in p for p in problems)
    assert "2x Insert on netops.findings" in ev["victims"]
    assert "the other 15 were raised in BACKGROUND threads" in ev["victims"]
    # The level clause is NOT what failed: p99 is 39 % of the cap.
    assert ev["p99_memory_tracking_pct"] == pytest.approx(39.0, abs=0.2)
    assert ev["memory_tracking_pct"] == pytest.approx(107.6, abs=0.2)
    assert not any("p99 MemoryTracking" in p for p in problems)
    assert ev["warnings"] and "a transient" in ev["warnings"][0]


def test_rescore_passes_s05_on_the_same_instrument():
    """Same window shape, zero refusals, merge peak above the total: PASS."""
    stack = _rescore_stack(**{
        "'max_server_memory_usage'": str(4096 * MIB),
        "system.metric_log": _metric_log(2952, 1567, 4084, samples=4773,
                                         first="2026-08-29 11:38:29"),
        "system.error_log": _error_log(0, rows=9)})
    ev, problems = ml._rescore_clickhouse(
        stack, "2026-08-29 11:38:28", "2026-08-29 12:58:00")
    assert not problems, problems
    assert ev["memory_limit_exceeded"] == 0
    assert ev["p99_memory_tracking_pct"] == pytest.approx(38.3, abs=0.2)
    assert ev["memory_tracking_pct"] == pytest.approx(72.1, abs=0.2)
    assert ev["peak_merges_memory_bytes"] == 4084 * MIB
    assert "INFORMATIONAL" in ev["merges_memory_verdict"]
    assert ev["warnings"] == []


def test_rescore_still_reports_a_genuine_sustained_breach():
    """The re-score is a correction, not an amnesty."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(**{"'max_server_memory_usage'": str(4096 * MIB),
                          "system.metric_log": _metric_log(
                              3900, 3700, 100, first="2026-08-29 11:39:00")}),
        "2026-08-29 11:39:00", "")
    assert any("p99 MemoryTracking" in p for p in problems)
    assert ev["p99_memory_tracking_pct"] == pytest.approx(90.3, abs=0.2)


def test_rescore_without_metric_log_is_UNKNOWN_never_a_PASS():
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(**{"system.metric_log":
                          ("", "table system.metric_log doesn't exist")}),
        "2026-08-29 11:39:00", "")
    assert any("clause (2b) is UNKNOWN" in p for p in problems)
    assert any("not a PASS" in p for p in problems)
    assert "UNAVAILABLE" in ev["metric_log"]


def test_rescore_without_error_log_is_UNKNOWN_never_a_PASS():
    """query_log cannot stand in: it saw 2 of s06's 17."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(**{"system.error_log":
                          ("", "table system.error_log doesn't exist")}),
        "2026-08-29 11:39:00", "")
    assert ev["memory_limit_exceeded"] == -1
    assert any("clause (2a) is UNKNOWN" in p for p in problems)
    assert any("sees only statement raises" in p for p in problems)


def test_rescore_of_a_recreated_error_log_is_UNKNOWN_not_a_clean_run():
    """WHAT ACTUALLY HAPPENED on 2026-08-29 16:06: a config change recreated
    error_log, and the re-score of two earlier runs found a table that starts
    after both of them. 0 in that window is not zero errors — it is no data."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(**{"system.error_log": _error_log(
            0, rows=1, earliest="2026-08-29 16:06:12")}),
        "2026-08-29 14:21:00", "2026-08-29 15:30:00")
    assert ev["memory_limit_exceeded"] == -1
    assert ev["memory_limit_exceeded_state"] == "uncovered"
    assert any("clause (2a) is UNKNOWN" in p for p in problems)
    assert any("only goes back to 2026-08-29 16:06:12" in p for p in problems)


def test_rescore_of_an_empty_window_publishes_no_peak_at_all():
    """`max()`/`quantileExact()` over an empty set are 0 in ClickHouse, and a
    0 MiB "peak" would read as the flattest server ever measured. A window with
    no samples publishes NO level at all."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(**{"system.metric_log": _metric_log(0, 0, 0, samples=0)}),
        "2026-08-29 14:21:00", "2026-08-29 15:30:00")
    assert ev["total_samples"] == 0
    assert "peak_memory_tracking_bytes" not in ev
    assert "p99_memory_tracking_bytes" not in ev
    assert any("UNKNOWN, never a PASS" in p for p in problems)


def test_rescore_names_a_partly_instrumented_window():
    stack = _rescore_stack(**{
        "'max_server_memory_usage'": str(4096 * MIB),
        "system.metric_log": _metric_log(2000, 1200, 300, samples=400,
                                         first="2026-08-29 12:30:00"),
        "system.error_log": _error_log(0, rows=9)})
    ev, problems = ml._rescore_clickhouse(
        stack, "2026-08-29 11:38:28", "2026-08-29 12:58:00")
    assert not problems, problems
    assert ev["metric_log"].startswith("PARTIAL")
    assert any("covers only part of the window" in w for w in ev["warnings"])


def test_rescore_refuses_a_window_it_cannot_trust():
    """The window is spliced into SQL. A malformed one is dropped, and the
    re-score answers UNKNOWN rather than widening to all of history."""
    ev, problems = ml._rescore_clickhouse(
        _rescore_stack(), "yesterday-ish", "")
    assert any("no run window" in p for p in problems)
    assert "peak_memory_tracking_bytes" not in ev


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


def test_rescore_writes_a_VERSIONED_file_and_never_the_runs_own_reports(
        tmp_path, monkeypatch):
    """The original verdict is the record of what the gate said at the time,
    and the v1 re-score is the record of what the superseded clause said."""
    (tmp_path / "report.json").write_text(json.dumps({"phases": [
        {"phase": "memflat", "status": "FAIL", "notes": "the original",
         "evidence": {"containers": [], "clickhouse": {
             "sample_census": {"window_start": "2026-08-29 11:39:00"}}}}]}),
        encoding="utf-8")
    (tmp_path / "report.md").write_text("original md", encoding="utf-8")
    (tmp_path / "memflat-rescore.md").write_text("v1 rescore", encoding="utf-8")
    before = ((tmp_path / "report.json").read_text(),
              (tmp_path / "report.md").read_text(),
              (tmp_path / "memflat-rescore.md").read_text())
    monkeypatch.setattr(ml, "Stack", lambda *a, **k: _rescore_stack(**{
        "'max_server_memory_usage'": str(4096 * MIB),
        "system.metric_log": _metric_log(2952, 1567, 4084, samples=4773,
                                         first="2026-08-29 11:39:00"),
        "system.error_log": _error_log(0, rows=9)}))
    args = ml.parse_args(["--rescore-memflat", str(tmp_path)])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    assert ml.rescore_memflat(args) == 1, "correlation is UNKNOWN => not PASS"
    assert ((tmp_path / "report.json").read_text(),
            (tmp_path / "report.md").read_text(),
            (tmp_path / "memflat-rescore.md").read_text()) == before
    assert ml.RESCORE_FILE == "memflat-rescore-v2.md"
    doc = (tmp_path / ml.RESCORE_FILE).read_text()
    assert "**MEMORY_LIMIT_EXCEEDED: 0**" in doc
    assert "p99 MemoryTracking: **1567 MiB**" in doc
    assert "THE JUDGED NUMBER" in doc
    assert "peak MemoryTracking: **2952 MiB**" in doc
    assert "peak MergesMutationsMemoryTracking: 4084 MiB" in doc
    assert "process RSS set from the OS" in doc
    assert "clause (2): PASS" in doc
    assert "the original" in doc, "the original verdict is quoted, not erased"


def test_rescore_refuses_without_a_window():
    """No window => no re-score. Guessing one would judge another run."""
    args = ml.parse_args(["--rescore-memflat", "/nonexistent-run-dir"])
    with pytest.raises(SystemExit):
        ml.rescore_memflat(args)
