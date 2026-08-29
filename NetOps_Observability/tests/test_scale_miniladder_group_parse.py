"""Consumer-group membership parsing in the G2 mini-ladder preflight.

REGRESSION (CI run 31991056443, 2026-08-17 03:19 UTC — the workflow's first
scheduled run): preflight FAILED with "netops-correlation has NO active
consumer … netops-router-syslog has NO active consumer (ingest router dead)"
before any load, while `docker compose ps -a` in the same job showed
correlation and vector-router "Up 6 minutes (healthy)" and install.py's own
gate had reported "bus alive: consumer group netops-correlation holds active
membership through the enforcing broker" 27 seconds earlier on the same broker.

Root cause: `kafka-consumer-groups.sh --describe` prints `-` in CURRENT-OFFSET
and LAG for a partition a LIVE member holds but has never committed. The
harness parsed LAG FIRST (`int(f[5])`) and `continue`d on ValueError, dropping
the row before counting CONSUMER-ID — so a healthy, freshly-installed stack
(nothing produced yet ⇒ nothing committed) read as `{_total: 0, _members: 0}`,
byte-identical to the dead-consumer verdict it was written to catch. It never
fired on the lab host because traffic there had always committed offsets by
run time.

The fixtures below are REAL CLI output shapes:
  UNCOMMITTED_OUT — captured live 2026-08-17 against apache/kafka 4.1.1 on the
                    TLS mesh (a console consumer joined with
                    enable.auto.commit=false).
  DEAD_GROUP_OUT  — the 2026-08-16 wiped-ACL signature (offsets, zero members).

Run:  python3 -m pytest tests/test_scale_miniladder_group_parse.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install  # noqa: E402  — path set above


def _load_harness():
    """Import the hyphen-named harness by path.

    PATH is asserted unchanged across the import: the harness's cron-proof PATH
    (§16.2) is applied in main(), NOT at module scope, because as module-scope
    code it leaked into the pytest process and hid the developer's
    ~/.local/bin — the shellcheck-based suites then failed with 'No such file
    or directory: shellcheck' whenever a harness test shared their run. This
    assertion keeps the import side-effect-free.
    """
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    before = os.environ.get("PATH", "")
    sys.modules["scale_miniladder"] = mod
    spec.loader.exec_module(mod)
    assert os.environ.get("PATH", "") == before, (
        "importing the harness must not mutate PATH — pin it in main() instead")
    return mod


ml = _load_harness()

HEADER = ("GROUP              TOPIC               PARTITION  CURRENT-OFFSET  "
          "LOG-END-OFFSET  LAG             CONSUMER-ID  HOST  CLIENT-ID\n")

# LIVE member, nothing committed yet — the CI shape. Verbatim column values as
# captured from the broker (only the ids shortened).
UNCOMMITTED_OUT = HEADER + (
    "netops-correlation netops.syslog       0          -               0    "
    "           -               aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
    "netops-correlation netops.flows        0          -               0    "
    "           -               aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
)

# LIVE member that HAS committed (the lab shape).
COMMITTED_OUT = HEADER + (
    "netops-correlation netops.syslog       0          1070            1073 "
    "           3               aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
)

# DEAD consumer: committed offsets frozen, LAG growing, CONSUMER-ID `-`.
DEAD_GROUP_OUT = HEADER + (
    "netops-correlation netops.syslog       0          12              99   "
    "           87              -            -     -\n"
)

# Multi-partition live member with a mix of committed and uncommitted
# partitions (a repartitioned topic must not silently lose lag).
MIXED_PARTITIONS_OUT = HEADER + (
    "netops-correlation netops.syslog       0          10              20   "
    "           10              aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
    "netops-correlation netops.syslog       1          -               5    "
    "           -               aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
    "netops-correlation netops.syslog       2          4               9    "
    "           5               aiokafka-1-abc /172.18.0.9 aiokafka-1\n"
)

# `--describe` on a group the broker has never seen.
UNKNOWN_GROUP_OUT = ("Consumer group 'netops-correlation' does not exist.\n")


class FakeStack:
    """Minimal stand-in for ml.Stack: only kafka_tool is exercised."""

    def __init__(self, results):
        # list of (rc, stdout, stderr); the last entry repeats.
        self.results = list(results)
        self.calls = 0

    def kafka_tool(self, tool, args, **kwargs):
        self.calls += 1
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


def group_lag(out: str, rc: int = 0, err: str = "") -> dict:
    stack = FakeStack([(rc, out, err)])
    return ml.Stack.group_lag(stack, "netops-correlation")


# ── the regression itself ────────────────────────────────────────────────────

def test_live_member_without_committed_offsets_counts_as_a_member():
    """THE run-31991056443 BUG. A `-` LAG must never hide a live CONSUMER-ID."""
    g = group_lag(UNCOMMITTED_OUT)
    assert g["_members"] == 2, "a joined-but-uncommitted member is still a member"
    assert g["_rows"] == 2
    assert g["_uncommitted"] == 2
    assert g["_total"] == 0            # nothing committed ⇒ nothing lagging
    assert g["netops.syslog"]["end"] == 0


def test_dead_consumer_still_fails_closed():
    """The signal the check exists for must survive the fix."""
    g = group_lag(DEAD_GROUP_OUT)
    assert g["_members"] == 0
    assert g["_rows"] == 1             # rows present ⇒ 'dead', not 'unknown'
    assert g["_total"] == 87


def test_committed_live_member_unchanged():
    g = group_lag(COMMITTED_OUT)
    assert g["_members"] == 1 and g["_total"] == 3
    assert g["netops.syslog"] == {"current": 1070, "end": 1073, "lag": 3}


def test_unknown_group_is_distinguishable_from_dead_consumer():
    g = group_lag(UNKNOWN_GROUP_OUT)
    assert g["_members"] == 0
    assert g["_rows"] == 0, "no rows ⇒ the group is unknown to the broker"


def test_describe_failure_is_never_a_silent_zero():
    g = group_lag("", rc=1, err="Connection to node -1 could not be established")
    assert g["_error"] and g["_total"] == -1 and g["_members"] == 0


def test_multi_partition_lag_is_aggregated_not_overwritten():
    g = group_lag(MIXED_PARTITIONS_OUT)
    assert g["_members"] == 3
    assert g["_uncommitted"] == 1
    assert g["_total"] == 15                       # 10 + 5, the `-` row adds 0
    assert g["netops.syslog"]["lag"] == 15
    assert g["netops.syslog"]["end"] == 20         # max across partitions
    assert g["netops.syslog"]["current"] == 4      # min committed


def test_other_groups_rows_are_ignored():
    other = HEADER + (
        "netops-router-syslog netops.syslog     0          -               0 "
        "              -               vector-abc /172.18.0.8 vector\n"
    )
    g = group_lag(other)
    assert g["_members"] == 0 and g["_rows"] == 0


# ── cross-parser agreement with the installer's gate ────────────────────────

@pytest.mark.parametrize("out,expected", [
    (UNCOMMITTED_OUT, 2),
    (COMMITTED_OUT, 1),
    (DEAD_GROUP_OUT, 0),
    (UNKNOWN_GROUP_OUT, 0),
    (MIXED_PARTITIONS_OUT, 3),
])
def test_harness_and_installer_agree_on_membership(out, expected):
    """install.py's verify_bus_consumers and this preflight must NEVER disagree
    about the same broker: run 31991056443 had the installer PASS and the
    harness FAIL 27s apart on identical output. install._kafka_group_members is
    the reference implementation (it never touched the offset columns)."""
    assert install._kafka_group_members(out, "netops-correlation") == expected
    assert group_lag(out)["_members"] == expected


# ── the bounded settle wait (cold-runner bring-up, not a softened check) ────

def test_preflight_settle_default_and_flag():
    assert ml.parse_args([]).consumer_settle_seconds == 180
    assert ml.parse_args(
        ["--consumer-settle-seconds", "300"]).consumer_settle_seconds == 300


# ── memflat: warm-anchored leak slope + cap headroom ────────────────────────
#
# Second false negative from the same validation run (32040415877): the phase
# FAILED on clickhouse x2.84 and correlation x3.15 measured from a COLD
# baseline, while both sat at ~25% of their own caps and every other container
# moved <=x1.15. Those are first-touch cache/window materialization, bounded by
# design; a cold->end ratio cannot tell them from a leak.

MIB = 1024 ** 2


def _healthy_ch(query, timeout=60):
    """ClickHouse answering memflat's clause-2/3 probes healthily (2026-08-29).

    These tests are about the SLOPE, not about ClickHouse's own accounting;
    stubbing keeps them hermetic (nothing here may touch a live stack) and
    leaves the ClickHouse clauses green so the slope verdict is what is being
    asserted. Their own tests live in tests/test_miniladder_memflat_clickhouse.py.
    """
    answers = {
        "toString(now())": "2026-08-29 07:00:00",
        "'max_server_memory_usage'": "0",
        "'max_server_memory_usage_to_ram_ratio'": "0.9",
        "'CGroupMemoryTotal'": "5584715776",
        "'OSMemoryTotal'": "16764780544",
        # peak, p99, merge peak, sample count and the earliest in-window
        # sample — see tests/test_miniladder_memflat_clickhouse.py for the
        # ClickHouse clauses' own tests.
        "system.metric_log": (f"{1000 * MIB}\t{800 * MIB}\t{500 * MIB}"
                              f"\t3600\t2026-08-29 07:00:00"),
        "system.metrics": (f"MemoryTracking\t{900 * MIB}\n"
                           f"MergesMutationsMemoryTracking\t{400 * MIB}"),
        # The MEMORY_LIMIT_EXCEEDED clause (2026-08-29): the lifetime counter,
        # and the error_log timeline as (in-window count, total rows, earliest
        # row) — a clean server that has never raised one.
        "system.errors": "0",
        "system.error_log": "0\t0\t1970-01-01 00:00:00",
        "'MaxPartCountForPartition'": "180",
        "'parts_to_delay_insert'": "1000",
    }
    for key, value in answers.items():
        if key in query:
            return True, value
    return False, f"unstubbed probe: {query[:120]}"


def _converged_track(name, rss_at_pending_zero, *, ago=3600.0,
                     first_pending=22736.0, samples=200, t_s=1986.0):
    """One correlation replica that DID drain its backlog, `ago` seconds back.

    memflat anchors correlation on the first sample where that replica reports
    `corr_engine_pending == 0` (2026-08-29); this is the shape the completion
    phase leaves behind for it.
    """
    return {name: {"container": name, "samples": samples,
                   "pending_zero_resets": 0, "pending_zero_t_s": t_s,
                   "pending_zero_monotonic": ml.time.monotonic() - ago,
                   "rss_at_pending_zero": rss_at_pending_zero,
                   "last_pending": 0.0, "last_rss": rss_at_pending_zero,
                   "last_t_s": t_s, "first_pending": first_pending,
                   "first_rss": rss_at_pending_zero}}


def _memflat_harness(tmp_path, cold, warm, end_stats, anon=None,
                     corr_track=None, **flags):
    argv = ["--run-dir", str(tmp_path)]
    for k, v in flags.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    args = ml.parse_args(argv)
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    h.baseline["mem"] = cold
    h.warm_mem = warm
    # Stateful services are judged on cgroup anon since 2026-08-29 (docker
    # stats is ~68% page cache). These fixtures predate that split and mean
    # "the container's memory", so anon mirrors them unless a test says
    # otherwise — the numbers under test are unchanged.
    cold_anon, warm_anon, end_anon = anon or (
        cold, warm, {n: v["used"] for n, v in end_stats.items()})
    h.baseline["mem_anon"] = cold_anon
    h.warm_anon = warm_anon
    h.baseline["ch_window_start"] = "2026-08-29 07:00:00"
    h.baseline["ch_max_part_count"] = 180
    h.baseline["ch_mem_errors"] = 0
    h.stack.mem_stats = lambda: end_stats            # type: ignore[assignment]
    h.stack.anon_sample = lambda services: dict(end_anon)  # type: ignore[assignment]
    h.stack.ch = _healthy_ch                         # type: ignore[assignment]
    # Correlation is anchored on the ENGINE's pending-zero sample since
    # 2026-08-29, not on "the instant input stopped". Unless a test says
    # otherwise, every correlation replica in the fixture converged long ago at
    # its warm figure — i.e. these pre-existing fixtures keep meaning exactly
    # what they meant, and the pending-zero clause has its own tests below.
    if corr_track is None:
        corr_track = {}
        for cname in end_stats:
            if "-correlation-" in cname:
                corr_track.update(_converged_track(
                    cname, warm.get(cname, -1) if warm else -1))
    h.corr_mem_track = dict(corr_track)
    return h


def _named(d):
    return {f"netops-{k}-1": v for k, v in d.items()}


# The measured CI shape: big cold->warm step, flat afterwards, far from caps.
CI_COLD = _named({"clickhouse": 474 * MIB, "correlation": 59 * MIB})
CI_WARM = _named({"clickhouse": 1300 * MIB, "correlation": 180 * MIB})
CI_END = _named({
    "clickhouse": {"used": 1349 * MIB, "limit": 5326 * MIB},
    "correlation": {"used": 187 * MIB, "limit": 789 * MIB},
})


def test_cold_start_cache_materialization_is_not_a_leak(tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "MEM_SERVICES", ["clickhouse", "correlation"])
    h = _memflat_harness(tmp_path, CI_COLD, CI_WARM, CI_END)
    assert h.memflat() is True, "the run-32040415877 numbers must PASS"
    ev = h.phases[-1]["evidence"]
    assert ev["anchor"].startswith("warm")
    ch = next(r for r in ev["containers"] if r["container"] == "netops-clickhouse-1")
    # The cold->end step is still REPORTED, just not judged.
    assert ch["ratio_cold_to_end"] == 2.846 or ch["ratio_cold_to_end"] > 2.8
    assert ch["pct_of_limit"] == 25.3


def test_leak_after_input_stops_still_fails(tmp_path, monkeypatch):
    """The invariant the phase exists for: growth once nothing is arriving."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    end = _named({"correlation": {"used": 400 * MIB, "limit": 789 * MIB}})
    h = _memflat_harness(tmp_path, _named({"correlation": 59 * MIB}),
                         _named({"correlation": 180 * MIB}), end)
    assert h.memflat() is False
    assert "LEAK SLOPE" in h.phases[-1]["notes"]


def test_container_near_its_own_cap_fails_even_when_flat(tmp_path, monkeypatch):
    """The OOM path: flat but at 95% of cap is one burst from a kill."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["opensearch"])
    end = _named({"opensearch": {"used": 3550 * MIB, "limit": 3690 * MIB}})
    h = _memflat_harness(tmp_path, _named({"opensearch": 3500 * MIB}),
                         _named({"opensearch": 3540 * MIB}), end)
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "% of its" in notes and "OOM" in notes


def test_missing_warm_sample_falls_back_loudly(tmp_path, monkeypatch):
    """burst() never completed ⇒ say which anchor was used; never pass blind."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["clickhouse"])
    h = _memflat_harness(tmp_path, CI_COLD, {},
                         _named({"clickhouse": {"used": 1349 * MIB, "limit": 5326 * MIB}}))
    h.memflat()
    assert "cold baseline" in h.phases[-1]["evidence"]["anchor"]


def test_absent_sample_is_a_failure_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "MEM_SERVICES", ["clickhouse"])
    h = _memflat_harness(tmp_path, {}, {}, {})
    assert h.memflat() is False
    # Wording pinned to the CURRENT contract: the 2026-08-24 replica-discovery
    # fix (judge every `<project>-<svc>-N` seen in any sample, instead of a
    # hardcoded -1 index) renamed this problem from "no memory sample" to name
    # the replica pattern that was not found. The old substring was left behind
    # by that change; the phase's behaviour — absent sample is a FAIL, asserted
    # on the line above — never changed.
    assert "no replica seen in any memory sample" in h.phases[-1]["notes"]


def test_mem_stats_parses_docker_usage_and_limit():
    parse = ml.Stack._mem_bytes
    assert parse("1.286GiB") == int(1.286 * 1024 ** 3)
    assert parse("474.3MiB") == int(474.3 * 1024 ** 2)
    assert parse("--") == -1


def test_ci_workflow_allows_a_longer_settle_than_the_lab_default():
    """The cold shared runner spends a JVM per topic in kafka-init (run
    31991056443: the last of 16 topics appeared ~7 min after boot), so the CI
    leg must pass a wait at least as long as the default — and must never
    disable the consumer assertion."""
    wf = ROOT.parent / ".github" / "workflows" / "scale-miniladder-nightly.yml"
    if not wf.exists():                       # tests may run from a subtree copy
        pytest.skip("workflows not present in this checkout")
    text = wf.read_text()
    assert "--consumer-settle-seconds" in text
    # The flag name also appears in the explanatory comment; only the actual
    # invocation is followed by a bare integer.
    values = [int(m) for m in re.findall(
        r"--consumer-settle-seconds\s+(\d+)", text)]
    assert values, "the harness invocation must pass an explicit settle value"
    assert min(values) >= ml.parse_args([]).consumer_settle_seconds


# ── memflat's correlation anchor: pending==0, not "input stopped" ──────────
#
# THE FALSE FAIL THIS PINS (run p2-s05-08291138, 2026-08-29):
#
#   [FAIL] memflat — netops-correlation-3: LEAK SLOPE (docker_stats)
#          470 -> 647 MiB (x1.37 > x1.3) after input stopped
#
# True, and beside the point: 22,736 signals were still PENDING in that
# replica's engine at the anchor sample, and correlation_completion measured
# the drain at 1,986 s. The engine builds objects for a backlog it accepted
# before input stopped; a working set that grows while a queue drains is the
# queue. The anchor is now the first sample where THAT replica reports
# corr_engine_pending == 0, with a >=120 s settle before the end sample.

class _Clock:
    """Virtual clock so the settle wait never costs the suite real seconds."""

    def __init__(self, t: float = 0.0) -> None:
        self.t, self.slept = t, 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept += seconds
        self.t += seconds


CORR = "netops-correlation-3"
CORR_LIMIT = 1280 * MIB


def _corr_harness(tmp_path, *, at_input_stop, at_end, track, **flags):
    end_stats = {CORR: {"used": at_end, "limit": CORR_LIMIT}}
    return _memflat_harness(tmp_path, {CORR: 60 * MIB}, {CORR: at_input_stop},
                            end_stats, corr_track=track, **flags)


def test_a_backlog_drain_is_not_a_leak(tmp_path, monkeypatch):
    """The p2-s05 numbers: x1.37 from input stop, x1.16 from pending 0."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=_converged_track(CORR, 560 * MIB))
    assert h.memflat() is True, h.phases[-1]["notes"]
    row = h.phases[-1]["evidence"]["containers"][0]
    assert row["anchor"] == "corr_engine_pending==0"
    assert row["verdict"] == "FLAT"
    assert row["rss_at_input_stop"] == 470 * MIB
    assert row["rss_at_pending_zero"] == 560 * MIB
    assert row["rss_end"] == 647 * MIB
    assert row["ratio_vs_anchor"] == pytest.approx(1.155, abs=0.005)
    # The old anchor is kept as evidence and NEVER judged — this is the exact
    # ratio that failed the run.
    assert row["ratio_input_stop_to_end_unjudged"] == pytest.approx(1.377, abs=0.005)
    assert row["pending_at_first_engine_sample"] == 22736.0
    # ...and the three numbers reach the operator on the phase line.
    notes = h.phases[-1]["notes"]
    assert ("correlation netops-correlation-3 rss 470 MiB at input stop -> "
            "560 MiB at pending 0 -> 647 MiB end" in notes)


def test_MUTANT_anchoring_on_input_stop_calls_that_drain_a_leak(
        tmp_path, monkeypatch):
    """THE MUTANT, stated as an invariant: on the run's own numbers the old
    anchor is over the threshold and the pending-zero anchor is under it. Put
    the anchor back on the input-stop sample and the drain fails again."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=_converged_track(CORR, 560 * MIB))
    assert h.memflat() is True
    row = h.phases[-1]["evidence"]["containers"][0]
    assert row["ratio_input_stop_to_end_unjudged"] > h.args.mem_factor
    assert row["ratio_vs_anchor"] <= h.args.mem_factor


def test_growth_AFTER_the_backlog_drained_still_fails(tmp_path, monkeypatch):
    """The invariant the phase exists for, on the honest anchor: nothing left
    to evaluate and the working set still climbing."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=_converged_track(CORR, 470 * MIB))
    assert h.memflat() is False
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE (docker_stats, anchored at corr_engine_pending==0)" in notes
    assert "470 -> 647 MiB (x1.38" in notes
    assert h.phases[-1]["evidence"]["containers"][0]["verdict"] == "LEAK"


def test_a_small_absolute_climb_after_convergence_is_still_jitter(
        tmp_path, monkeypatch):
    """The 64 MiB floor survives the re-anchoring: a small container must not
    fail on a ratio alone."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    h = _corr_harness(tmp_path, at_input_stop=40 * MIB, at_end=100 * MIB,
                      track=_converged_track(CORR, 50 * MIB))
    assert h.memflat() is True, h.phases[-1]["notes"]


def test_a_run_that_never_converged_is_UNKNOWN_never_a_leak(
        tmp_path, monkeypatch):
    """Pending never reached 0 ⇒ the numbers are reported and NOT judged: a
    leak cannot be told from a drain here, and UNKNOWN is never PASS either."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    stuck = _converged_track(CORR, 560 * MIB)
    stuck[CORR].update({"pending_zero_monotonic": None, "pending_zero_t_s": None,
                        "rss_at_pending_zero": -1, "last_pending": 22736.0})
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=stuck)
    assert h.memflat() is False, "UNKNOWN is never PASS"
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE UNKNOWN" in notes
    assert "never reached 0 on this replica" in notes
    assert "last pending 22736" in notes
    assert "rss_at_input_stop 470 MiB" in notes and "rss_end 647 MiB" in notes
    assert "LEAK SLOPE (docker_stats" not in notes, "never a leak accusation"
    assert h.phases[-1]["evidence"]["containers"][0]["verdict"] == "UNKNOWN"


def test_no_completion_phase_at_all_is_UNKNOWN(tmp_path, monkeypatch):
    """burst() failed ⇒ correlation_completion never ran ⇒ there is no anchor,
    and inventing one from the input-stop sample is the defect."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track={})
    assert h.memflat() is False
    assert "no per-replica engine sample" in h.phases[-1]["notes"]


def test_the_end_sample_waits_out_the_settle_period(tmp_path, monkeypatch):
    """Convergence 5 s ago ⇒ memflat waits the rest of the settle before it
    samples, and then judges normally. A slope measured the instant a queue
    empties is measuring the queue."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    clock = _Clock()
    monkeypatch.setattr(ml, "time", clock)   # virtual: the suite never sleeps
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=_converged_track(CORR, 470 * MIB, ago=5.0))
    assert h.memflat() is False
    assert clock.slept >= ml.CORR_MEM_SETTLE_S - 5.0, "it really waited"
    settle = h.phases[-1]["evidence"]["correlation_settle"]
    assert settle["waited_s"] == pytest.approx(115.0, abs=5.0)
    assert settle["replicas_at_pending_zero"] == 1
    assert "LEAK SLOPE (docker_stats, anchored at" in h.phases[-1]["notes"]


def test_a_settle_the_budget_cannot_buy_is_UNKNOWN(tmp_path, monkeypatch):
    """The wait is BOUNDED (CORR_MEM_SETTLE_MAX_S). If the budget runs out
    before the settle is met, the slope is not judged — it is reported."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    monkeypatch.setattr(ml, "CORR_MEM_SETTLE_MAX_S", 0.0)
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB, at_end=647 * MIB,
                      track=_converged_track(CORR, 470 * MIB, ago=5.0))
    assert h.memflat() is False, "UNKNOWN is never PASS"
    notes = h.phases[-1]["notes"]
    assert "LEAK SLOPE UNKNOWN" in notes and "past pending 0" in notes
    assert "LEAK SLOPE (docker_stats" not in notes


def test_the_OOM_clause_holds_whatever_the_anchor_says(tmp_path, monkeypatch):
    """A replica at 95 % of its cap is one burst from a kill even mid-drain."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["correlation"])
    stuck = _converged_track(CORR, 560 * MIB)
    stuck[CORR].update({"pending_zero_monotonic": None,
                        "rss_at_pending_zero": -1, "last_pending": 22736.0})
    h = _corr_harness(tmp_path, at_input_stop=470 * MIB,
                      at_end=int(CORR_LIMIT * 0.95), track=stuck)
    assert h.memflat() is False
    assert "one burst from an OOM kill" in h.phases[-1]["notes"]


def test_a_transient_pending_zero_mid_drain_does_not_anchor():
    """The completion gate itself warns that pending "can read 0 for an
    instant mid-drain"; anchoring there would recreate the defect."""
    h = type("H", (), {"corr_mem_track": {},
                       "_corr_mem_track": ml.Harness._corr_mem_track})()
    def sample(pending, rss, t):
        ml.Harness._corr_mem_track(
            h, {"per_replica": {"abc": {"name": CORR, "pending": pending,
                                        "rss": rss}}}, t, t)
    sample(9000.0, 400 * MIB, 0.0)
    sample(0.0, 450 * MIB, 10.0)        # the instant
    sample(7000.0, 500 * MIB, 20.0)     # ...and the backlog is back
    sample(0.0, 600 * MIB, 30.0)        # the real convergence
    sample(0.0, 610 * MIB, 40.0)
    row = h.corr_mem_track[CORR]
    assert row["pending_zero_resets"] == 1
    assert row["rss_at_pending_zero"] == 600 * MIB, "re-armed on the real one"
    assert row["pending_zero_t_s"] == 30.0
    assert row["first_pending"] == 9000.0
    assert row["samples"] == 5


def test_an_unreadable_pending_never_anchors():
    """-1.0 is UNKNOWN, never idle — the completion gate's own rule."""
    h = type("H", (), {"corr_mem_track": {},
                       "_corr_mem_track": ml.Harness._corr_mem_track})()
    ml.Harness._corr_mem_track(
        h, {"per_replica": {"abc": {"name": CORR, "pending": -1.0,
                                    "rss": 400 * MIB}}}, 0.0, 0.0)
    assert h.corr_mem_track[CORR]["pending_zero_monotonic"] is None


def test_api_keeps_the_input_stop_anchor(tmp_path, monkeypatch):
    """`api` holds no backlog: its slope is still input-stop -> end."""
    monkeypatch.setattr(ml, "MEM_SERVICES", ["api"])
    end = _named({"api": {"used": 400 * MIB, "limit": 789 * MIB}})
    h = _memflat_harness(tmp_path, _named({"api": 59 * MIB}),
                         _named({"api": 180 * MIB}), end)
    assert h.memflat() is False
    row = h.phases[-1]["evidence"]["containers"][0]
    assert row["instrument"] == "docker_stats"
    assert "anchor" not in row, "unchanged: api is judged against the warm sample"
    assert "LEAK SLOPE (docker_stats)" in h.phases[-1]["notes"]


# ── TRACKER 175: the device-store tombstone debt ───────────────────────────
#
# `DELETE /api/devices/{id}` writes a permanent suppression tombstone
# (`.d/suppressed/<sha256hex(id)>`, devstore.go / audit F-69). This harness
# creates and deletes 2,500 devices a run, so every run leaves 2,500 files
# behind forever. Measured on the lab box 2026-08-29 after a day of runs:
# 35,427 tombstones, 142 MB, ZERO manual devices, and the onboard rate down
# from 30-43/s to 15.4/s. Nothing removes them and no API can.

import hashlib  # noqa: E402 — beside the tests that need it


def _debt_harness(tmp_path, data_dir, reason="api /data bind mount",
                  created=()):
    args = ml.parse_args(["--run-dir", str(tmp_path / "run")])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    h.created_ids = list(created)
    h.stack.api_data_dir = lambda: (data_dir, reason)  # type: ignore[assignment]
    return h


def _tombstone(root, device_id):
    d = root / "devices.json.d" / "suppressed"
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha256(device_id.encode()).hexdigest()).write_text(
        json.dumps({"id": device_id, "deleted_at": "2026-08-29T00:00:00Z"}),
        encoding="utf-8")


def test_the_tombstone_debt_is_counted_and_attributed(tmp_path, capsys):
    root = tmp_path / "data-api"
    mine = [f"mlx-08291138abcd-{i:05d}" for i in range(3)]
    for did in mine + ["mlx-08290322msp1-00000", "core-rtr-01"]:
        _tombstone(root, did)
    h = _debt_harness(tmp_path, str(root), created=mine)
    ev = h.tombstone_debt()
    assert ev["reachable"] is True
    assert ev["suppressed_entries"] == 5
    # Record names are sha256(id): only recomputing them can attribute a
    # hash-named file to this run. A directory scan never could.
    assert ev["this_run"] == 3
    err = capsys.readouterr().err
    assert "TOMBSTONE DEBT: 5 suppressed entries" in err
    assert "No API exists to purge them" in err


def test_the_harness_never_deletes_a_tombstone(tmp_path):
    """It is an unsynchronised write into a LIVE service's private state: the
    api holds the suppression set in memory from boot. Measure, never mutate."""
    root = tmp_path / "data-api"
    _tombstone(root, "mlx-08291138abcd-00000")
    h = _debt_harness(tmp_path, str(root), created=["mlx-08291138abcd-00000"])
    h.tombstone_debt()
    assert len(list((root / "devices.json.d" / "suppressed").iterdir())) == 1


def test_an_unreachable_device_store_is_UNKNOWN_never_zero(tmp_path, capsys):
    """A named volume or an image-internal /data cannot be counted from here."""
    h = _debt_harness(tmp_path, "", reason=(
        "the api's /data is a volume (netops_api_data), not a host bind "
        "mount — the device store is not reachable from this harness"))
    ev = h.tombstone_debt()
    assert ev["reachable"] is False
    assert ev["suppressed_entries"] == -1, "never 0 — 0 is a measurement"
    assert "not reachable" in ev["reason"]
    assert "TOMBSTONE DEBT: UNKNOWN" in capsys.readouterr().err


def test_a_store_that_never_deleted_anything_reads_zero(tmp_path):
    root = tmp_path / "data-api"
    root.mkdir()
    ev = _debt_harness(tmp_path, str(root)).tombstone_debt()
    assert ev["reachable"] is True and ev["suppressed_entries"] == 0


def test_the_onboard_rate_trend_accumulates_across_runs(tmp_path):
    """The debt is invisible inside ONE run — every run just looks slow. Only
    the slope across runs shows it, so last-run.json carries the history."""
    hb_path = tmp_path / "last-run.json"
    args = ml.parse_args(["--run-dir", str(tmp_path / "run")])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    rates = [43.0, 30.0, 15.4]
    history = []
    for i, rate in enumerate(rates):
        h = ml.Harness(args)
        hb = {"ts": f"2026-08-29T0{i}:00:00Z", "runid": f"r{i}", "devices": 2500,
              "onboard_rate_first": rate, "tombstones": 2500 * (i + 1)}
        history = h._rate_history(str(hb_path), hb)
        hb["onboard_rate_history"] = history
        hb_path.write_text(json.dumps(hb), encoding="utf-8")
    assert [e["rate"] for e in history] == rates
    assert [e["tombstones"] for e in history] == [2500, 5000, 7500]


def test_the_rate_trend_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "ONBOARD_RATE_HISTORY", 3)
    hb_path = tmp_path / "last-run.json"
    args = ml.parse_args(["--run-dir", str(tmp_path / "run")])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    history = []
    for i in range(6):
        hb = {"ts": f"t{i}", "runid": f"r{i}", "devices": 10,
              "onboard_rate_first": float(i), "tombstones": i}
        history = h._rate_history(str(hb_path), hb)
        hb_path.write_text(json.dumps({"onboard_rate_history": history}),
                           encoding="utf-8")
    assert [e["runid"] for e in history] == ["r3", "r4", "r5"]


def test_a_corrupt_last_run_json_restarts_the_trend_loudly(tmp_path, capsys):
    hb_path = tmp_path / "last-run.json"
    hb_path.write_text("{not json", encoding="utf-8")
    args = ml.parse_args(["--run-dir", str(tmp_path / "run")])
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    out = h._rate_history(str(hb_path), {"ts": "t", "runid": "r", "devices": 1,
                                         "onboard_rate_first": 9.0,
                                         "tombstones": 1})
    assert [e["runid"] for e in out] == ["r"]
    assert "trend restarts at this run" in capsys.readouterr().err


# ── the clean-slate offset heuristic, re-baselined (2026-08-29) ────────────

def test_group_lag_reports_the_max_current_offset():
    """clean-slate.sh:243 maxes CURRENT-OFFSET over the describe rows; the
    harness must warn about THAT number, not a different one."""
    out = (HEADER +
           "netops-correlation netops.syslog 0 250 300 50 c-1 /10.0.0.1 c\n"
           "netops-correlation netops.syslog 1 900 900 0  c-1 /10.0.0.1 c\n"
           "netops-correlation netops.flows  0 -   0   -  c-1 /10.0.0.1 c\n")
    got = group_lag(out)
    assert got["_max_current"] == 900
    assert got["netops.syslog"]["lag"] == 50, "lag accounting is unchanged"


def test_an_unreadable_describe_reports_max_current_UNKNOWN():
    assert group_lag("", rc=1, err="broker unreachable")["_max_current"] == -1


def test_a_lifetime_topic_offset_no_longer_warns_on_every_run():
    """THE NOISE THIS RETIRES (run p2-s05-08291138):

        WARNING: planned injection (900000) + current netops.syslog end offset
        (73132772) exceeds 100k — clean-slate.sh --verify's offset heuristic
        will flag this stack until its next reset

    `end_offset` sums the LOG-END-OFFSETs of every partition of a topic that
    never resets, so that condition became true on every run, on every stack,
    forever. clean-slate.sh:243 measures something else entirely — the max
    CURRENT-OFFSET over the consumer-group describe rows. A warning that
    cannot be false is not a warning."""
    # The lab stack's real shape: the bound is long gone, and this run does
    # not spend it. Stated as a fact, never as a WARNING.
    level, msg = ml.clean_slate_offset_note(73_132_772, 900_000)
    assert level == "log"
    assert "already reads this bus as not-reset" in msg
    assert "does not change that" in msg


def test_the_run_that_actually_spends_the_signal_still_warns():
    """The one case worth a warning: intact now, gone after this run, and the
    operator can still choose to reset first."""
    level, msg = ml.clean_slate_offset_note(4_000, 900_000)
    assert level == "warn"
    assert "will push the max consumer CURRENT-OFFSET from 4000" in msg
    assert "clean-slate.sh:243" in msg


def test_a_run_that_stays_inside_the_bound_says_nothing():
    assert ml.clean_slate_offset_note(4_000, 1_000) == ("", "")


def test_an_unreadable_offset_is_UNKNOWN_not_silence():
    level, msg = ml.clean_slate_offset_note(-1, 900_000)
    assert level == "log" and "UNKNOWN" in msg
