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


def _memflat_harness(tmp_path, cold, warm, end_stats, **flags):
    argv = ["--run-dir", str(tmp_path)]
    for k, v in flags.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    args = ml.parse_args(argv)
    args.project, args.base_url = "netops", "http://localhost:8000"
    args.env_file = str(tmp_path / "nonexistent.env")
    h = ml.Harness(args)
    h.baseline["mem"] = cold
    h.warm_mem = warm
    h.stack.mem_stats = lambda: end_stats            # type: ignore[assignment]
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
    assert "no memory sample" in h.phases[-1]["notes"]


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
