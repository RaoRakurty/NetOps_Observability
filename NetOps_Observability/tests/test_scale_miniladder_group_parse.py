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

    PATH is saved/restored across the import: the harness pins a cron-proof
    PATH at module scope (§16.2), and letting that leak into the pytest process
    hid the developer's ~/.local/bin — which made the shellcheck-based suites
    (test_backup_ship, test_perf_signing_ship) fail with
    'No such file or directory: shellcheck' whenever this file was collected
    first. A test may never mutate the environment other tests read.
    """
    path = ROOT / "scripts" / "scale-miniladder.py"
    spec = importlib.util.spec_from_file_location("scale_miniladder", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    saved_path = os.environ.get("PATH", "")
    try:
        sys.modules["scale_miniladder"] = mod
        spec.loader.exec_module(mod)
    finally:
        os.environ["PATH"] = saved_path
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
