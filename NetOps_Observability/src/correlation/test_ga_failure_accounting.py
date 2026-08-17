"""GA-gate G1 — failure accounting made structurally visible (scale-test P0s).

The 2026-08 scale test exposed a defect CLASS, not just defects: failures that
only increment a counter nobody surfaces (238k dead-letter payloads lost while
QUARANTINE_WRITE_FAILURES climbed in the dark). These tests make the class
impossible to reintroduce:

  1. Counter-exposure contract — every module-level failure/drop counter in
     main.py MUST surface in the /healthz payload. The counter list is
     DISCOVERED by AST over main.py, so a future orphaned counter (added but
     never exposed) fails this suite the day it lands.
  2. Event-accounting invariant — a mixed batch (valid syslog, poison
     payloads, forged-tenant events) driven through handle() with the
     consume-loop's exact quarantine discipline satisfies
         consumed == persisted + deadlettered + explicitly_counted_rejections
     — zero unexplained losses.
  3. Drain / bounded memory — a 12k-event burst leaves every module-level
     container back at (or bounded by) steady state; nothing grows unbounded.

Deterministic throughout: operation counts and structure sizes, never timing.

Run:  python3 -m pytest test_ga_failure_accounting.py -v
"""
from __future__ import annotations

import ast
import asyncio
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import main

MAIN_PY = Path(main.__file__)


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    """Fake ClickHouse that records every committed insert (the
    test_tenant_claim_verification pattern)."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.inserts.append((table, list(rows)))
        return True

    def rows_for(self, table: str) -> list[dict]:
        return [r for t, rs in self.inserts if t == table for r in rs]


# ── counter discovery (the introspective part) ───────────────────────────────

# Failure/drop counter naming convention in main.py. A counter is "in scope"
# when its module-level name matches one of these suffixes (or is one of the
# explicit quarantine/dead-letter names) AND it is initialised to a literal
# int 0 (scalars) or a literal {} (per-key tallies). Anything new that matches
# is discovered automatically — an orphaned counter fails the exposure test.
COUNTER_SUFFIXES = (
    "_FAILURES", "_DROPPED", "_DROPS", "_REJECTED", "_REFUSED", "_REFUSALS",
    "_QUARANTINED", "_EVICTED",
)
EXPLICIT_COUNTERS = {
    "QUARANTINE_WRITE_FAILURES",  # the 238k-loss counter — never optional
    "QUARANTINE_ROTATIONS",
    "DEADLETTER_COUNT",
    # A replica that JOINED the group and was assigned nothing consumes at zero
    # rate forever while every health signal looks normal (more replicas than
    # BUS_PARTITIONS). It is not a "failure" by name, so the suffix convention
    # misses it — this set is the documented extension point for exactly that.
    "CONSUMER_ZERO_ASSIGNMENTS",
}


def discovered_counters() -> tuple[list[str], list[str]]:
    """(int_counters, dict_counters) — module-level failure/drop counters."""
    tree = ast.parse(MAIN_PY.read_text(), str(MAIN_PY))
    ints: list[str] = []
    dicts: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        else:
            continue
        for name in targets:
            if name.startswith("_"):
                continue  # private rate-limit state, not a contract counter
            if not (name in EXPLICIT_COUNTERS or name.endswith(COUNTER_SUFFIXES)):
                continue
            if (isinstance(value, ast.Constant)
                    and isinstance(value.value, int)
                    and not isinstance(value.value, bool)):
                ints.append(name)
            elif isinstance(value, ast.Dict) and not value.keys:
                dicts.append(name)
    return ints, dicts


def numeric_leaves(obj) -> set:
    """Every numeric leaf value reachable in a JSON-shaped payload."""
    out: set = set()
    if isinstance(obj, bool):
        return out
    if isinstance(obj, (int, float)):
        out.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out |= numeric_leaves(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out |= numeric_leaves(v)
    return out


def test_counter_discovery_finds_the_known_failure_counters():
    """Sanity anchor: if the discovery ever silently returns nothing (a rename,
    an AST change), the exposure test would vacuously pass — so pin the
    counters this suite exists for."""
    ints, dicts = discovered_counters()
    for must in ("QUARANTINE_WRITE_FAILURES", "QUARANTINE_ROTATIONS",
                 "DEADLETTER_COUNT", "METRICS_DROPPED", "FLOWS_DROPPED",
                 "WIRELESS_DROPPED", "SERIES_EVICTED", "TENANT_CLAIMS_REFUSED",
                 "BATCH_ROWS_QUARANTINED", "PROJECTION_WRITE_FAILURES"):
        assert must in ints, f"discovery lost {must}"
    for must in ("HANDLER_FAILURES", "CH_INSERT_FAILURES", "TENANT_REFUSALS"):
        assert must in dicts, f"discovery lost dict counter {must}"


def test_every_failure_counter_is_surfaced_on_healthz(monkeypatch):
    """The 238k-loss shape: a counter that increments but is exposed NOWHERE.

    Each discovered counter is set to a unique sentinel value, then /healthz is
    rendered and every sentinel must appear among its numeric leaves. A counter
    whose sentinel is missing is an ORPHAN — a failure the platform counts but
    an operator can never see. New counters are discovered automatically; the
    fix for a failure here is to add the counter to the health() payload (and
    thus /metrics, which is derived from it), never to rename it out of scope.
    """
    ints, dicts = discovered_counters()
    base = 90_000_001  # far above any organic value; primes-ish spacing keeps them unique
    expected: dict[str, int] = {}
    for i, name in enumerate(ints):
        val = base + i * 7
        monkeypatch.setattr(main, name, val)
        expected[name] = val
    for j, name in enumerate(dicts):
        val = base + 1_000_000 + j * 11
        monkeypatch.setitem(getattr(main, name), "zz_ga_exposure_probe", val)
        expected[name] = val

    payload = run(main.health())
    leaves = numeric_leaves(payload)
    orphans = sorted(n for n, v in expected.items() if v not in leaves)
    assert not orphans, (
        "module-level failure/drop counters NOT exposed on /healthz: "
        f"{orphans} — a failure that only increments an unexposed counter is "
        "invisible in production (the 238k dead-letter loss shape). Add them "
        "to main.health()."
    )


# ── event accounting ─────────────────────────────────────────────────────────


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """Trusted device→tenant registry: leaf0..leaf59 → acme."""
    csv_path = tmp_path / "device_tenant.csv"
    lines = ["identity,tenant_id"] + [f"leaf{i},acme" for i in range(60)]
    csv_path.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(csv_path))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)
    return csv_path


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """Reset every structure this suite touches, both sides."""
    def clear_all():
        main.QUARANTINE.clear()
        main.HANDLER_FAILURES.clear()
        main._QUARANTINE_LOG_LAST.clear()
        main.SYSLOG_BUCKET.clear()
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main.TENANT_REFUSALS.clear()
        main.CH_INSERT_FAILURES.clear()
    clear_all()
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    monkeypatch.setattr(main, "CORR_DLQ_DIR", "")  # memory-only quarantine: no disk IO
    for name in ("SYSLOG_RECEIVED", "SYSLOG_SIGNALS", "DEADLETTER_COUNT",
                 "TENANT_CLAIMS_VERIFIED", "TENANT_CLAIMS_REFUSED",
                 "CLOCK_SKEW_SIGNALS"):
        monkeypatch.setattr(main, name, 0)
    yield
    clear_all()


def _syslog(i: int, host: str = "leaf0", **over) -> dict:
    ev = {
        "hostname": host,
        "tenant_id": "acme",
        "appname": "%BGP-5-ADJCHANGE",
        "severity": "info",  # weight 1: stays under the burst threshold
        "message": f"neighbor 10.2.{i // 250}.{i % 250} Down BGP Notification sent",
    }
    ev.update(over)
    return ev


async def _drive(events: list[tuple[str, object]]) -> None:
    """The consume loop's per-event discipline, exactly (main.consume):
    decode + handle inside a per-event try; any exception quarantines THAT
    event (raw bytes when the decode itself failed) and the loop continues."""
    import json as _json
    for topic, raw in events:
        event = None
        try:
            if isinstance(raw, (bytes, bytearray)):
                event = _json.loads(bytes(raw).decode("utf-8")) if raw else None
            else:
                event = raw
            await main.handle(topic, event)
        except Exception as exc:  # noqa: BLE001 — mirrors the consume loop
            main.quarantine_event(topic, raw if event is None else event, exc)


def test_zero_unexplained_event_loss(monkeypatch, registry):
    """consumed == persisted + deadlettered + explicitly_counted_rejections.

    11 events go in: 6 valid control-plane syslog (each must become exactly one
    persisted corr_signals row), 3 forged-tenant events (each must be counted
    AND quarantined), 2 poison payloads (undecodable bytes / non-dict JSON —
    each must be counted in HANDLER_FAILURES and quarantined). Every event is
    accounted for in exactly one outcome class; nothing vanishes.
    """
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    valid = [("netops.syslog", _syslog(i)) for i in range(6)]
    forged = [("netops.syslog", _syslog(100 + i, tenant_id="victim-corp"))
              for i in range(3)]
    poison = [
        ("netops.syslog", b"\x00\xffnot-json at all"),   # decode failure: raw bytes kept
        ("netops.syslog", ["not", "a", "dict"]),          # handler failure: shape poison
    ]
    events = valid + forged + poison

    before = {
        "received": main.SYSLOG_RECEIVED,
        "signals": main.SYSLOG_SIGNALS,
        "deadletter": main.DEADLETTER_COUNT,
        "handler_failures": sum(main.HANDLER_FAILURES.values()),
        "quarantine": len(main.QUARANTINE),
    }

    run(_drive(events))
    run(main.SIGNAL_BATCH.flush())  # exactly what the consume loop does pre-commit

    consumed = len(events)
    persisted = main.SYSLOG_SIGNALS - before["signals"]
    forged_counted = main.DEADLETTER_COUNT - before["deadletter"]
    poisoned = sum(main.HANDLER_FAILURES.values()) - before["handler_failures"]
    rejections = 0  # no lane in this batch has an explicit-rejection counter path

    # Per-class exactness first (a compensating error must not cancel out).
    assert persisted == len(valid), "valid control-plane events did not all become signals"
    assert forged_counted == len(forged), "forged-tenant events not all counted as dead-letters"
    assert poisoned == len(poison), "poison payloads not all counted in HANDLER_FAILURES"

    # The persisted class REALLY persisted (rows landed on the CH fake, not
    # just a counter): batched write path, flushed above.
    assert len(ch.rows_for("netops.corr_signals")) == len(valid)

    # Every dead-lettered event kept its evidence.
    assert len(main.QUARANTINE) - before["quarantine"] == len(forged) + len(poison)

    # Intake honesty: received counts events that REACHED the lane handler —
    # valid + forged + the shape-poison list (which decodes, enters
    # handle_syslog, is counted at intake, THEN raises). The undecodable bytes
    # never reach any lane.
    assert main.SYSLOG_RECEIVED - before["received"] == len(valid) + len(forged) + 1

    # The invariant this test exists for — zero unexplained losses.
    assert consumed == persisted + forged_counted + poisoned + rejections, (
        f"{consumed - (persisted + forged_counted + poisoned + rejections)} "
        "event(s) vanished without a counter — the silent-loss class is back"
    )


# ── drain / bounded memory ───────────────────────────────────────────────────


def test_burst_drains_to_steady_state_memory(monkeypatch, registry):
    """A 12k-event syslog burst must leave every module-level container bounded,
    and back at steady state once time passes (flush + prune + sweep).

    Containers checked (the module-level mutable state the syslog path can
    grow): SIGNAL_BATCH (pending rows), WINDOW_BUFFER + _BUFFERED_IDS (live
    evidence window), SYSLOG_BUCKET (burst tracker keyed by device-supplied
    hostname), QUARANTINE (dead-letter ring), HANDLER_FAILURES /
    CH_INSERT_FAILURES / TENANT_REFUSALS / _QUARANTINE_LOG_LAST (per-key
    tallies), SERIES (z-score baselines, LRU-capped), _CLOCK_SKEW_LAST
    (cooldown map, hard-capped), OPEN_OBJECTS and _FLOW_AGG (untouched by this
    lane — must stay untouched).
    """
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    n = 12_000
    hosts = [f"leaf{i % 60}" for i in range(n)]
    open_objects_before = len(main.OPEN_OBJECTS)
    flow_agg_before = len(main._FLOW_AGG)
    series_before = len(main.SERIES)

    async def burst():
        for i in range(n):
            await main.handle("netops.syslog", _syslog(i, host=hosts[i]))
        await main.SIGNAL_BATCH.flush()

    run(burst())

    # Everything the burst produced either landed or is a counted failure —
    # nothing is parked in the batcher after the pre-commit flush.
    assert main.SIGNAL_BATCH.pending() == 0
    assert main.SYSLOG_SIGNALS == n, "every valid event became exactly one signal"
    assert len(ch.rows_for("netops.corr_signals")) == n
    assert sum(main.HANDLER_FAILURES.values()) == 0
    assert len(main.QUARANTINE) == 0

    # Hard bounds held DURING the burst.
    assert len(main.WINDOW_BUFFER) <= (main.WINDOW_BUFFER.maxlen or 0)
    assert len(main.SYSLOG_BUCKET) <= main.SYSLOG_BUCKET_MAX
    assert len(main.SERIES) <= main.SERIES_MAX
    assert len(main._CLOCK_SKEW_LAST) <= main._CLOCK_SKEW_LAST_CAP
    assert len(main.QUARANTINE) <= main.CORR_QUARANTINE_MAX
    # Per-key tallies are keyed by topic/lane:reason — bounded cardinality.
    assert len(main._QUARANTINE_LOG_LAST) <= len(main.TOPICS) + 8
    assert len(main.TENANT_REFUSALS) == 0

    # Structures OUTSIDE this lane did not grow as a side effect.
    assert len(main.OPEN_OBJECTS) == open_objects_before
    assert len(main._FLOW_AGG) == flow_agg_before
    assert len(main.SERIES) == series_before  # syslog lane never touches z-score baselines

    # And the burst DRAINS: once the engine's window horizon passes, the live
    # window releases every buffered signal and its dedup id — the exact prune
    # the engine cycle runs (run_window → _prune_buffer).
    later = datetime.now(timezone.utc) + timedelta(
        seconds=main.ENGINE_CFG.window_s + main.METRIC_FUTURE_SKEW_S + 60)
    main._prune_buffer(later)
    assert len(main.WINDOW_BUFFER) == 0, "window buffer did not drain past the horizon"
    assert len(main._BUFFERED_IDS) == 0, "dedup id set leaked after the buffer drained"

    # The burst tracker sweeps to empty once its 60s window has passed.
    monkeypatch.setattr(main, "_SYSLOG_SWEEP_LAST", 0.0)
    main._sweep_syslog_buckets(time.time() + main.SYSLOG_WINDOW + 1)
    assert len(main.SYSLOG_BUCKET) == 0, "syslog burst buckets did not sweep to empty"


def test_healthz_registry_count_is_eager_not_lazy(tmp_path, monkeypatch):
    """registry_identities must reflect the CSV even if no event has triggered
    a lookup yet (idle replica). Proven live 2026-08-16: a 2-replica deployment's
    idle member reported 0 for a healthy 201-row registry and failed the
    mini-ladder propagation gate."""
    import main as m

    csv_path = tmp_path / "device_tenant.csv"
    csv_path.write_text(
        "identity,tenant_id\ndev-a,tenant-1\ndev-b,\n", encoding="utf-8"
    )
    monkeypatch.setattr(m, "TENANT_ENRICHMENT_FILE", str(csv_path))
    # Simulate the idle-replica state: nothing loaded, no lookups performed.
    monkeypatch.setattr(m, "_tenant_map", {})
    monkeypatch.setattr(m, "_tenant_mtime", None)
    # The healthz computation must refresh from disk, not echo the lazy global.
    assert len(m._tenant_registry()) == 2
    # And pin that health() actually uses the eager accessor — a regression to
    # the raw `_tenant_map` global re-introduces the idle-replica lie.
    import ast
    import inspect
    import pathlib

    src = pathlib.Path(inspect.getfile(m)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    joined = ast.dump(tree)
    assert "_tenant_registry" in joined  # sanity: accessor exists
    import re

    m_ = re.search(r'"registry_identities":\s*len\(([_a-zA-Z()]+)\)', src)
    assert m_ is not None, "registry_identities line not found in main.py"
    assert m_.group(1) == "_tenant_registry()", (
        f"healthz registry_identities must call _tenant_registry(), got {m_.group(1)}"
    )
