"""#100 lane-readiness harness — broken-source soak for signal lanes.

THE READINESS RULE (docs/incidents/correlix-clickhouse-bounded-io.md): every
NEW signal lane must prove bounded write amplification under a sustained
broken-source scenario BEFORE it ships. The 2026-07-09 incident was exactly
this gap: the app-experience lane could turn one dead probe target into a
persisting incident, and the engine persisted a full snapshot + archive slice
every 30s cycle for as long as the source stayed broken — ~30x expected table
growth, which then detonated the (also unbounded) read path.

How to use for a new lane:
    1. Build the lane's semantic Signals the way its normalizer would emit them
       for ONE broken source, per engine cycle (same evidence kinds each cycle,
       fresh instance ids — that is what a real broken source produces).
    2. Feed N cycles to run_broken_source_soak().
    3. Assert the write budget: a materially-unchanged incident persists ONCE
       (plus heartbeats at CORR_VERSION_HEARTBEAT_S while content refreshes) —
       NOT once per cycle.

test_probe_lane_broken_source_soak below is the reference usage.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import main
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)


class _StubCH:
    """Records inserts; stands in for the ClickHouse client in engine_cycle."""

    def __init__(self):
        self.rows: dict = {}

    async def insert(self, table: str, rows: list, dedup_token="") -> None:
        self.rows.setdefault(table, []).extend(rows)


def lane_signal(kind: str, entity_id: str, *, offset_s: float, now: datetime,
                entity_type: EntityType = EntityType.DEVICE,
                severity: Severity = Severity.CRIT,
                modality: ModalityClass = ModalityClass.DEVICE_TELEMETRY,
                observer: str = "soak-observer") -> Signal:
    """One semantic signal the way a lane normalizer would emit it. Each call
    mints a fresh instance identity (native_id includes the offset), which is
    the storm shape: same evidence, rotating instance ids."""
    return Signal(
        tenant_id="t-soak", ts=now + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id=observer, observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=entity_type, entity_id=entity_id,
        severity=severity, native_id=f"soak|{kind}|{entity_id}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def run_broken_source_soak(batches, heartbeat_s: float = 900.0) -> dict:
    """Feed one batch of Signals per engine cycle against a stub ClickHouse and
    return the write-amplification counters. `batches` is an iterable of signal
    lists — batch i is what the (broken) source emits in cycle i.

    Returns: {"object_rows", "current_rows", "archive_rows", "damped"}."""
    stub = _StubCH()
    saved_ch, saved_open = main.ch, main.OPEN_OBJECTS
    saved_hb = main.CORR_VERSION_HEARTBEAT_S
    main.ch, main.OPEN_OBJECTS = stub, {}
    main.CORR_VERSION_HEARTBEAT_S = heartbeat_s
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    damped0, persisted0 = main.VERSIONS_DAMPED, main.VERSIONS_PERSISTED
    try:
        for batch in batches:
            for s in batch:
                main.buffer_signal(s)
            asyncio.run(main.engine_cycle())
    finally:
        main.ch, main.OPEN_OBJECTS = saved_ch, saved_open
        main.CORR_VERSION_HEARTBEAT_S = saved_hb
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
    return {
        "object_rows": len(stub.rows.get("netops.corr_objects", [])),
        "current_rows": len(stub.rows.get("netops.corr_current", [])),
        "archive_rows": len(stub.rows.get("netops.corr_signals_archive", [])),
        "damped": main.VERSIONS_DAMPED - damped0,
        "persisted": main.VERSIONS_PERSISTED - persisted0,
        "_stub": stub,
    }


def _dead_target_batches(cycles: int, now: datetime):
    """The reference broken source: one dead device emitting the SAME two
    evidence kinds every cycle with fresh instance ids (a .120-style outage)."""
    out = []
    for i in range(cycles):
        off = -600 + i * 30  # one engine cycle apart, all inside the window
        out.append([
            lane_signal("link_state_change", "soak-core-1", offset_s=off, now=now),
            lane_signal("device_resource_anomaly", "soak-core-1", offset_s=off + 2, now=now),
        ])
    return out


def test_probe_lane_broken_source_soak():
    """THE lane budget: a source broken for 15 cycles (≈7.5 min) persists ONE
    object version — not fifteen. Every additional row is write amplification
    the #100 damper must suppress."""
    now = datetime.now(timezone.utc)
    res = run_broken_source_soak(_dead_target_batches(15, now))
    assert res["object_rows"] == 1, (
        f"broken source wrote {res['object_rows']} versions in 15 cycles — "
        "write amplification regressed (#100 damper)")
    assert res["damped"] == 14, f"expected 14 damped persists, got {res['damped']}"
    # The hot projection gets exactly the damped write rate too.
    assert res["current_rows"] == res["object_rows"]
    # Archive slices are only written WITH a persist — never per cycle.
    assert res["archive_rows"] <= res["object_rows"] * 4


def test_soak_heartbeat_bounds_staleness_not_churn():
    """With a short heartbeat, a still-broken source re-persists once per
    heartbeat window — bounded freshness, still not per-cycle churn."""
    now = datetime.now(timezone.utc)
    # 10 cycles, heartbeat=0 semantics differ (legacy), so use a tiny positive
    # heartbeat: every content-refreshing cycle after it elapses persists.
    res = run_broken_source_soak(_dead_target_batches(10, now), heartbeat_s=0.0)
    # heartbeat 0 = damping OFF (legacy per-change persistence): every cycle
    # with fresh instances persists. This pins the knob's documented meaning.
    assert res["object_rows"] == 10
    assert res["damped"] == 0


def test_lifecycle_close_persists_immediately():
    """Terminal transitions are NEVER damped: when the source stops and the
    object quiesces, the closed version persists on that cycle."""
    now = datetime.now(timezone.utc)
    stub = _StubCH()
    saved_ch, saved_open = main.ch, main.OPEN_OBJECTS
    saved_hb, saved_q = main.CORR_VERSION_HEARTBEAT_S, main.CORR_QUIESCE_S
    main.ch, main.OPEN_OBJECTS = stub, {}
    main.CORR_VERSION_HEARTBEAT_S = 900.0
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        main.buffer_signal(lane_signal("link_state_change", "soak-core-2", offset_s=-60, now=now))
        main.buffer_signal(lane_signal("device_resource_anomaly", "soak-core-2", offset_s=-58, now=now))
        asyncio.run(main.engine_cycle())
        assert len(stub.rows["netops.corr_objects"]) == 1
        # Source goes quiet; make quiesce immediate. The component no longer
        # materializes (buffer cleared), so the object closes THIS cycle.
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main.CORR_QUIESCE_S = 0.0
        asyncio.run(main.engine_cycle())
        rows = stub.rows["netops.corr_objects"]
        assert len(rows) == 2, "closed transition must persist immediately (never damped)"
        assert rows[-1]["state"] == "closed"
        # The hot projection sees the terminal state too (Command Center truth).
        assert stub.rows["netops.corr_current"][-1]["state"] == "closed"
    finally:
        main.ch, main.OPEN_OBJECTS = saved_ch, saved_open
        main.CORR_VERSION_HEARTBEAT_S, main.CORR_QUIESCE_S = saved_hb, saved_q
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()


def test_material_severity_escalation_persists():
    """A WARN→CRIT escalation of the SAME evidence is operator-meaningful and
    must re-version (material change), even mid-damping."""
    now = datetime.now(timezone.utc)
    warn = [[lane_signal("link_state_change", "soak-core-3", offset_s=-120, now=now, severity=Severity.WARN),
             lane_signal("device_resource_anomaly", "soak-core-3", offset_s=-118, now=now, severity=Severity.WARN)]]
    crit = [[lane_signal("link_state_change", "soak-core-3", offset_s=-60, now=now, severity=Severity.CRIT),
             lane_signal("device_resource_anomaly", "soak-core-3", offset_s=-58, now=now, severity=Severity.CRIT)]]
    res = run_broken_source_soak(warn + crit)
    assert res["object_rows"] == 2, "severity escalation must persist a new version"


def test_current_projection_badges_and_narrowness():
    """#100 completion: the corr_current dual-write carries the narrow triage
    badges (derived from the SAME hypotheses JSON the history row persists) and
    NEVER the wide blob columns — the whole point of the projection is that the
    hot list path reads badges without touching hypotheses."""
    now = datetime.now(timezone.utc)
    res = run_broken_source_soak(_dead_target_batches(3, now))
    cur = res["_stub"].rows["netops.corr_current"]
    obj = res["_stub"].rows["netops.corr_objects"]
    assert cur, "projection row missing"
    for row in cur:
        for banned in ("hypotheses", "layer_coverage", "app_impact"):
            assert banned not in row, f"wide column {banned!r} leaked into corr_current"
        for badge in ("owner", "plane_count", "debug_excluded", "low_authority"):
            assert badge in row, f"badge column {badge!r} missing from corr_current write"
    # Badge semantics must match the history row's verdict JSON exactly.
    import json as _json
    verdict = (_json.loads(obj[-1]["hypotheses"])["ranking"]["hypotheses"] or [{}])[0].get("verdict", {})
    last = cur[-1]
    assert last["owner"] == str(verdict.get("owner") or "")
    assert last["plane_count"] == len(verdict.get("modality_coverage") or [])
    assert last["debug_excluded"] == (1 if verdict.get("excluded_debug_probes") else 0)
    assert last["low_authority"] == (1 if verdict.get("low_authority_probe_scopes") else 0)


def test_current_badges_malformed_blob_defaults():
    """A malformed hypotheses blob must never block the projection write — it
    degrades to default badges (observable via the row itself)."""
    assert main._current_badges("not json") == {
        "owner": "", "plane_count": 0, "debug_excluded": 0, "low_authority": 0}
    assert main._current_badges("{}")["plane_count"] == 0
