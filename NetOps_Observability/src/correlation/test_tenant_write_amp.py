"""#101 per-tenant write-amplification visibility — bounded cardinality.

The contract: one tenant's storm must be attributable (who, which kind, which
entity, how damped) WITHOUT per-tenant Prometheus series. Accounting rolls up
in-process and flushes one row per (tenant, window) to
netops.corr_tenant_write_amp; /metrics exposes only the top-K noisiest tenants
of the last window."""

import asyncio
from datetime import datetime, timedelta, timezone

import main
from signals import EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source
from test_lane_soak import _StubCH, lane_signal


def _reset_wa(monkeypatch, flush_s: float = 0.0, topk: int = 2):
    monkeypatch.setattr(main, "TENANT_WA", {})
    monkeypatch.setattr(main, "TENANT_WA_LAST", [])
    monkeypatch.setattr(main, "_WA_WINDOW_START", None)
    monkeypatch.setattr(main, "CORR_WA_FLUSH_S", flush_s)
    monkeypatch.setattr(main, "CORR_WA_TOPK", topk)


def _tenant_signal(tenant: str, kind: str, entity: str, *, offset_s: float, now: datetime) -> Signal:
    return Signal(
        tenant_id=tenant, ts=now + timedelta(seconds=offset_s), source=Source.METRIC,
        kind=kind, observer=Observer(observer_id="wa-obs", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=EntityType.DEVICE,
        entity_id=entity, severity=Severity.CRIT,
        native_id=f"wa|{tenant}|{kind}|{entity}|{offset_s}",
        attrs={"onset_uncertainty_s": 5.0},
    )


def test_raw_seen_counts_per_tenant_post_dedup(monkeypatch):
    _reset_wa(monkeypatch, flush_s=1e9)  # accumulate only
    now = datetime.now(timezone.utc)
    saved = main.ch
    main.ch = _StubCH()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        s1 = _tenant_signal("t-a", "link_state_change", "dev-1", offset_s=-60, now=now)
        main.buffer_signal(s1)
        main.buffer_signal(s1)  # redelivery — must NOT double count
        main.buffer_signal(_tenant_signal("t-b", "device_resource_anomaly", "dev-2", offset_s=-50, now=now))
    finally:
        main.ch = saved
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
    assert main.TENANT_WA["t-a"]["raw_seen"] == 1
    assert main.TENANT_WA["t-b"]["raw_seen"] == 1
    assert main.TENANT_WA["t-a"]["kinds"].most_common(1)[0][0] == "link_state_change"


def test_flush_rolls_up_and_bounds_topk(monkeypatch):
    """Storm on t-noisy + trickle on t-quiet: the flush writes one row per
    tenant with raw/persisted/damped + dominant kind/entity, /metrics exposes
    at most top-K series, and the window resets."""
    _reset_wa(monkeypatch, flush_s=0.0, topk=1)
    now = datetime.now(timezone.utc)
    stub = _StubCH()
    saved_ch, saved_open = main.ch, main.OPEN_OBJECTS
    main.ch, main.OPEN_OBJECTS = stub, {}
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        # Cycle 1 opens objects for both tenants (both persist v1)…
        for i in range(4):
            main.buffer_signal(_tenant_signal("t-noisy", "link_state_change", "storm-dev", offset_s=-300 + i, now=now))
            main.buffer_signal(_tenant_signal("t-noisy", "device_resource_anomaly", "storm-dev", offset_s=-299 + i, now=now))
        main.buffer_signal(_tenant_signal("t-quiet", "link_state_change", "calm-dev", offset_s=-200, now=now))
        main.buffer_signal(_tenant_signal("t-quiet", "device_resource_anomaly", "calm-dev", offset_s=-198, now=now))
        asyncio.run(main.engine_cycle())   # sets the window start
        # …cycle 2: fresh storm instances for t-noisy only → damped (same material).
        for i in range(4):
            main.buffer_signal(_tenant_signal("t-noisy", "link_state_change", "storm-dev", offset_s=-100 + i, now=now))
            main.buffer_signal(_tenant_signal("t-noisy", "device_resource_anomaly", "storm-dev", offset_s=-99 + i, now=now))
        asyncio.run(main.engine_cycle())   # flush happens here (flush_s=0)
    finally:
        main.ch, main.OPEN_OBJECTS = saved_ch, saved_open
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()

    rows = stub.rows.get("netops.corr_tenant_write_amp", [])
    assert rows, "flush must write the rollup table"
    by_tenant = {r["tenant_id"]: r for r in rows}
    noisy, quiet = by_tenant["t-noisy"], by_tenant["t-quiet"]
    assert noisy["raw_seen"] == 16 and quiet["raw_seen"] == 2
    assert noisy["damped"] >= 1, "storm refresh must be damped, and counted per tenant"
    assert noisy["top_signal_kind"] in ("link_state_change", "device_resource_anomaly")
    assert noisy["top_entity"] == "storm-dev"
    assert noisy["persisted"] >= 1 and quiet["persisted"] >= 1
    assert 0.0 <= noisy["damping_ratio"] <= 1.0
    assert noisy["open_objects"] >= 1
    assert noisy["max_incident_age_s"] >= 0

    # Bounded exposition: top-K=1 → exactly one tenant in TENANT_WA_LAST, the
    # noisiest, and the accumulator reset for the next window.
    assert len(main.TENANT_WA_LAST) == 1
    assert main.TENANT_WA_LAST[0]["tenant_id"] == "t-noisy"
    assert main.TENANT_WA == {}

    body = asyncio.run(main.metrics_exposition()).body.decode()
    assert body.count('corr_tenant_writes_window{tenant_id="t-noisy"') == 3  # raw/persisted/damped
    assert 'tenant_id="t-quiet"' not in body, "below-K tenants must not get series"


def test_entity_counter_is_capped(monkeypatch):
    """An adversarial entity spray must not grow memory unboundedly: past the
    cap, only already-seen entities keep counting."""
    _reset_wa(monkeypatch, flush_s=1e9)
    monkeypatch.setattr(main, "_WA_ENTITY_CAP", 10)
    now = datetime.now(timezone.utc)
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    try:
        for i in range(50):
            main.buffer_signal(_tenant_signal("t-spray", "link_state_change", f"dev-{i}", offset_s=-60 - i, now=now))
    finally:
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
    assert len(main.TENANT_WA["t-spray"]["entities"]) == 10
    assert main.TENANT_WA["t-spray"]["raw_seen"] == 50  # totals stay exact


def test_flush_failure_is_nonfatal(monkeypatch):
    """A failed rollup insert never raises into the engine loop and still
    resets the window (accounting is best-effort, never backpressure)."""
    _reset_wa(monkeypatch, flush_s=0.0)

    class _Boom(_StubCH):
        async def insert(self, table, rows):
            if table == "netops.corr_tenant_write_amp":
                raise ConnectionError("ch down")
            await super().insert(table, rows)
            return True

    saved = main.ch
    main.ch = _Boom()
    try:
        now = datetime.now(timezone.utc)
        main._wa_note_raw(lane_signal("link_state_change", "x", offset_s=-1, now=now))
        asyncio.run(main._flush_tenant_write_amp(now))                       # arms window
        asyncio.run(main._flush_tenant_write_amp(now + timedelta(seconds=1)))  # flush → insert fails
    finally:
        main.ch = saved
    assert main.TENANT_WA == {}, "window must reset even when the insert fails"
    assert main.TENANT_WA_LAST, "top-K still reflects the window (metrics keep working)"
