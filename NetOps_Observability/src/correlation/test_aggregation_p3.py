"""P3 Aggregation Plane — steps 1 and 2.

Design: `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §3/§5/§7; owner memo
§16–§19, §21–§25; sizing `docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md`.

The properties pinned here are the ones the plane's whole claim rests on:

  * KEY — the AggKey is EXACTLY the harness's K3, so the plan-time projection
    and the engine-side counters partition the same stream the same way.
  * DETERMINISM — the deltas are a function of the event-time-ordered stream,
    never of arrival order, load or the clock (memo §21). With a MUTANT that
    puts the wall clock in the key, this turns red.
  * LOSSLESSNESS — Σ agg_count over a key equals every raw observation of that
    key; the raw row is persisted and counted whether the plane forwards or
    absorbs (the accounting gate).
  * CAUSAL COVERAGE — every memo-§17 class is forwarded synchronously; only a
    pure repeat is absorbed.
  * BOUNDS — per-tenant caps hold, and eviction is counted, never silent (§9/§10).
  * TENANCY — tenant A's stream cannot create, read, mutate or evict tenant B's
    state (§3a).
  * WIRING — with `CORR_AGGREGATION_PLANE` off the ingest path is byte-identical.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import aggregation
import main
from aggregation import (
    AGG_EVICT_REASONS,
    COUNT_THRESHOLDS,
    AggKey,
    AggPlane,
    DeltaClass,
    delta_class,
    observe_all,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

# A minute boundary, so `int(ts) // 60` and "seconds from the stream start // 60"
# partition identically — the same alignment the bench uses to make its
# plan-time and engine-side columns exactly comparable.
T0 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


def mk(*, tenant: str = "t1", entity: str = "dev1:Gi0/1",
       kind: str = "link_state_change", sev: Severity = Severity.HIGH,
       state: str = "down", t: float = 0.0, observer: str = "",
       modality: ModalityClass = ModalityClass.CONTROL_PLANE,
       source: Source = Source.SYSLOG, seq: int = 0) -> Signal:
    """One promoted-shaped Signal. `seq` only varies native_id, so two otherwise
    identical observations still get distinct (deterministic) signal ids."""
    ts = T0 + timedelta(seconds=t)
    return Signal(
        tenant_id=tenant, ts=ts, source=source, kind=kind,
        observer=Observer(observer_id=observer or entity.split(":")[0],
                          observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE,
        entity_id=entity, severity=sev,
        native_id=f"{entity}|{kind}|{state}|{t}|{seq}",
        attrs={"state": state},
    )


def plane(**kw) -> AggPlane:
    kw.setdefault("horizon_s", 600.0)
    kw.setdefault("lateness_s", 120.0)
    return AggPlane(**kw)


# ══ 1. the key IS K3 ═════════════════════════════════════════════════════════

def test_agg_key_is_exactly_k3():
    """`(tenant, entity_id, kind, severity, 60 s event-time bucket)` — the
    harness's K3. Every component is read from the signal; nothing else is."""
    s = mk(t=17.0)
    k = AggKey.of(s)
    assert k == ("t1", "dev1:Gi0/1", "link_state_change", "high",
                 int(T0.timestamp()) // 60)
    assert k.tenant_id == "t1" and k.bucket == int(T0.timestamp()) // 60


def test_agg_key_buckets_on_event_time_only():
    same_minute = [AggKey.of(mk(t=x, seq=int(x))) for x in (0.0, 30.0, 59.999)]
    assert len(set(same_minute)) == 1
    assert AggKey.of(mk(t=60.0)) != same_minute[0]
    # ...and it is a pure function of the signal: recomputing later, on a
    # different wall clock, yields the same key.
    s = mk(t=12.0)
    assert AggKey.of(s) == AggKey.of(s)


def test_agg_key_separates_tenant_severity_kind_entity():
    base = AggKey.of(mk())
    assert AggKey.of(mk(tenant="t2")) != base
    assert AggKey.of(mk(entity="dev2:Gi0/1")) != base
    assert AggKey.of(mk(kind="bgp_adjacency_change")) != base
    assert AggKey.of(mk(sev=Severity.WARN)) != base


def test_recovery_states_match_the_harness():
    """The engine and the harness must classify a recovery identically, or
    `recoveries_total` and the plan-time recovery count are not the same
    metric. Skipped (never silently passed) when the harness is not on disk."""
    here = Path(__file__).resolve()
    chain = here.parents[2] / "scripts" / "enterprise_outage_chain.py"
    if not chain.exists():
        pytest.skip(f"harness not present at {chain}")
    spec = importlib.util.spec_from_file_location("_eoc_for_test", chain)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert aggregation.RECOVERY_STATES == mod.RECOVERY_STATES
    assert aggregation.CORR_AGG_BUCKET_S == mod.AGG_BUCKET_S_K3


# ══ 2. the classifier: every memo-§17 class, and only repeats absorbed ═══════

def test_first_is_forwarded_and_pure_repeats_are_absorbed():
    p = plane()
    out = observe_all(p, [mk(t=float(i), seq=i) for i in range(5)])
    assert len(out) == 1                      # FIRST only
    assert p.forwarded_by_class == {"first": 1}
    assert p.suppressed == 4
    assert p.observed == 5


def test_state_transition_and_recovery_are_forwarded():
    p = plane()
    # Same witness, same key band (severity forced equal so the class, not the
    # key, is what is under test).
    out = observe_all(p, [
        mk(state="down", sev=Severity.HIGH, t=0, seq=0),
        mk(state="up", sev=Severity.HIGH, t=1, seq=1),     # recovery
        mk(state="down", sev=Severity.HIGH, t=2, seq=2),   # transition back
    ])
    assert len(out) == 3
    assert p.forwarded_by_class == {"first": 1, "recovery": 1,
                                    "state_transition": 1}
    assert p.state_transitions == 2 and p.recoveries == 1


def test_contradiction_is_a_different_witness_disagreeing():
    p = plane()
    out = observe_all(p, [
        mk(state="down", observer="dev1", t=0, seq=0),
        mk(state="up", observer="probe-a", t=1, seq=1),
    ])
    assert len(out) == 2
    assert p.forwarded_by_class["contradiction"] == 1
    # The MOVE still counts as a transition + a recovery: the counters mean what
    # `measure_stream` means by them, whatever class the delta was labelled.
    assert p.state_transitions == 1 and p.recoveries == 1
    assert p.contradictions == 1


def test_new_vantage_and_new_modality_are_forwarded():
    p = plane()
    out = observe_all(p, [
        mk(observer="dev1", t=0, seq=0),
        mk(observer="dev1", t=1, seq=1),                       # repeat
        mk(observer="collector-7", t=2, seq=2),                # new vantage
        mk(observer="dev1", modality=ModalityClass.DEVICE_TELEMETRY,
           t=3, seq=3),                                        # new modality
    ])
    assert len(out) == 3
    assert p.forwarded_by_class["new_vantage"] == 1
    assert p.forwarded_by_class["new_modality"] == 1
    assert p.suppressed == 1


def test_count_threshold_crossings_are_content_derived():
    p = plane()
    out = observe_all(p, [mk(t=float(i) / 100.0, seq=i) for i in range(120)])
    classes = [s.attrs["agg_class"] for s in out]
    assert classes == ["first", "count_threshold", "count_threshold"]
    assert [s.attrs["agg_count"] for s in out] == [1, 10, 100]
    assert p.count_thresholds == 2
    # The thresholds are powers of ten, so the delta count for N observations is
    # log10(N) — bounded by construction, never by a timer or a rate.
    assert 10 in COUNT_THRESHOLDS and 1000 in COUNT_THRESHOLDS


def test_every_memo_17_class_is_reachable_and_forwarded():
    """A class that can never fire is a class the engine never gets told about.

    Each group runs on its OWN identity, because the classes are priority
    ordered: a witness disagreeing about the state is a CONTRADICTION whatever
    else is also true of it, so NEW_VANTAGE is only observable on an identity
    where the witnesses AGREE.
    """
    p = plane()
    # A flapping identity, one witness: first -> recovery -> transition.
    observe_all(p, [
        mk(entity="d1:Gi0/1", observer="d1", state="down", t=0, seq=0),
        mk(entity="d1:Gi0/1", observer="d1", state="up", t=1, seq=1),
        mk(entity="d1:Gi0/1", observer="d1", state="down", t=2, seq=2),
    ])
    # A second, INDEPENDENT witness that disagrees: contradiction.
    observe_all(p, [
        mk(entity="d2:Gi0/1", observer="d2", state="down", t=0, seq=3),
        mk(entity="d2:Gi0/1", observer="probe-a", state="up", t=1, seq=4),
    ])
    # Witnesses that AGREE: a new vantage, then a new modality.
    observe_all(p, [
        mk(entity="d3:Gi0/1", observer="d3", state="down", t=0, seq=5),
        mk(entity="d3:Gi0/1", observer="probe-b", state="down", t=1, seq=6),
        mk(entity="d3:Gi0/1", observer="probe-b", state="down", t=2, seq=7,
           modality=ModalityClass.ACTIVE_PROBE),
    ])
    # Sheer volume on one identity: the count crossing.
    observe_all(p, [mk(entity="d4:Gi0/1", observer="d4", t=float(i) / 100.0,
                       seq=100 + i) for i in range(12)])
    got = set(p.forwarded_by_class)
    assert got == {c.value for c in DeltaClass if c is not DeltaClass.REPEAT}
    assert DeltaClass.REPEAT.value not in got
    assert p.suppressed > 0, "nothing was absorbed — the plane did no work"


def test_delta_class_is_pure():
    """It reads state and mutates nothing — a classifier with a side effect
    could not be replayed."""
    p = plane()
    p.observe(mk(t=0, seq=0))
    key = AggKey.of(mk(t=1, seq=1))
    st = p.state_of(key)
    assert st is not None
    before = (st.count, len(st.vantages), st.first_health)
    for _ in range(3):
        assert delta_class(st, mk(t=1, seq=1)) is DeltaClass.REPEAT
    assert (st.count, len(st.vantages), st.first_health) == before


# ══ 3. losslessness (the accounting gate) ════════════════════════════════════

def test_sum_of_agg_counts_equals_every_observation():
    p = plane()
    stream = ([mk(entity=f"dev{i % 7}:Gi0/1", t=float(i) / 10.0, seq=i)
               for i in range(500)]
              + [mk(kind="bgp_adjacency_change", entity=f"dev{i % 3}",
                    t=float(i) / 10.0, seq=1000 + i) for i in range(200)])
    observe_all(p, stream)
    assert p.raw_count("t1") == len(stream) == p.observed
    assert p.forwarded + p.suppressed == p.observed
    assert p.evicted_total() == 0
    # ...and per key: what was forwarded plus what was absorbed IS the count.
    for k in p.keys_of("t1"):
        st = p.state_of(k)
        assert st is not None
        assert st.forwarded + st.suppressed == st.count


def test_forwarded_delta_carries_the_state_it_collapsed():
    p = plane()
    out = observe_all(p, [mk(t=float(i) / 10.0, seq=i) for i in range(10)])
    last = out[-1]
    a = last.attrs
    assert a["agg_class"] == "count_threshold"
    assert a["agg_count"] == 10
    assert a["agg_key"] == AggKey.of(last).token()
    assert a["agg_policy"] == aggregation.AGG_POLICY_VERSION
    assert a["agg_first_ts"].startswith("2026-08-29T12:00:00")
    assert a["agg_distinct_sources"] == 1
    assert len(a["agg_samples"]) == aggregation.CORR_AGG_SAMPLES


def test_offset_range_is_recorded_when_the_caller_knows_it():
    """Memo §16's raw Kafka offset range. It is NOT on the Signal (no offset
    field, no producer stamps one), so the ingest boundary supplies it."""
    p = plane()
    for i in range(12):
        p.observe(mk(t=float(i) / 10.0, seq=i), (3, 63_059_833 + i))
    st = p.state_of(AggKey.of(mk(t=0.0)))
    assert st is not None
    assert st.offset_range() == ["3:63059833-63059844"]


# ══ 4. determinism (memo §21) ════════════════════════════════════════════════

def _mixed_stream() -> list[Signal]:
    """Several identities, repeats, transitions and recoveries — the shape the
    determinism claims have to survive."""
    out = []
    for i in range(240):
        dev = f"dev{i % 6}"
        state = "down" if (i // 6) % 3 else "up"
        out.append(mk(entity=f"{dev}:Gi0/1", observer=dev, state=state,
                      sev=Severity.HIGH if state == "down" else Severity.WARN,
                      t=float(i) / 4.0, seq=i))
    return out


def _fingerprint(p: AggPlane, out: list[Signal]) -> tuple:
    """What a delta stream IS: per key, the ordered list of (delta identity,
    class, count-at-emission) — plus the final state of every key."""
    per_key: dict[str, list] = {}
    for s in out:
        per_key.setdefault(s.attrs["agg_key"], []).append(
            (s.signal_id_str, s.attrs["agg_class"], s.attrs["agg_count"]))
    states = {}
    for k in p.keys_of("t1"):
        st = p.state_of(k)
        assert st is not None
        states[k.token()] = (
            st.count, st.first_ts_ms, st.last_ts_ms, st.frontier,
            tuple(sorted(st.sev_dist.items())), tuple(sorted(st.sources)),
            tuple(sorted(st.vantages)), tuple(sorted(st.modalities)),
            tuple(sorted(st.states.items())), st.recovery, st.contradiction,
            st.first_health, st.first_observer, tuple(st.samples),
            st.forwarded, st.suppressed)
    return (per_key, states)


def test_interleaving_across_keys_changes_nothing():
    """The reordering a partitioned bus actually produces: per-key event-time
    order preserved, the streams of different keys arbitrarily interleaved."""
    stream = _mixed_stream()
    a = plane()
    fa = _fingerprint(a, observe_all(a, stream))

    # Round-robin the per-IDENTITY substreams — a maximally different arrival
    # order that still preserves every identity's own event-time order (and
    # therefore every key's, since the key refines the identity). This is the
    # reordering a partitioned bus produces.
    by_ident: dict = {}
    for s in stream:
        by_ident.setdefault((s.tenant_id, s.entity_id, s.kind), []).append(s)
    lanes = list(by_ident.values())
    mixed: list[Signal] = []
    i = 0
    while any(lanes):
        lane = lanes[i % len(lanes)]
        if lane:
            mixed.append(lane.pop(0))
        i += 1
    b = plane()
    fb = _fingerprint(b, observe_all(b, mixed))

    assert fa == fb
    assert a.stats()["forwarded_by_class"] == b.stats()["forwarded_by_class"]
    assert (a.suppressed, a.state_transitions, a.recoveries) == (
        b.suppressed, b.state_transitions, b.recoveries)
    assert a.late_forwarded == b.late_forwarded == 0


def test_out_of_order_within_a_key_keeps_the_commutative_state_and_loses_nothing():
    """Within-key reordering inside the permitted lateness: the commutative
    final state is IDENTICAL, the forwarded set is a SUPERSET of the canonical
    one (never smaller — losslessness in the safe direction), and the excess is
    exactly `late_forwarded`, a counter (§10)."""
    stream = _mixed_stream()
    a = plane()
    out_a = observe_all(a, stream)

    # Swap adjacent pairs: every displacement is < 1 s, far inside the 120 s
    # declared lateness.
    swapped = list(stream)
    for i in range(0, len(swapped) - 1, 2):
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
    b = plane()
    out_b = observe_all(b, swapped)

    def commutative(p: AggPlane) -> dict:
        got = {}
        for k in p.keys_of("t1"):
            st = p.state_of(k)
            assert st is not None
            got[k.token()] = (
                st.count, st.first_ts_ms, st.last_ts_ms,
                tuple(sorted(st.sev_dist.items())), tuple(sorted(st.sources)),
                tuple(sorted(st.vantages)), tuple(sorted(st.modalities)),
                tuple(sorted(st.states.items())), st.recovery,
                st.first_health, st.first_observer, tuple(st.samples))
        return got

    assert commutative(a) == commutative(b)
    assert a.observed == b.observed == len(stream)
    ids_a = {s.signal_id_str for s in out_a}
    ids_b = {s.signal_id_str for s in out_b}
    assert ids_a <= ids_b, "a reordering LOST a delta — losslessness broken"
    assert len(ids_b) - len(ids_a) <= b.late_forwarded
    assert b.beyond_lateness == 0


def test_beyond_lateness_is_counted_and_still_forwarded():
    p = plane(lateness_s=5.0)
    p.observe(mk(t=300.0, seq=0))
    # 300 s older than the frontier — far outside the declared 5 s allowance.
    got = p.observe(mk(t=0.0, seq=1))
    assert got is not None, "an unorderable observation must never be suppressed"
    assert p.beyond_lateness == 1
    # It landed in a different 60 s bucket, so it is a FIRST for its own key —
    # forwarded on its class, not on the lateness rule. The lateness rule is
    # what keeps it from ever being CLASSIFIED as a transition it cannot prove.
    assert got.attrs["agg_class"] == "first"
    assert p.state_transitions == 0


def test_mutant_wall_clock_in_the_key_turns_determinism_red(monkeypatch):
    """A key derived from the WALL CLOCK instead of event time (memo §21's
    explicit prohibition). The determinism assertions above must FAIL against
    it — a test that cannot fail proves nothing."""
    import time as _time

    def wall_clock_key(sig, bucket_s=aggregation.CORR_AGG_BUCKET_S, **kw):
        return AggKey(sig.tenant_id, sig.entity_id, sig.kind,
                      sig.severity.value, _time.time_ns())

    monkeypatch.setattr(AggKey, "of", staticmethod(wall_clock_key))
    stream = _mixed_stream()
    p = plane()
    out = observe_all(p, stream)
    # Every observation gets its own key, so nothing is ever a repeat: the
    # collapse the plane exists for disappears, and the delta stream stops
    # being a function of the input.
    assert p.suppressed == 0
    assert len(out) == len(stream)
    with pytest.raises(AssertionError):
        a = plane()
        fa = _fingerprint(a, observe_all(a, stream))
        b = plane()
        fb = _fingerprint(b, observe_all(b, stream))
        assert fa == fb


# ══ 5. bounds (§9) and counted eviction (§10) ════════════════════════════════

def test_key_cap_holds_and_every_eviction_is_counted():
    p = plane(max_keys=25)
    observe_all(p, [mk(entity=f"dev{i}:Gi0/1", t=float(i) / 10.0, seq=i)
                    for i in range(400)])
    assert p.key_count() <= 25
    assert p.evicted.get("capacity", 0) > 0
    assert p.evicted_total() >= 400 - 25
    assert set(p.evicted) <= set(AGG_EVICT_REASONS)


def test_event_time_expiry_runs_on_the_stream_clock_not_the_wall_clock():
    p = plane(horizon_s=120.0)
    observe_all(p, [mk(entity=f"dev{i}:Gi0/1", t=float(i), seq=i)
                    for i in range(600)])
    # 600 s of stream over a 120 s horizon: only the last few buckets survive.
    assert p.key_count() <= 4 * (aggregation.CORR_AGG_BUCKET_S and 60)
    assert p.evicted.get("expired", 0) > 0
    # Nothing was expired by a clock: replaying the identical stream a second
    # time into a fresh plane gives the identical population.
    q = plane(horizon_s=120.0)
    observe_all(q, [mk(entity=f"dev{i}:Gi0/1", t=float(i), seq=i)
                    for i in range(600)])
    assert p.key_count() == q.key_count()
    assert p.evicted == q.evicted


def test_tenant_map_is_bounded():
    p = plane(max_tenants=4)
    observe_all(p, [mk(tenant=f"tn{i}", t=float(i) / 10.0, seq=i)
                    for i in range(50)])
    assert len(p._tenants) <= 4
    assert p.evicted.get("tenant_capacity", 0) > 0


def test_identity_map_is_bounded():
    p = plane(max_keys=8, horizon_s=1e9)
    observe_all(p, [mk(entity=f"dev{i}:Gi0/1", t=float(i) / 100.0, seq=i)
                    for i in range(200)])
    assert p.ident_count() <= 8
    assert p.evicted.get("ident_capacity", 0) > 0


# ══ 6. tenant isolation (§3a) ════════════════════════════════════════════════

def test_tenant_a_stream_never_touches_tenant_b_state():
    p = plane()
    a = [mk(tenant="ta", t=float(i) / 10.0, seq=i) for i in range(5)]
    b = [mk(tenant="tb", t=float(i) / 10.0, seq=i) for i in range(5)]
    observe_all(p, a)
    forwarded_b = observe_all(p, b)
    # tb's first observation is a FIRST for tb, not a repeat of ta's identical
    # identity: the tenant is the first component of the key.
    assert len(forwarded_b) == 1
    assert forwarded_b[0].attrs["agg_class"] == "first"
    assert p.raw_count("ta") == 5 and p.raw_count("tb") == 5
    assert all(k.tenant_id == "ta" for k in p.keys_of("ta"))
    assert all(k.tenant_id == "tb" for k in p.keys_of("tb"))
    assert p.keys_of("nobody") == [] and p.raw_count("nobody") == 0


def test_a_noisy_tenant_cannot_evict_a_quiet_tenants_state():
    """The cap is PER TENANT, so cross-tenant eviction is not a thing that can
    happen — a shared pool would make one tenant's storm delete another's."""
    p = plane(max_keys=10)
    observe_all(p, [mk(tenant="quiet", entity="dev0:Gi0/1", t=0.0, seq=0)])
    observe_all(p, [mk(tenant="loud", entity=f"dev{i}:Gi0/1",
                       t=float(i) / 100.0, seq=i) for i in range(500)])
    assert p.raw_count("quiet") == 1
    assert p.keys_of("quiet") == [AggKey.of(mk(tenant="quiet",
                                               entity="dev0:Gi0/1"))]


# ══ 7. ingest wiring (step 2) ════════════════════════════════════════════════

SYSLOG_LINE = {
    "hostname": "mlx-1", "appname": "LINK-3-UPDOWN",
    "message": "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down",
    "severity": "err", "tenant_id": "t1",
}


class _CHStub:
    async def insert(self, *a, **kw):
        return True


def _lines(n: int, *, host: str = "mlx-1") -> list[dict]:
    """`n` syslog lines that all promote to the SAME identity — the repeat shape
    the plane exists to collapse. Only the timestamp moves, and it stays inside
    one 60 s bucket."""
    return [dict(SYSLOG_LINE, hostname=host,
                 timestamp=(T0 + timedelta(milliseconds=100 * i)).isoformat())
            for i in range(n)]


async def _drive(lines: list[dict], *, plane_on: bool,
                 guard: bool = False) -> tuple[list[str], list[str], int, int]:
    """Run lines through the REAL handle_syslog. Returns
    (raw corr_signals rows, buffered signal ids, syslog_received, syslog_signals).
    `guard` makes any call into the plane an error — how "off means untouched"
    is proven rather than asserted."""
    rows: list[str] = []

    async def _batch_signal(row, lane="syslog"):
        rows.append(json.dumps(row, sort_keys=True, default=str))

    async def _emit(**kw):
        pass

    class _Boom:
        def observe(self, *a, **kw):
            raise AssertionError("the aggregation plane ran with the flag OFF")

    saved = (main.CORR_AGGREGATION_PLANE, main.batch_signal, main.emit,
             main.verified_tenant, main.ch, main.CORR_SIGNALS_ENABLED,
             main.SYSLOG_RECEIVED, main.SYSLOG_SIGNALS, main.AGG_PLANE)
    main.CORR_AGGREGATION_PLANE = plane_on
    main.batch_signal = _batch_signal
    main.emit = _emit
    main.verified_tenant = lambda claim, host, lane, **kw: "t1"
    main.ch = _CHStub()
    main.CORR_SIGNALS_ENABLED = True
    main.SYSLOG_RECEIVED = 0
    main.SYSLOG_SIGNALS = 0
    main.AGG_PLANE.reset()
    if guard:
        main.AGG_PLANE = _Boom()               # type: ignore[assignment]
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.SYSLOG_BUCKET.clear()
    main.TENANT_WATERMARK.clear()
    try:
        for ev in lines:
            await main.handle_syslog(ev)
        return (rows, [str(s.signal_id) for s in main.WINDOW_BUFFER],
                main.SYSLOG_RECEIVED, main.SYSLOG_SIGNALS)
    finally:
        (main.CORR_AGGREGATION_PLANE, main.batch_signal, main.emit,
         main.verified_tenant, main.ch, main.CORR_SIGNALS_ENABLED,
         main.SYSLOG_RECEIVED, main.SYSLOG_SIGNALS, main.AGG_PLANE) = saved
        main.AGG_PLANE.reset()
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main._BUFFERED_ID_ORDER.clear()
        main.SYSLOG_BUCKET.clear()


def test_flag_off_is_byte_identical_ingest():
    lines = _lines(50)
    rows, buffered, recv, sigs = asyncio.run(_drive(lines, plane_on=False,
                                                    guard=True))
    assert recv == 50 and sigs == 50
    assert len(rows) == 50
    assert len(buffered) == 50           # every promoted signal reaches the window


def test_flag_on_absorbs_repeats_and_leaves_raw_accounting_exact():
    lines = _lines(50)
    off_rows, off_buf, off_recv, off_sigs = asyncio.run(
        _drive(lines, plane_on=False))
    on_rows, on_buf, on_recv, on_sigs = asyncio.run(
        _drive(lines, plane_on=True))

    # THE ACCOUNTING GATE: the raw corr_signals rows and both raw counters are
    # byte-for-byte what they are with the plane off. The plane sits BETWEEN the
    # raw write and the window, so a suppressed repeat is exactly as persisted
    # and as counted as a forwarded one.
    assert on_rows == off_rows
    assert (on_recv, on_sigs) == (off_recv, off_sigs) == (50, 50)
    # ...and the ENGINE sees far less.
    assert len(off_buf) == 50
    assert len(on_buf) < len(off_buf)
    assert set(on_buf) <= set(off_buf)
    assert main.AGG_PLANE.observed == 0   # reset by the harness on exit


def test_forwarded_signal_is_annotated_on_the_real_lane():
    async def _run():
        await _drive(_lines(3), plane_on=False)   # warm nothing; readability
        rows: list = []

        async def _batch_signal(row, lane="syslog"):
            rows.append(row)

        saved = (main.CORR_AGGREGATION_PLANE, main.batch_signal, main.emit,
                 main.verified_tenant, main.ch, main.CORR_SIGNALS_ENABLED)
        main.CORR_AGGREGATION_PLANE = True
        main.batch_signal = _batch_signal
        main.emit = lambda **kw: asyncio.sleep(0)
        main.verified_tenant = lambda claim, host, lane, **kw: "t1"
        main.ch = _CHStub()
        main.CORR_SIGNALS_ENABLED = True
        main.AGG_PLANE.reset()
        main.WINDOW_BUFFER.clear()
        main._BUFFERED_IDS.clear()
        main._BUFFERED_ID_ORDER.clear()
        try:
            for ev in _lines(4):
                await main.handle_syslog(ev)
            return list(main.WINDOW_BUFFER), rows
        finally:
            (main.CORR_AGGREGATION_PLANE, main.batch_signal, main.emit,
             main.verified_tenant, main.ch, main.CORR_SIGNALS_ENABLED) = saved
            main.AGG_PLANE.reset()
            main.WINDOW_BUFFER.clear()
            main._BUFFERED_IDS.clear()
            main._BUFFERED_ID_ORDER.clear()
            main.SYSLOG_BUCKET.clear()

    buffered, rows = asyncio.run(_run())
    assert len(buffered) == 1
    a = buffered[0].attrs
    assert a["agg_class"] == "first" and a["agg_key"]
    assert a["agg_policy"] == aggregation.AGG_POLICY_VERSION
    # The RAW rows were serialized before the plane ran, so none of them carries
    # an aggregation field — the stored raw evidence is unchanged.
    assert all("agg_" not in r["attrs"] for r in rows)


def test_plane_is_observable(monkeypatch):
    """§10: the counters, the closed label sets and the ratios are all
    exported, with the flag off as zeros rather than as a missing section."""
    st = main.agg_stats()
    assert st["policy"] == aggregation.AGG_POLICY_VERSION
    assert st["enabled"] is main.CORR_AGGREGATION_PLANE
    assert st["bucket_s"] == aggregation.CORR_AGG_BUCKET_S
    assert st["horizon_s"] == pytest.approx(main.RETENTION_REQUIRED_S, abs=0.01)
    assert st["lateness_s"] == pytest.approx(main.CORR_PERMITTED_LATENESS_S,
                                             abs=0.01)
    assert "aggregation" in main.epoch_state()

    text = main._metrics_text()
    for name in ("corr_agg_enabled", "corr_agg_observed_total",
                 "corr_agg_suppressed_total", "corr_agg_keys",
                 "corr_agg_state_transitions_total",
                 "corr_agg_recoveries_total"):
        assert name in text
    for c in DeltaClass:
        assert f'corr_agg_forwarded_total{{class="{c.value}"}}' in text
    for r in AGG_EVICT_REASONS:
        assert f'corr_agg_evicted_total{{reason="{r}"}}' in text


def test_the_plane_the_process_uses_is_bound_to_the_windows_own_horizon():
    """A plane expiring on a different clock than the window it feeds would
    hand the engine deltas whose state had already been thrown away."""
    assert main.AGG_PLANE.horizon_ms == int(main.RETENTION_REQUIRED_S * 1000)
    assert main.AGG_PLANE.lateness_ms == int(main.CORR_PERMITTED_LATENESS_S * 1000)
    assert main.AGG_PLANE.bucket_s == aggregation.CORR_AGG_BUCKET_S
    assert sys.modules["aggregation"] is aggregation
