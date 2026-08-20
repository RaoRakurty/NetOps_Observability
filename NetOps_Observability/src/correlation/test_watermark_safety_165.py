"""Tracker 165 phases 3-5 — attacking the retention clock.

Stream-time retention removed one defect (wall-clock delay destroying
event-time-valid evidence). It introduced three new ways to destroy the same
evidence, and this file exists to attack all three:

  * the IDLE BACKSTOP, which uses wall time to reclaim a stalled tenant and so
    can recreate the original defect exactly;
  * a FUTURE-SKEWED timestamp, which can drag a tenant's watermark forward and
    expire everything behind it;
  * BROKEN CO-PARTITIONING, which makes the watermark a clock over half a
    stream — an expiry decision taken on evidence the member cannot see.

Every test here is written to make evidence disappear. The ones that pass are
the ones where it did not.
"""
from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timedelta, timezone

import pytest

import main
from test_prune_buffer_156 import T0, mk, run


@pytest.fixture(autouse=True)
def _clean():
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main.TENANT_WATERMARK.clear()
    main._LAST_OFFSET.clear()
    main.COPARTITION_OK = True
    main.CONSUMER_LAG_TOTAL = None
    main.CONSUMER_LAG_AT = 0.0
    # These are process-lifetime counters; zero them so each test can assert on
    # absolute values instead of threading deltas through every assertion.
    main.STREAM_TIME_EVICTIONS = 0
    main.IDLE_TENANT_EVICTIONS = 0
    main.WATERMARK_REGRESSIONS = 0
    main.COPARTITION_VIOLATIONS = 0
    yield
    main.COPARTITION_OK = True
    main.CONSUMER_LAG_TOTAL = None


def _load(*sigs):
    for s in sigs:
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


def _stall_watermark(tenant: str, ts_offset: float, age_s: float):
    """Tenant's clock sits at T0+ts_offset and last moved `age_s` ago."""
    main.TENANT_WATERMARK[tenant] = (
        (T0 + timedelta(seconds=ts_offset)).timestamp(), time.monotonic() - age_s)


def _caught_up(lag: int):
    main.CONSUMER_LAG_TOTAL = lag
    main.CONSUMER_LAG_AT = time.monotonic()


# ── Phase 3: the idle backstop ───────────────────────────────────────────────

def test_A_a_genuinely_idle_tenant_is_eventually_reclaimed():
    """No backlog anywhere and a stream that stopped an hour ago: reclaiming is
    safe, and the backstop must actually work or it is not a memory control."""
    _load(mk(1, 0))
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S + 60)
    _caught_up(0)
    before = main.IDLE_TENANT_EVICTIONS
    run(main._prune_buffer(T0 + timedelta(seconds=main.CORR_TENANT_IDLE_EVICT_S + 600)))
    assert len(main.WINDOW_BUFFER) == 0
    assert main.IDLE_TENANT_EVICTIONS == before + 1


def test_B_backlog_means_NOT_idle_even_after_hours_of_wall_clock():
    """THE regression test for the defect this backstop shipped with.

    Evidence A is retained. B, 300 s later in event time and well inside the
    engine's reach, is still sitting unprocessed in the log. Hours of wall clock
    pass. The tenant LOOKS idle — its watermark has not moved — but it is not:
    we simply have not reached B yet. Shedding A here is precisely the
    'wall-clock delay destroys event-time-valid evidence' bug wearing a
    different hat.
    """
    _load(mk(1, 0))
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S * 5)
    _caught_up(1)                     # B (and others) still unconsumed
    run(main._prune_buffer(T0 + timedelta(hours=6)))
    assert len(main.WINDOW_BUFFER) == 1, (
        "evidence was shed while the log still held records that could "
        "legitimately correlate with it")
    assert main.IDLE_TENANT_EVICTIONS == 0


def test_B2_and_the_delayed_partner_still_correlates_when_it_arrives():
    """Completing scenario B: after the backlog clears, B arrives and the pair
    must still form an edge — the point of retaining A at all."""
    from engine import EngineConfig, build_edges, build_nodes
    a = mk(1, 0)
    _load(a)
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S * 5)
    _caught_up(1)
    run(main._prune_buffer(T0 + timedelta(hours=6)))
    b = main.dc_replace(mk(1, 300), kind="if_util_high", native_id="nat-b")
    _load(b)
    edges, _ = build_edges(build_nodes(tuple(main.WINDOW_BUFFER)), (), EngineConfig())
    assert len(edges) == 1, "the delayed partner had nothing left to attach to"


def test_C_backlog_on_ANOTHER_topic_still_blocks_the_backstop():
    """Cross-topic delay. The lag figure is deliberately GLOBAL, so a tenant
    that looks quiet on syslog is still protected while its probe lane is
    behind. Conservative on purpose: this is a memory control, and being slow
    to reclaim is the safe direction."""
    _load(mk(1, 0))
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S * 2)
    main._LAST_OFFSET[("netops.probes", 0)] = 10
    _caught_up(500)                   # backlog lives on a different lane
    run(main._prune_buffer(T0 + timedelta(hours=3)))
    assert len(main.WINDOW_BUFFER) == 1


def test_D_unknown_or_stale_lag_is_treated_as_backlog():
    """Fail-safe. If we cannot prove we are level with the broker we must not
    delete anything — 'no measurement' must never read as 'caught up'."""
    _load(mk(1, 0))
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S * 2)
    main.CONSUMER_LAG_TOTAL = None            # never measured
    run(main._prune_buffer(T0 + timedelta(hours=3)))
    assert len(main.WINDOW_BUFFER) == 1, "unknown lag must not permit eviction"

    main.CONSUMER_LAG_TOTAL = 0               # measured, but long ago
    main.CONSUMER_LAG_AT = time.monotonic() - (main.CORR_LAG_FRESH_S * 10)
    run(main._prune_buffer(T0 + timedelta(hours=3)))
    assert len(main.WINDOW_BUFFER) == 1, "a stale lag reading must not permit eviction"


def test_E_a_tenant_resuming_after_inactivity_gets_a_clean_clock():
    """Resumption must not let a stale watermark expire the new traffic."""
    _stall_watermark("acme", 0, main.CORR_TENANT_IDLE_EVICT_S * 3)
    fresh = mk(2, 10_000)                       # returns far in the future
    main.buffer_signal(fresh)
    wm_ts, wm_at = main.TENANT_WATERMARK["acme"]
    assert wm_ts == fresh.ts.timestamp(), "resumption must advance the clock"
    assert (time.monotonic() - wm_at) < 1.0, "and refresh its liveness stamp"
    _caught_up(0)
    run(main._prune_buffer(datetime.now(timezone.utc)))
    assert any(s.native_id == fresh.native_id for s in main.WINDOW_BUFFER)


def test_lag_accounting_counts_only_what_is_unconsumed():
    class _TP:
        def __init__(self, t, p): self.topic, self.partition = t, p
        def __hash__(self): return hash((self.topic, self.partition))
        def __eq__(self, o): return (self.topic, self.partition) == (o.topic, o.partition)

    class _Consumer:
        def __init__(self, hw): self._hw = hw
        def assignment(self): return set(self._hw)
        def highwater(self, tp): return self._hw[tp]

    tp = _TP("netops.syslog", 0)
    main._LAST_OFFSET[("netops.syslog", 0)] = 99
    main._LAG_SAMPLED_AT = 0.0
    main._refresh_consumer_lag(_Consumer({tp: 100}), time.monotonic())
    assert main.CONSUMER_LAG_TOTAL == 0, "consumed through 99 of highwater 100 is level"
    main._LAG_SAMPLED_AT = 0.0
    main._refresh_consumer_lag(_Consumer({tp: 250}), time.monotonic())
    assert main.CONSUMER_LAG_TOTAL == 150


def test_an_unfetched_partition_never_looks_caught_up():
    """highwater() is None until a fetch populates it — that is 'unknown', not
    'zero', and must not be silently counted as level."""
    class _TP:
        def __init__(self, t, p): self.topic, self.partition = t, p
        def __hash__(self): return hash((self.topic, self.partition))
        def __eq__(self, o): return (self.topic, self.partition) == (o.topic, o.partition)

    class _Consumer:
        def assignment(self): return {_TP("netops.syslog", 0)}
        def highwater(self, tp): return None

    main.CONSUMER_LAG_TOTAL = None
    main._LAG_SAMPLED_AT = 0.0
    main._refresh_consumer_lag(_Consumer(), time.monotonic())
    assert main.CONSUMER_LAG_TOTAL is None
    assert main._consumer_caught_up(time.monotonic()) is False


# ── Phase 5: future-timestamp / clock-skew attacks ───────────────────────────

@pytest.mark.parametrize("skew_s,label", [
    (30, "+30s"), (300, "+5min"), (3600, "+1h"), (86400, "+1day")])
def test_a_future_skewed_event_cannot_collapse_tenant_state(skew_s, label):
    """One malformed/fast device must not expire a tenant's whole window.

    Beyond METRIC_FUTURE_SKEW_S the H14 clamp rewrites the timestamp to arrival,
    so the watermark cannot jump. WITHIN the skew allowance the timestamp is
    accepted verbatim — which is why the lateness allowance is now floored at
    METRIC_FUTURE_SKEW_S: the horizon has to absorb exactly this.
    """
    now = datetime.now(timezone.utc)
    normal = [main.dc_replace(mk(i, 0), ts=now - timedelta(seconds=s))
              for i, s in enumerate((0, 60, 120, 240, 380))]
    for s in normal:
        main.buffer_signal(s)
    held_before = len(main.WINDOW_BUFFER)
    assert held_before == len(normal)

    main.buffer_signal(main.dc_replace(
        mk(99, 0), ts=now + timedelta(seconds=skew_s), native_id="nat-skewed"))
    _caught_up(0)
    run(main._prune_buffer(now))

    survivors = {s.native_id for s in main.WINDOW_BUFFER}
    lost = {s.native_id for s in normal} - survivors
    assert not lost, (
        f"{label} skew expired legitimate evidence: {sorted(lost)}")


def test_beyond_the_skew_allowance_the_timestamp_is_clamped_not_trusted():
    now = datetime.now(timezone.utc)
    before = main.EVENT_TS_FUTURE_CLAMPED
    main.buffer_signal(main.dc_replace(mk(5, 0), ts=now + timedelta(days=1)))
    assert main.EVENT_TS_FUTURE_CLAMPED == before + 1
    wm_ts, _ = main.TENANT_WATERMARK["acme"]
    assert wm_ts <= now.timestamp() + main.METRIC_FUTURE_SKEW_S + 60


def test_the_lateness_allowance_covers_the_permitted_skew():
    """The arithmetic the floor exists for: a device running at the edge of the
    allowed skew drags the cutoff forward by that much, so the horizon must be
    reach + skew or the full reach does not survive it."""
    assert main.CORR_PERMITTED_LATENESS_S >= main.METRIC_FUTURE_SKEW_S
    assert main.CORR_PERMITTED_LATENESS_S >= main.CORR_ENGINE_INTERVAL_S
    effective = main.RETENTION_REQUIRED_S - main.METRIC_FUTURE_SKEW_S
    assert effective == pytest.approx(main.ENGINE_REACH_S) or effective >= main.ENGINE_REACH_S, (
        f"a maximally skewed device leaves only {effective:.1f}s of horizon "
        f"against a {main.ENGINE_REACH_S:.1f}s reach")


# ── Phase 4: watermark invariants ────────────────────────────────────────────

def test_invariant_1_watermark_never_moves_backward():
    main._advance_watermark(mk(1, 500), time.monotonic())
    before = main.WATERMARK_REGRESSIONS
    main._advance_watermark(mk(2, 100), time.monotonic())
    assert main.TENANT_WATERMARK["acme"][0] == mk(1, 500).ts.timestamp()
    assert main.WATERMARK_REGRESSIONS == before + 1


def test_invariant_3_one_tenant_cannot_advance_anothers_retention():
    slow = main.dc_replace(mk(1, 0), tenant_id="slow")
    fast_old = main.dc_replace(mk(2, 0), tenant_id="fast")
    fast_new = main.dc_replace(
        mk(3, int(main.RETENTION_REQUIRED_S) + 100), tenant_id="fast")
    _load(slow, fast_old, fast_new)
    for s in (slow, fast_old, fast_new):
        main._advance_watermark(s, time.monotonic())
    _caught_up(0)
    run(main._prune_buffer(datetime.now(timezone.utc)))
    kept = {s.tenant_id for s in main.WINDOW_BUFFER}
    assert "slow" in kept
    assert [s.native_id for s in main.WINDOW_BUFFER if s.tenant_id == "fast"] == ["nat-3"]


def test_invariant_6_replay_produces_deterministic_retention():
    """Same stream, same watermark, same survivors — twice, with the wall clock
    deliberately different between runs."""
    def once(wall_offset_s):
        main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
        main._BUFFERED_ID_ORDER.clear(); main.TENANT_WATERMARK.clear()
        sigs = [mk(i % 20, i * 30) for i in range(40)]
        for s in sigs:
            main.WINDOW_BUFFER.append(s)
            main._BUFFERED_ID_ORDER.append(str(s.signal_id))
            main._BUFFERED_IDS.add(str(s.signal_id))
            main._advance_watermark(s, time.monotonic())
        _caught_up(0)
        run(main._prune_buffer(T0 + timedelta(seconds=wall_offset_s)))
        return [s.native_id for s in main.WINDOW_BUFFER]
    assert once(0) == once(100_000), "retention must not depend on the wall clock"


def test_invariant_8_a_cold_watermark_after_assignment_movement_expires_nothing():
    """A partition acquired at a rebalance starts with no watermark for its
    tenants. 'No clock' must mean 'expire nothing', never 'expire everything'
    — the failure mode that would turn every rebalance into evidence loss."""
    _load(mk(1, 0), mk(2, 10))
    assert main.TENANT_WATERMARK == {}
    _caught_up(0)
    run(main._prune_buffer(T0 + timedelta(days=1)))
    assert len(main.WINDOW_BUFFER) == 2
    assert main.STREAM_TIME_EVICTIONS == 0


# ── Phase 2: broken co-partitioning ──────────────────────────────────────────

def test_broken_copartitioning_suspends_stream_expiry():
    """The watermark is a clock over a stream this member can only half see, so
    it must stop being used to DELETE. Retaining is recoverable; deleting on a
    wrong clock is not."""
    old = mk(1, 0)
    new = mk(2, int(main.RETENTION_REQUIRED_S) + 500)
    _load(old, new)
    for s in (old, new):
        main._advance_watermark(s, time.monotonic())
    _caught_up(0)
    main.COPARTITION_OK = False
    run(main._prune_buffer(datetime.now(timezone.utc)))
    assert len(main.WINDOW_BUFFER) == 2, "expiry must be suspended"
    assert main.STREAM_TIME_EVICTIONS == 0
    assert main.rca_degradation_reason() == main.DEGRADED_PARTITION_TOPOLOGY
    assert main.rca_evidence_degraded() is True


def test_healthy_copartitioning_still_expires():
    """The negative control: the suspension must be conditional, or retention
    silently stops working everywhere."""
    old = mk(1, 0)
    new = mk(2, int(main.RETENTION_REQUIRED_S) + 500)
    _load(old, new)
    for s in (old, new):
        main._advance_watermark(s, time.monotonic())
    _caught_up(0)
    main.COPARTITION_OK = True
    run(main._prune_buffer(datetime.now(timezone.utc)))
    assert [s.native_id for s in main.WINDOW_BUFFER] == ["nat-2"]
    assert main.STREAM_TIME_EVICTIONS == 1


def test_the_violation_is_counted_and_exposed():
    main.COPARTITION_OK = False
    main.COPARTITION_VIOLATIONS = 3
    st = main.retention_state()
    assert st["copartition_ok"] is False
    assert st["copartition_violations"] == 3
    assert st["stream_expiry_suspended"] is True
    assert st["rca_degradation_reason"] == "partition_topology"


def test_partition_topology_outranks_resource_capacity(monkeypatch):
    """A wrong clock is worse than a full buffer, and the operator must be told
    the worse one."""
    monkeypatch.setattr(main, "WINDOW_BUFFER", deque([mk(1, 0)], maxlen=1))
    main.COPARTITION_OK = False
    assert main.rca_degradation_reason() == main.DEGRADED_PARTITION_TOPOLOGY


# ── Phase 2: the DETECTION path, not just the flag ───────────────────────────
#
# The tests above set COPARTITION_OK directly, which proves the RESPONSE but
# says nothing about whether a real divergence is noticed. Mutating the
# detection to `COPARTITION_OK = True` survived all of them, so it gets its own
# tests driving the actual rebalance callback.

class _TP165:
    def __init__(self, topic, partition):
        self.topic, self.partition = topic, partition


class _Consumer165:
    def partitions_for_topic(self, topic):
        return {0, 1}


def _assign(tps):
    import asyncio as _a
    main.CONSUMER_ASSIGNMENT.clear()
    main.CONSUMER_PARTITION_TOTALS.clear()
    main.CONSUMER_PARTITION_ACQUIRED_AT.clear()
    main.CONSUMER_ASSIGNMENT_SEEN = False
    # Deliberately does NOT reset COPARTITION_OK: the recovery test below is
    # only meaningful if the flag carries over between assignments, and a reset
    # here masked a "once broken, broken until restart" mutant.
    listener = main._AssignmentLogger(_Consumer165())
    _a.run(listener.on_partitions_assigned(tps))


def test_detection_uniform_assignment_is_healthy():
    _assign([_TP165(t, 0) for t in main.TOPICS])
    assert main.COPARTITION_OK is True
    assert main.COPARTITION_VIOLATIONS == 0
    assert main.rca_degradation_reason() != main.DEGRADED_PARTITION_TOPOLOGY


def test_detection_divergent_partition_sets_are_caught():
    """One topic whose partition set differs — the shape a failed
    `kafka-topics --alter` leaves behind, which splits tenants across members
    and makes every watermark a clock over half a stream."""
    tps = [_TP165(t, 0) for t in main.TOPICS] + [_TP165(main.TOPICS[0], 1)]
    _assign(tps)
    assert main.COPARTITION_OK is False, "divergent partition sets went unnoticed"
    assert main.COPARTITION_VIOLATIONS == 1
    assert main.TOPICS[0] in main.COPARTITION_LAST_DETAIL
    assert main.rca_degradation_reason() == main.DEGRADED_PARTITION_TOPOLOGY


def test_detection_ignores_topics_this_member_does_not_hold():
    """The range assignor legitimately gives a member nothing on some topics.
    That is not divergence, and calling it divergence would suspend expiry
    permanently on every multi-replica deployment."""
    _assign([_TP165(t, 1) for t in main.TOPICS[:4]])
    assert main.COPARTITION_OK is True
    assert main.COPARTITION_VIOLATIONS == 0


def test_detection_recovers_when_the_topology_is_repaired():
    """The flag is per-assignment, not sticky — a fixed topology must restore
    expiry, or one bad rebalance disables retention until restart."""
    _assign([_TP165(t, 0) for t in main.TOPICS] + [_TP165(main.TOPICS[0], 1)])
    assert main.COPARTITION_OK is False
    _assign([_TP165(t, 0) for t in main.TOPICS])
    assert main.COPARTITION_OK is True
    assert main.rca_degradation_reason() != main.DEGRADED_PARTITION_TOPOLOGY


def test_a_broken_lag_probe_never_quarantines_an_event():
    """Regression: the first version of the lag probe ran INSIDE the per-event
    try-block. When it raised on a consumer without `assignment()`, the EVENT
    was quarantined as if its payload were poison — instrumentation converting
    good data into DLQ traffic. The probe must degrade to 'lag unknown' (which
    means 'assume backlog', i.e. retain) and never touch the payload path."""
    class _NoLagConsumer:
        pass

    before_fail = main.CONSUMER_LAG_PROBE_FAILURES
    main._LAG_SAMPLED_AT = 0.0
    main.CONSUMER_LAG_TOTAL = None
    main._refresh_consumer_lag(_NoLagConsumer(), time.monotonic())   # must not raise
    assert main.CONSUMER_LAG_PROBE_FAILURES == before_fail + 1
    assert main.CONSUMER_LAG_TOTAL is None
    assert main._consumer_caught_up(time.monotonic()) is False, (
        "an unusable probe must read as backlog, so the backstop holds evidence")


def test_the_lag_probe_is_rate_limited():
    """It runs per message; without the rate limit it would walk the whole
    assignment on every event."""
    class _CountingConsumer:
        calls = 0
        def assignment(self):
            type(self).calls += 1
            return set()
        def highwater(self, tp): return None

    c = _CountingConsumer()
    main._LAG_SAMPLED_AT = 0.0
    now = time.monotonic()
    for _ in range(50):
        main._refresh_consumer_lag(c, now)
    assert _CountingConsumer.calls == 1, "the probe must sample, not poll per event"
